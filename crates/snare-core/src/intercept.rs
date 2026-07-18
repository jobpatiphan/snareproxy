//! Interactive intercept (§5.1 "Intercept") — the Burp-style breakpoint.
//!
//! When enabled, the proxy engine registers each request here and *awaits* a
//! [`Decision`] before forwarding. The decision comes from a frontend (Web/TUI)
//! via the daemon API, so the operator can edit, forward, or drop a request
//! while it hangs mid-flight.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use tokio::sync::oneshot;

use crate::model::{Header, HttpRequest};

/// What the operator decided for a held request.
pub enum Decision {
    /// Forward this (possibly edited) request.
    Forward(Box<HttpRequest>),
    /// Drop it — the client gets a synthetic 403.
    Drop,
}

/// Edits applied to a held request before forwarding. Any `None` field keeps the
/// original value.
#[derive(Debug, Default, Clone)]
pub struct Edit {
    pub method: Option<String>,
    pub path: Option<String>,
    pub query: Option<Option<String>>, // outer None = keep; inner None = clear query
    pub headers: Option<Vec<Header>>,
    pub body: Option<Vec<u8>>,
}

struct Pending {
    request: HttpRequest,
    tx: oneshot::Sender<Decision>,
}

/// Shared breakpoint coordinator. One instance, held behind an `Arc`, is shared
/// by the engine (producer) and the API (consumer).
#[derive(Default)]
pub struct Intercept {
    enabled: AtomicBool,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, Pending>>,
}

impl Intercept {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    /// Hold a request; returns its id and a receiver the engine awaits.
    pub fn register(&self, request: HttpRequest) -> (u64, oneshot::Receiver<Decision>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .unwrap()
            .insert(id, Pending { request, tx });
        (id, rx)
    }

    /// Snapshot of everything currently held (id + request), for the queue view.
    pub fn queue(&self) -> Vec<(u64, HttpRequest)> {
        let g = self.pending.lock().unwrap();
        let mut v: Vec<_> = g.iter().map(|(k, p)| (*k, p.request.clone())).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }

    /// Forward a held request, applying `edit`. Returns false if the id is gone.
    pub fn forward(&self, id: u64, edit: Option<Edit>) -> bool {
        let Some(p) = self.pending.lock().unwrap().remove(&id) else {
            return false;
        };
        let mut req = p.request;
        if let Some(e) = edit {
            if let Some(m) = e.method {
                req.method = m;
            }
            if let Some(path) = e.path {
                req.path = path;
            }
            if let Some(q) = e.query {
                req.query = q;
            }
            if let Some(h) = e.headers {
                req.headers = h;
            }
            if let Some(b) = e.body {
                req.body = b;
            }
        }
        p.tx.send(Decision::Forward(Box::new(req))).is_ok()
    }

    /// Drop a held request. Returns false if the id is gone.
    pub fn discard(&self, id: u64) -> bool {
        let Some(p) = self.pending.lock().unwrap().remove(&id) else {
            return false;
        };
        p.tx.send(Decision::Drop).is_ok()
    }

    /// Forward everything currently held, unedited (used when turning intercept
    /// off so nothing hangs).
    pub fn release_all(&self) {
        let drained: Vec<Pending> = self.pending.lock().unwrap().drain().map(|(_, p)| p).collect();
        for p in drained {
            let _ = p.tx.send(Decision::Forward(Box::new(p.request)));
        }
    }
}
