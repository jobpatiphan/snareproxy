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

use crate::model::{Header, HttpRequest, HttpResponse};

/// What the operator decided for a held request.
pub enum Decision {
    /// Forward this (possibly edited) request.
    Forward(Box<HttpRequest>),
    /// Drop it — the client gets a synthetic 403.
    Drop,
}

/// What the operator decided for a held response.
pub enum RespDecision {
    /// Return this (possibly edited) response to the client.
    Forward(Box<HttpResponse>),
    /// Drop it — the client gets a synthetic 403.
    Drop,
}

/// Edits applied to a held response before returning it.
#[derive(Debug, Default, Clone)]
pub struct RespEdit {
    pub status: Option<u16>,
    pub headers: Option<Vec<Header>>,
    pub body: Option<Vec<u8>>,
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

struct PendingResp {
    response: HttpResponse,
    tx: oneshot::Sender<RespDecision>,
}

/// Shared breakpoint coordinator. One instance, held behind an `Arc`, is shared
/// by the engine (producer) and the API (consumer).
#[derive(Default)]
pub struct Intercept {
    enabled: AtomicBool,
    resp_enabled: AtomicBool,
    next_id: AtomicU64,
    pending: Mutex<HashMap<u64, Pending>>,
    pending_resp: Mutex<HashMap<u64, PendingResp>>,
    /// Host substrings to limit intercept to; empty = every host.
    scope: Mutex<Vec<String>>,
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

    pub fn responses_enabled(&self) -> bool {
        self.resp_enabled.load(Ordering::Relaxed)
    }

    pub fn set_responses_enabled(&self, on: bool) {
        self.resp_enabled.store(on, Ordering::Relaxed);
    }

    pub fn set_scope(&self, hosts: Vec<String>) {
        *self.scope.lock().unwrap() = hosts.into_iter().filter(|h| !h.trim().is_empty()).collect();
    }

    pub fn scope(&self) -> Vec<String> {
        self.scope.lock().unwrap().clone()
    }

    /// True if `host` is in scope (or scope is empty, meaning "everything").
    pub fn in_scope(&self, host: &str) -> bool {
        let scope = self.scope.lock().unwrap();
        scope.is_empty() || scope.iter().any(|s| host.contains(s.as_str()))
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

    /// Hold a response; returns its id and a receiver the engine awaits.
    pub fn register_response(
        &self,
        response: HttpResponse,
    ) -> (u64, oneshot::Receiver<RespDecision>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let (tx, rx) = oneshot::channel();
        self.pending_resp
            .lock()
            .unwrap()
            .insert(id, PendingResp { response, tx });
        (id, rx)
    }

    /// Snapshot of held responses (id + response), for the queue view.
    pub fn queue_responses(&self) -> Vec<(u64, HttpResponse)> {
        let g = self.pending_resp.lock().unwrap();
        let mut v: Vec<_> = g.iter().map(|(k, p)| (*k, p.response.clone())).collect();
        v.sort_by_key(|(k, _)| *k);
        v
    }

    /// Return a held response, applying `edit`. Returns false if the id is gone.
    pub fn forward_response(&self, id: u64, edit: Option<RespEdit>) -> bool {
        let Some(p) = self.pending_resp.lock().unwrap().remove(&id) else {
            return false;
        };
        let mut resp = p.response;
        if let Some(e) = edit {
            if let Some(s) = e.status {
                resp.status = s;
            }
            if let Some(h) = e.headers {
                resp.headers = h;
            }
            if let Some(b) = e.body {
                resp.body = b;
            }
        }
        p.tx.send(RespDecision::Forward(Box::new(resp))).is_ok()
    }

    /// Drop a held response. Returns false if the id is gone.
    pub fn discard_response(&self, id: u64) -> bool {
        let Some(p) = self.pending_resp.lock().unwrap().remove(&id) else {
            return false;
        };
        p.tx.send(RespDecision::Drop).is_ok()
    }

    /// Forward all held requests unedited (used when request intercept is
    /// turned off so nothing hangs).
    pub fn release_requests(&self) {
        let reqs: Vec<Pending> = self
            .pending
            .lock()
            .unwrap()
            .drain()
            .map(|(_, p)| p)
            .collect();
        for p in reqs {
            let _ = p.tx.send(Decision::Forward(Box::new(p.request)));
        }
    }

    /// Forward all held responses unedited (used when response intercept is
    /// turned off).
    pub fn release_responses(&self) {
        let resps: Vec<PendingResp> = self
            .pending_resp
            .lock()
            .unwrap()
            .drain()
            .map(|(_, p)| p)
            .collect();
        for p in resps {
            let _ = p.tx.send(RespDecision::Forward(Box::new(p.response)));
        }
    }

    /// Forward everything currently held, both directions.
    pub fn release_all(&self) {
        self.release_requests();
        self.release_responses();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_scope_matches_all() {
        let i = Intercept::new();
        assert!(i.in_scope("anything.test"));
    }

    #[test]
    fn scope_matches_substring() {
        let i = Intercept::new();
        i.set_scope(vec!["example.com".into()]);
        assert!(i.in_scope("api.example.com"));
        assert!(!i.in_scope("evil.test"));
    }

    #[test]
    fn scope_ignores_blank_entries() {
        let i = Intercept::new();
        i.set_scope(vec!["  ".into(), "".into()]);
        assert!(i.in_scope("anything")); // blanks filtered → still "all"
    }

    #[test]
    fn toggles_default_off() {
        let i = Intercept::new();
        assert!(!i.enabled());
        assert!(!i.responses_enabled());
        i.set_enabled(true);
        assert!(i.enabled());
    }
}
