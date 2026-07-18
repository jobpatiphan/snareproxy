//! Cross-process live events (design: team-mode.md §9, topology B).
//!
//! With several `snared` proxies sharing one Postgres, each captures traffic
//! locally. To let every operator see *everyone's* events live, we relay the
//! local event bus through Postgres `LISTEN/NOTIFY`:
//!
//! - a **publisher** forwards every local event to `NOTIFY snare_events` (tagged
//!   with this daemon's random origin id);
//! - a **listener** receives notifications and, skipping our own origin, feeds
//!   them into a separate `remote` bus that the SSE endpoint merges with the
//!   local one.
//!
//! Local and remote buses are kept separate so a relayed event is never
//! re-published — that (plus the origin tag) prevents echo storms.

use std::sync::mpsc;
use std::time::Duration;

use postgres::fallible_iterator::FallibleIterator;
use postgres::NoTls;
use serde::{Deserialize, Serialize};
use snare_core::model::FlowEvent;
use tokio::sync::broadcast;

const CHANNEL: &str = "snare_events";

#[derive(Serialize, Deserialize)]
struct Wire {
    /// Origin daemon id (skip our own on receive).
    o: u64,
    e: FlowEvent,
}

/// Start the publisher + listener for cross-process events.
pub fn start(
    url: String,
    local: broadcast::Sender<FlowEvent>,
    remote: broadcast::Sender<FlowEvent>,
) {
    let origin = random_origin();

    // Bridge: local broadcast (async) -> std channel -> NOTIFY thread (sync pg).
    let (notify_tx, notify_rx) = mpsc::channel::<String>();
    let mut local_rx = local.subscribe();
    tokio::spawn(async move {
        while let Ok(ev) = local_rx.recv().await {
            if let Ok(json) = serde_json::to_string(&Wire { o: origin, e: ev }) {
                // pg_notify payloads are capped (~8000 bytes); skip oversized ones.
                if json.len() < 7800 && notify_tx.send(json).is_err() {
                    break;
                }
            }
        }
    });

    // NOTIFY thread.
    let notify_url = url.clone();
    std::thread::Builder::new()
        .name("snare-pg-notify".into())
        .spawn(move || {
            let mut client = match postgres::Client::connect(&notify_url, NoTls) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("pubsub notify connect failed: {e}");
                    return;
                }
            };
            while let Ok(json) = notify_rx.recv() {
                if let Err(e) = client.execute("SELECT pg_notify($1, $2)", &[&CHANNEL, &json]) {
                    tracing::warn!("pg_notify failed: {e}");
                }
            }
        })
        .ok();

    // LISTEN thread.
    std::thread::Builder::new()
        .name("snare-pg-listen".into())
        .spawn(move || loop {
            let mut client = match postgres::Client::connect(&url, NoTls) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("pubsub listen connect failed: {e}; retrying");
                    std::thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            if client.batch_execute(&format!("LISTEN {CHANNEL}")).is_err() {
                std::thread::sleep(Duration::from_secs(2));
                continue;
            }
            loop {
                {
                    // Drain notifications for up to 25s, then fall through to the
                    // keep-alive. Scope the borrow so we can query afterwards.
                    let mut notifs = client.notifications();
                    let mut it = notifs.timeout_iter(Duration::from_secs(25));
                    loop {
                        match it.next() {
                            Ok(Some(n)) => {
                                if let Ok(w) = serde_json::from_str::<Wire>(n.payload()) {
                                    if w.o != origin {
                                        let _ = remote.send(w.e);
                                    }
                                }
                            }
                            Ok(None) => break, // timeout tick
                            Err(_) => break,   // connection issue -> keep-alive detects it
                        }
                    }
                }
                // Keep-alive; a failure means a dropped connection -> reconnect.
                if client.execute("SELECT 1", &[]).is_err() {
                    break;
                }
            }
        })
        .ok();
}

fn random_origin() -> u64 {
    let mut buf = [0u8; 8];
    if getrandom::getrandom(&mut buf).is_err() {
        return snare_core::now_millis() as u64;
    }
    u64::from_le_bytes(buf)
}
