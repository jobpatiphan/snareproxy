//! WebSocket capture (§ Burp WebSockets) — a running log of intercepted
//! WebSocket messages. Unlike HTTP flows (request/response pairs), a WebSocket
//! is a stream of messages, so it gets its own lightweight model + log.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

/// A single captured WebSocket message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    pub id: u64,
    pub ts: i64,
    pub host: String,
    /// "send" = client→server, "recv" = server→client.
    pub direction: String,
    /// "text" | "binary" | "ping" | "pong" | "close" | "frame".
    pub kind: String,
    /// Text payload verbatim; binary/ping/pong as base64.
    pub data: String,
    pub size: usize,
}

/// In-memory log of WebSocket messages, shared with the engine (not persisted —
/// like findings, it's derived from live traffic).
#[derive(Default)]
pub struct WsLog {
    next_id: AtomicU64,
    msgs: Mutex<Vec<WsMessage>>,
}

impl WsLog {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        ts: i64,
        host: String,
        direction: &str,
        kind: &str,
        data: String,
        size: usize,
    ) -> WsMessage {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let m = WsMessage {
            id,
            ts,
            host,
            direction: direction.to_string(),
            kind: kind.to_string(),
            data,
            size,
        };
        let mut g = self.msgs.lock().unwrap();
        g.push(m.clone());
        // Cap memory: keep the most recent 5000 messages.
        let len = g.len();
        if len > 5000 {
            g.drain(0..len - 5000);
        }
        m
    }

    pub fn list(&self) -> Vec<WsMessage> {
        self.msgs.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.msgs.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_lists() {
        let log = WsLog::new();
        let a = log.record(1, "h".into(), "send", "text", "hi".into(), 2);
        let b = log.record(2, "h".into(), "recv", "text", "yo".into(), 2);
        assert_eq!(a.id, 1);
        assert_eq!(b.id, 2);
        assert_eq!(b.direction, "recv");
        let all = log.list();
        assert_eq!(all.len(), 2);
        log.clear();
        assert!(log.list().is_empty());
    }

    #[test]
    fn caps_at_5000() {
        let log = WsLog::new();
        for i in 0..5100 {
            log.record(i, "h".into(), "send", "text", "x".into(), 1);
        }
        assert_eq!(log.list().len(), 5000);
    }
}
