//! Team-mode auth (design: team-mode.md T2).
//!
//! A shared **project token** grants a session: `POST /team/join` with the
//! project token + a display name returns a per-session bearer token that all
//! subsequent API/SSE calls must carry. When no project token is configured the
//! server is in **local mode** and auth is a no-op (backward compatible).

use std::collections::HashMap;
use std::sync::Mutex;

/// An authenticated operator (available in request extensions for attribution).
#[derive(Debug, Clone)]
pub struct Operator {
    pub id: String,
    pub display_name: String,
}

pub struct Auth {
    project_token: Option<String>,
    sessions: Mutex<HashMap<String, Operator>>,
}

impl Auth {
    pub fn new(project_token: Option<String>) -> Self {
        Self {
            project_token,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// True in team mode (a project token is set); false in local mode.
    pub fn enabled(&self) -> bool {
        self.project_token.is_some()
    }

    pub fn verify_project(&self, token: &str) -> bool {
        match &self.project_token {
            Some(t) => constant_time_eq(t.as_bytes(), token.as_bytes()),
            None => false,
        }
    }

    /// Create a session for a joining operator; returns (session_token, operator).
    pub fn create_session(&self, display_name: String) -> (String, Operator) {
        let display_name = if display_name.trim().is_empty() {
            "operator".to_string()
        } else {
            display_name.trim().to_string()
        };
        let op = Operator {
            id: rand_hex(8),
            display_name,
        };
        let token = rand_hex(24);
        self.sessions.lock().unwrap().insert(token.clone(), op.clone());
        (token, op)
    }

    pub fn verify_session(&self, token: &str) -> Option<Operator> {
        self.sessions.lock().unwrap().get(token).cloned()
    }
}

/// Timing-safe token comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `n` cryptographically-random bytes, hex-encoded.
fn rand_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    // getrandom failing is catastrophic (no entropy) — fall back to a non-secret
    // marker rather than panicking the server.
    if getrandom::getrandom(&mut buf).is_err() {
        return format!("insecure-{}", snare_core::now_millis());
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}
