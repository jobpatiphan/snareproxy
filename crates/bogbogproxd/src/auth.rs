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

/// How long since a session's last activity before the operator is "offline".
const PRESENCE_TIMEOUT_MS: i64 = 30_000;
const SESSION_IDLE_TIMEOUT_MS: i64 = 12 * 60 * 60 * 1_000;

pub struct Auth {
    project_token: Option<String>,
    /// session token -> (operator, last-seen unix millis)
    sessions: Mutex<HashMap<String, (Operator, i64)>>,
}

impl Auth {
    pub fn new(project_token: Option<String>) -> Self {
        Self {
            project_token: project_token.filter(|token| !token.trim().is_empty()),
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
    pub fn create_session(&self, display_name: String) -> anyhow::Result<(String, Operator)> {
        let display_name = if display_name.trim().is_empty() {
            "operator".to_string()
        } else {
            display_name.trim().to_string()
        };
        let op = Operator {
            id: rand_hex(8)?,
            display_name,
        };
        let token = rand_hex(24)?;
        self.sessions
            .lock()
            .unwrap()
            .insert(token.clone(), (op.clone(), bogbogprox_core::now_millis()));
        Ok((token, op))
    }

    /// Verify a session token and refresh its last-seen (presence heartbeat).
    pub fn verify_session(&self, token: &str) -> Option<Operator> {
        let mut g = self.sessions.lock().unwrap();
        let now = bogbogprox_core::now_millis();
        g.retain(|_, (_, seen)| now.saturating_sub(*seen) <= SESSION_IDLE_TIMEOUT_MS);
        g.get_mut(token).map(|(op, seen)| {
            *seen = now;
            op.clone()
        })
    }

    pub fn revoke_session(&self, token: &str) -> bool {
        self.sessions.lock().unwrap().remove(token).is_some()
    }

    /// Operators seen within the presence window, newest first.
    pub fn online(&self) -> Vec<String> {
        let cutoff = bogbogprox_core::now_millis() - PRESENCE_TIMEOUT_MS;
        let g = self.sessions.lock().unwrap();
        let mut ops: Vec<(&Operator, i64)> = g
            .values()
            .filter(|(_, seen)| *seen >= cutoff)
            .map(|(op, seen)| (op, *seen))
            .collect();
        ops.sort_by_key(|(_, seen)| std::cmp::Reverse(*seen));
        ops.into_iter()
            .map(|(op, _)| op.display_name.clone())
            .collect()
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
fn rand_hex(n: usize) -> anyhow::Result<String> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf)
        .map_err(|e| anyhow::anyhow!("secure random generation failed: {e}"))?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_can_be_verified_and_revoked() {
        let auth = Auth::new(Some("project-secret".into()));
        let (token, _) = auth.create_session("alice".into()).unwrap();
        assert!(auth.verify_session(&token).is_some());
        assert!(auth.revoke_session(&token));
        assert!(auth.verify_session(&token).is_none());
    }

    #[test]
    fn empty_project_token_does_not_enable_auth() {
        assert!(!Auth::new(Some("   ".into())).enabled());
    }
}
