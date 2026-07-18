//! Passive scanner (§ Burp passive scan) — inspects every captured flow and
//! raises findings for common security issues, without sending any new traffic.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::model::Flow;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: u64,
    pub flow_id: i64,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub host: String,
}

/// Passive scanner state, shared with the engine.
pub struct Scanner {
    enabled: AtomicBool,
    next_id: AtomicU64,
    findings: Mutex<Vec<Finding>>,
    /// De-dupe key `host|title` so the same issue isn't raised on every request.
    seen: Mutex<HashSet<String>>,
}

impl Default for Scanner {
    fn default() -> Self {
        Self {
            enabled: AtomicBool::new(true), // passive scanning on by default
            next_id: AtomicU64::new(0),
            findings: Mutex::new(Vec::new()),
            seen: Mutex::new(HashSet::new()),
        }
    }
}

impl Scanner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }

    pub fn list(&self) -> Vec<Finding> {
        self.findings.lock().unwrap().clone()
    }

    pub fn clear(&self) {
        self.findings.lock().unwrap().clear();
        self.seen.lock().unwrap().clear();
    }

    /// Inspect a completed flow and return any *new* findings (also stored).
    pub fn scan(&self, flow: &Flow) -> Vec<Finding> {
        if !self.enabled() {
            return vec![];
        }
        let resp = match &flow.response {
            Some(r) => r,
            None => return vec![],
        };
        let req = &flow.request;
        let host = req.host.clone();
        let is_https = req.scheme == "https";
        let ct = resp.mime().unwrap_or("").to_string();
        let is_html = ct.contains("html");

        let mut raw: Vec<(Severity, String, String)> = Vec::new();
        let hdr = |name: &str| resp.header(name).is_some();

        if is_html {
            if !hdr("content-security-policy") {
                raw.push((Severity::Low, "Missing Content-Security-Policy".into(),
                    "No CSP header — reduces XSS/injection defence.".into()));
            }
            if !hdr("x-frame-options") && !hdr("content-security-policy") {
                raw.push((Severity::Low, "Missing X-Frame-Options".into(),
                    "Page may be framable (clickjacking).".into()));
            }
            if !hdr("x-content-type-options") {
                raw.push((Severity::Info, "Missing X-Content-Type-Options".into(),
                    "No `nosniff` — browser may MIME-sniff.".into()));
            }
        }
        if is_https && !hdr("strict-transport-security") {
            raw.push((Severity::Low, "Missing HSTS".into(),
                "HTTPS response without Strict-Transport-Security.".into()));
        }
        if let Some(server) = resp.header("server") {
            if server.chars().any(|c| c.is_ascii_digit()) {
                raw.push((Severity::Info, "Server version disclosure".into(), format!("Server: {server}")));
            }
        }
        if let Some(p) = resp.header("x-powered-by") {
            raw.push((Severity::Info, "X-Powered-By disclosure".into(), format!("X-Powered-By: {p}")));
        }
        for (k, v) in &resp.headers {
            if k.eq_ignore_ascii_case("set-cookie") {
                let low = v.to_ascii_lowercase();
                if !low.contains("httponly") {
                    raw.push((Severity::Low, "Cookie without HttpOnly".into(),
                        v.split(';').next().unwrap_or(v).to_string()));
                }
                if is_https && !low.contains("secure") {
                    raw.push((Severity::Low, "Cookie without Secure".into(),
                        v.split(';').next().unwrap_or(v).to_string()));
                }
            }
        }
        // Reflected query-parameter value (basic reflected-XSS indicator).
        if is_html {
            if let Some(q) = &req.query {
                let body = String::from_utf8_lossy(&resp.body);
                for pair in q.split('&') {
                    if let Some((name, val)) = pair.split_once('=') {
                        if val.len() >= 4 && body.contains(val) {
                            raw.push((Severity::Medium, "Reflected parameter in response".into(),
                                format!("`{name}={val}` reflected — check for XSS.")));
                            break;
                        }
                    }
                }
            }
        }

        let mut seen = self.seen.lock().unwrap();
        let mut store = self.findings.lock().unwrap();
        let mut out = Vec::new();
        for (severity, title, detail) in raw {
            let key = format!("{host}|{title}");
            if !seen.insert(key) {
                continue; // already reported for this host
            }
            let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
            let f = Finding { id, flow_id: flow.id, severity, title, detail, host: host.clone() };
            store.push(f.clone());
            out.push(f);
        }
        out
    }
}
