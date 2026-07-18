//! Match & Replace (§ Burp M&R) — automatic regex rewrites applied to every
//! request/response as it passes through the proxy.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::model::{Header, HttpRequest, HttpResponse};
use crate::session::template_for_regex;

/// Skip body-level regex on bodies larger than this (avoid pathological CPU on
/// big downloads). Header/URL rules still apply.
const MAX_BODY_SCAN: usize = 2 * 1024 * 1024;

/// Which part of a message a rule targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    RequestUrl,
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
}

impl Part {
    fn is_request(self) -> bool {
        matches!(self, Part::RequestUrl | Part::RequestHeader | Part::RequestBody)
    }
}

/// Serializable rule as seen over the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSpec {
    pub id: u64,
    pub name: String,
    pub enabled: bool,
    pub part: Part,
    /// Regex pattern (supports capture groups; replacement may reference `$1`).
    pub pattern: String,
    pub replace: String,
}

struct CompiledRule {
    spec: RuleSpec,
    re: Regex,
}

/// Thread-safe set of match/replace rules, shared with the engine.
#[derive(Default)]
pub struct Rules {
    next_id: AtomicU64,
    rules: Mutex<Vec<CompiledRule>>,
}

impl Rules {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn list(&self) -> Vec<RuleSpec> {
        self.rules.lock().unwrap().iter().map(|c| c.spec.clone()).collect()
    }

    /// Add a rule. Returns the stored spec, or an error if the regex is invalid.
    pub fn add(
        &self,
        name: String,
        part: Part,
        pattern: String,
        replace: String,
        enabled: bool,
    ) -> Result<RuleSpec, String> {
        let re = Regex::new(&pattern).map_err(|e| e.to_string())?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let spec = RuleSpec { id, name, enabled, part, pattern, replace };
        self.rules.lock().unwrap().push(CompiledRule { spec: spec.clone(), re });
        Ok(spec)
    }

    pub fn remove(&self, id: u64) -> bool {
        let mut g = self.rules.lock().unwrap();
        let before = g.len();
        g.retain(|c| c.spec.id != id);
        g.len() != before
    }

    pub fn set_enabled(&self, id: u64, on: bool) -> bool {
        let mut g = self.rules.lock().unwrap();
        for c in g.iter_mut() {
            if c.spec.id == id {
                c.spec.enabled = on;
                return true;
            }
        }
        false
    }

    /// True if any request-targeting rule is enabled (cheap gate for the engine).
    pub fn has_request_rules(&self) -> bool {
        self.rules
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.spec.enabled && c.spec.part.is_request())
    }

    pub fn has_response_rules(&self) -> bool {
        self.rules
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.spec.enabled && !c.spec.part.is_request())
    }

    /// Apply all enabled request rules in place. `{{var}}` in a replacement is
    /// substituted from `vars`. Returns true if anything changed.
    pub fn apply_request(&self, req: &mut HttpRequest, vars: &HashMap<String, String>) -> bool {
        let g = self.rules.lock().unwrap();
        let mut changed = false;
        for c in g.iter().filter(|c| c.spec.enabled) {
            let rep = template_for_regex(&c.spec.replace, vars);
            match c.spec.part {
                Part::RequestUrl => {
                    if let Cow::Owned(s) = c.re.replace_all(&req.path, rep.as_str()) {
                        req.path = s;
                        changed = true;
                    }
                }
                Part::RequestBody if req.body.len() <= MAX_BODY_SCAN => {
                    let body = String::from_utf8_lossy(&req.body).into_owned();
                    if let Cow::Owned(s) = c.re.replace_all(&body, rep.as_str()) {
                        req.body = s.into_bytes();
                        changed = true;
                    }
                }
                Part::RequestHeader => {
                    if apply_headers(&mut req.headers, &c.re, &rep) {
                        changed = true;
                    }
                }
                _ => {}
            }
        }
        changed
    }

    /// Apply all enabled response rules in place. Returns true if anything changed.
    pub fn apply_response(&self, resp: &mut HttpResponse, vars: &HashMap<String, String>) -> bool {
        let g = self.rules.lock().unwrap();
        let mut changed = false;
        for c in g.iter().filter(|c| c.spec.enabled) {
            let rep = template_for_regex(&c.spec.replace, vars);
            match c.spec.part {
                Part::ResponseBody if resp.body.len() <= MAX_BODY_SCAN => {
                    let body = String::from_utf8_lossy(&resp.body).into_owned();
                    if let Cow::Owned(s) = c.re.replace_all(&body, rep.as_str()) {
                        resp.body = s.into_bytes();
                        changed = true;
                    }
                }
                Part::ResponseHeader => {
                    if apply_headers(&mut resp.headers, &c.re, &rep) {
                        changed = true;
                    }
                }
                _ => {}
            }
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::HttpRequest;

    fn req(body: &str) -> HttpRequest {
        HttpRequest {
            method: "GET".into(),
            scheme: "https".into(),
            host: "h".into(),
            port: 443,
            path: "/a".into(),
            query: None,
            http_version: "HTTP/1.1".into(),
            headers: vec![("User-Agent".into(), "curl".into())],
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn body_replace_all() {
        let r = Rules::new();
        r.add("t".into(), Part::RequestBody, "foo".into(), "bar".into(), true).unwrap();
        let mut q = req("foo baz foo");
        assert!(r.apply_request(&mut q, &std::collections::HashMap::new()));
        assert_eq!(String::from_utf8_lossy(&q.body), "bar baz bar");
    }

    #[test]
    fn url_capture_group() {
        let r = Rules::new();
        r.add("t".into(), Part::RequestUrl, r"/(\w+)".into(), "/x-$1".into(), true).unwrap();
        let mut q = req("");
        assert!(r.apply_request(&mut q, &std::collections::HashMap::new()));
        assert_eq!(q.path, "/x-a");
    }

    #[test]
    fn header_rule_can_remove() {
        let r = Rules::new();
        r.add("t".into(), Part::RequestHeader, "^User-Agent:.*".into(), "".into(), true).unwrap();
        let mut q = req("");
        assert!(r.apply_request(&mut q, &std::collections::HashMap::new()));
        assert!(q.headers.is_empty());
    }

    #[test]
    fn bad_regex_is_rejected() {
        assert!(Rules::new().add("t".into(), Part::RequestBody, "(".into(), "".into(), true).is_err());
    }

    #[test]
    fn injects_variable_into_header() {
        let r = Rules::new();
        r.add("auth".into(), Part::RequestHeader, "^User-Agent:.*".into(),
              "Authorization: Bearer {{token}}".into(), true).unwrap();
        let mut vars = std::collections::HashMap::new();
        vars.insert("token".to_string(), "SECRET123".to_string());
        let mut q = req("");
        assert!(r.apply_request(&mut q, &vars));
        assert!(q.headers.iter().any(|(k, v)| k == "Authorization" && v == "Bearer SECRET123"));
    }

    #[test]
    fn disabled_rule_is_noop() {
        let r = Rules::new();
        r.add("t".into(), Part::RequestBody, "foo".into(), "bar".into(), false).unwrap();
        let mut q = req("foo");
        assert!(!r.apply_request(&mut q, &std::collections::HashMap::new()));
    }
}

/// Apply a rule across header lines ("Name: Value"); an empty result drops the
/// header, letting a rule remove headers too.
fn apply_headers(headers: &mut Vec<Header>, re: &Regex, rep: &str) -> bool {
    let mut changed = false;
    let mut out = Vec::with_capacity(headers.len());
    for (k, v) in headers.drain(..) {
        let line = format!("{k}: {v}");
        match re.replace_all(&line, rep) {
            Cow::Owned(s) => {
                changed = true;
                let s = s.trim();
                if s.is_empty() {
                    continue; // rule removed this header
                }
                match s.split_once(':') {
                    Some((nk, nv)) => out.push((nk.trim().to_string(), nv.trim().to_string())),
                    None => out.push((s.to_string(), String::new())),
                }
            }
            Cow::Borrowed(_) => out.push((k, v)),
        }
    }
    *headers = out;
    changed
}
