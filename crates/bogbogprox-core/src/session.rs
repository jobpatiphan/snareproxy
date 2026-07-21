//! Session handling (§ Burp session handling / macros).
//!
//! - [`Vars`] holds named string variables (e.g. an auth token).
//! - [`Macros`] holds request templates that, when run, extract a value from the
//!   response into a variable.
//! - [`template`] / [`template_for_regex`] substitute `{{name}}` placeholders,
//!   so a Match & Replace rule can inject a live variable (e.g. `Authorization:
//!   Bearer {{token}}`) and stay fresh by re-running the macro.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::model::Header;

/// Named string variables, shared across the engine, macros, and rules.
#[derive(Default)]
pub struct Vars {
    map: Mutex<HashMap<String, String>>,
}

impl Vars {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, k: &str, v: &str) {
        self.map
            .lock()
            .unwrap()
            .insert(k.to_string(), v.to_string());
    }

    pub fn remove(&self, k: &str) -> bool {
        self.map.lock().unwrap().remove(k).is_some()
    }

    pub fn snapshot(&self) -> HashMap<String, String> {
        self.map.lock().unwrap().clone()
    }

    pub fn list(&self) -> Vec<(String, String)> {
        let g = self.map.lock().unwrap();
        let mut v: Vec<_> = g.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        v.sort();
        v
    }

    pub fn load(&self, items: Vec<(String, String)>) {
        let mut g = self.map.lock().unwrap();
        g.clear();
        for (k, v) in items {
            g.insert(k, v);
        }
    }
}

/// A saved request + extraction that refreshes a variable when run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacroSpec {
    pub id: u64,
    pub name: String,
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: String,
    /// Regex to pull the value from the response (capture group 1, else whole match).
    pub extract: String,
    /// Variable the extracted value is stored into.
    pub var: String,
}

#[derive(Default)]
pub struct Macros {
    next_id: AtomicU64,
    list: Mutex<Vec<MacroSpec>>,
}

impl Macros {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&self, mut m: MacroSpec) -> MacroSpec {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        m.id = id;
        self.list.lock().unwrap().push(m.clone());
        m
    }

    pub fn list(&self) -> Vec<MacroSpec> {
        self.list.lock().unwrap().clone()
    }

    pub fn get(&self, id: u64) -> Option<MacroSpec> {
        self.list
            .lock()
            .unwrap()
            .iter()
            .find(|m| m.id == id)
            .cloned()
    }

    pub fn remove(&self, id: u64) -> bool {
        let mut g = self.list.lock().unwrap();
        let n = g.len();
        g.retain(|m| m.id != id);
        g.len() != n
    }

    pub fn load(&self, specs: Vec<MacroSpec>) {
        let mut g = self.list.lock().unwrap();
        g.clear();
        self.next_id.store(0, Ordering::Relaxed);
        for s in specs {
            if s.id > self.next_id.load(Ordering::Relaxed) {
                self.next_id.store(s.id, Ordering::Relaxed);
            }
            g.push(s);
        }
    }
}

/// Substitute `{{name}}` placeholders with variable values (plain).
pub fn template(s: &str, vars: &HashMap<String, String>) -> String {
    if !s.contains("{{") {
        return s.to_string();
    }
    let mut out = s.to_string();
    for (k, v) in vars {
        let needle = format!("{{{{{}}}}}", k);
        if out.contains(&needle) {
            out = out.replace(&needle, v);
        }
    }
    out
}

/// Like [`template`] but escapes `$` in substituted values so the result is safe
/// to use as a regex replacement string (where `$1` is a capture reference).
pub fn template_for_regex(s: &str, vars: &HashMap<String, String>) -> String {
    if !s.contains("{{") {
        return s.to_string();
    }
    let mut out = s.to_string();
    for (k, v) in vars {
        let needle = format!("{{{{{}}}}}", k);
        if out.contains(&needle) {
            out = out.replace(&needle, &v.replace('$', "$$"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vars_set_get_remove() {
        let v = Vars::new();
        v.set("token", "abc");
        assert_eq!(v.snapshot().get("token").unwrap(), "abc");
        assert!(v.remove("token"));
        assert!(v.snapshot().is_empty());
    }

    #[test]
    fn template_substitutes() {
        let mut m = HashMap::new();
        m.insert("token".to_string(), "xy".to_string());
        assert_eq!(template("Bearer {{token}}", &m), "Bearer xy");
        assert_eq!(template("no vars here", &m), "no vars here");
    }

    #[test]
    fn regex_template_escapes_dollar() {
        let mut m = HashMap::new();
        m.insert("t".to_string(), "a$1b".to_string());
        // the value's $1 must be escaped to $$1 so regex treats it literally
        assert_eq!(template_for_regex("X{{t}}", &m), "Xa$$1b");
    }
}
