//! Persisted settings (§30) — rules, intercept scope, and scanner state survive
//! a daemon restart. Flows already persist in SQLite; this covers the rest.
//!
//! Intentionally *not* persisted: the intercept on/off toggles (session state —
//! you don't want intercept silently re-armed after a restart) and findings
//! (derived from traffic).

use std::path::Path;

use serde::{Deserialize, Serialize};
use snare_core::intercept::Intercept;
use snare_core::rules::{RuleSpec, Rules};
use snare_core::scanner::Scanner;
use snare_core::session::{MacroSpec, Macros, Vars};

#[derive(Debug, Serialize, Deserialize)]
pub struct Persisted {
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
    #[serde(default)]
    pub scope: Vec<String>,
    #[serde(default = "yes")]
    pub scanner_enabled: bool,
    #[serde(default)]
    pub vars: Vec<(String, String)>,
    #[serde(default)]
    pub macros: Vec<MacroSpec>,
}
fn yes() -> bool {
    true
}

/// Read persisted settings, or `None` if there's no config file yet (so first
/// run keeps in-code defaults).
pub fn load(path: &Path) -> Option<Persisted> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(p) => Some(p),
        Err(e) => {
            tracing::warn!("ignoring malformed config {}: {e}", path.display());
            None
        }
    }
}

/// Apply persisted settings onto the live coordinators at startup.
pub fn apply(
    p: &Persisted,
    rules: &Rules,
    intercept: &Intercept,
    scanner: &Scanner,
    vars: &Vars,
    macros: &Macros,
) {
    for r in &p.rules {
        // Re-add each rule; a bad regex (shouldn't happen — it was valid once) is
        // skipped rather than aborting startup.
        if let Err(e) = rules.add(r.name.clone(), r.part, r.pattern.clone(), r.replace.clone(), r.enabled)
        {
            tracing::warn!("dropping saved rule {:?}: {e}", r.name);
        }
    }
    intercept.set_scope(p.scope.clone());
    scanner.set_enabled(p.scanner_enabled);
    vars.load(p.vars.clone());
    macros.load(p.macros.clone());
}

/// Snapshot the current settings for writing to disk.
pub fn snapshot(
    rules: &Rules,
    intercept: &Intercept,
    scanner: &Scanner,
    vars: &Vars,
    macros: &Macros,
) -> Persisted {
    Persisted {
        rules: rules.list(),
        scope: intercept.scope(),
        scanner_enabled: scanner.enabled(),
        vars: vars.list(),
        macros: macros.list(),
    }
}

/// Best-effort save (creates the parent dir). Never fails an API call.
pub fn save(path: &Path, p: &Persisted) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    match serde_json::to_vec_pretty(p) {
        Ok(bytes) => {
            if let Err(e) = std::fs::write(path, bytes) {
                tracing::warn!("could not save config {}: {e}", path.display());
            }
        }
        Err(e) => tracing::warn!("could not serialize config: {e}"),
    }
}
