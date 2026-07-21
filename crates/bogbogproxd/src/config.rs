//! Persisted settings (§30) — rules, intercept scope, and scanner state survive
//! a daemon restart. Flows already persist in SQLite; this covers the rest.
//!
//! Intentionally *not* persisted: the intercept on/off toggles (session state —
//! you don't want intercept silently re-armed after a restart) and findings
//! (derived from traffic).

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use bogbogprox_core::intercept::Intercept;
use bogbogprox_core::rules::{RuleSpec, Rules};
use bogbogprox_core::scanner::Scanner;
use bogbogprox_core::session::{MacroSpec, Macros, Vars};

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
    #[serde(default)]
    pub annotations: Vec<bogbogprox_core::annotate::Annotation>,
}
fn yes() -> bool {
    true
}

#[derive(Clone)]
pub enum Backend {
    Local(PathBuf),
    Postgres(bogbogprox_store_postgres::PostgresStore),
}

impl Backend {
    pub fn load(&self) -> Option<Persisted> {
        let bytes = match self {
            Self::Local(path) => {
                if path.exists() {
                    if std::fs::symlink_metadata(path)
                        .map(|metadata| metadata.file_type().is_symlink())
                        .unwrap_or(false)
                    {
                        tracing::warn!("refusing symlinked config {}", path.display());
                        return None;
                    }
                    if let Err(e) = secure_file(path) {
                        tracing::warn!("could not secure config {}: {e:#}", path.display());
                    }
                }
                std::fs::read(path).ok()?
            }
            Self::Postgres(store) => match store.load_setting("shared_config") {
                Ok(Some(value)) => value.into_bytes(),
                Ok(None) => return None,
                Err(e) => {
                    tracing::warn!("could not load shared Postgres config: {e:#}");
                    return None;
                }
            },
        };
        match serde_json::from_slice(&bytes) {
            Ok(p) => Some(p),
            Err(e) => {
                tracing::warn!("ignoring malformed persisted config: {e}");
                None
            }
        }
    }

    pub fn save(&self, persisted: &Persisted) {
        let bytes = match serde_json::to_vec_pretty(persisted) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!("could not serialize config: {e}");
                return;
            }
        };
        let result = match self {
            Self::Local(path) => save_local(path, &bytes),
            Self::Postgres(store) => {
                store.save_setting("shared_config", &String::from_utf8_lossy(&bytes))
            }
        };
        if let Err(e) = result {
            tracing::warn!("could not save persisted config: {e:#}");
        }
    }

    pub fn save_kind(&self, kind: &str, persisted: &Persisted) {
        let Self::Postgres(store) = self else {
            self.save(persisted);
            return;
        };
        let (field, value) = match kind {
            "rules" => ("rules", serde_json::to_string(&persisted.rules)),
            "scope" => ("scope", serde_json::to_string(&persisted.scope)),
            "scanner" => (
                "scanner_enabled",
                serde_json::to_string(&persisted.scanner_enabled),
            ),
            "vars" => ("vars", serde_json::to_string(&persisted.vars)),
            "macros" => ("macros", serde_json::to_string(&persisted.macros)),
            "annotations" => ("annotations", serde_json::to_string(&persisted.annotations)),
            _ => {
                self.save(persisted);
                return;
            }
        };
        match value {
            Ok(value) => {
                if let Err(e) = store.save_setting_field("shared_config", field, &value) {
                    tracing::warn!("could not save shared {kind} config: {e:#}");
                }
            }
            Err(e) => tracing::warn!("could not serialize shared {kind} config: {e}"),
        }
    }
}

/// Apply persisted settings onto the live coordinators at startup.
#[allow(clippy::too_many_arguments)]
pub fn apply(
    p: &Persisted,
    rules: &Rules,
    intercept: &Intercept,
    scanner: &Scanner,
    vars: &Vars,
    macros: &Macros,
    annotations: &bogbogprox_core::annotate::Annotations,
) {
    if let Err(e) = rules.replace(p.rules.clone()) {
        tracing::warn!("ignoring invalid persisted rules: {e}");
    }
    intercept.set_scope(p.scope.clone());
    scanner.set_enabled(p.scanner_enabled);
    vars.load(p.vars.clone());
    macros.load(p.macros.clone());
    annotations.load(p.annotations.clone());
}

/// Snapshot the current settings for writing to disk.
pub fn snapshot(
    rules: &Rules,
    intercept: &Intercept,
    scanner: &Scanner,
    vars: &Vars,
    macros: &Macros,
    annotations: &bogbogprox_core::annotate::Annotations,
) -> Persisted {
    Persisted {
        rules: rules.list(),
        scope: intercept.scope(),
        scanner_enabled: scanner.enabled(),
        vars: vars.list(),
        macros: macros.list(),
        annotations: annotations.snapshot(),
    }
}

static SAVE_SEQ: AtomicU64 = AtomicU64::new(0);

fn save_local(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(dir) = path.parent() {
        crate::paths::secure_dir(dir)?;
    }
    let seq = SAVE_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!(
        "tmp-{}-{}-{seq}",
        std::process::id(),
        bogbogprox_core::now_millis()
    ));
    write_private(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    secure_file(path)?;
    Ok(())
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(unix)]
fn secure_file(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn secure_file(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Persisted {
        Persisted {
            rules: vec![],
            scope: vec!["example.test".into()],
            scanner_enabled: true,
            vars: vec![("token".into(), "secret".into())],
            macros: vec![],
            annotations: vec![],
        }
    }

    #[test]
    fn local_backend_round_trips_atomically() {
        let root = std::env::temp_dir().join(format!(
            "bogbogprox-config-test-{}-{}",
            std::process::id(),
            bogbogprox_core::now_millis()
        ));
        let path = root.join("config.json");
        let backend = Backend::Local(path.clone());
        backend.save(&sample());
        let loaded = backend.load().unwrap();
        assert_eq!(loaded.scope, vec!["example.test"]);
        assert_eq!(loaded.vars[0].1, "secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir(root);
    }
}
