//! Filesystem layout (§29): XDG config/data dirs with env override.

use std::path::PathBuf;

use anyhow::{Context, Result};
use directories::ProjectDirs;

pub struct Paths {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
}

/// Create an application-private directory and tighten an existing one.
pub fn secure_dir(path: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

impl Paths {
    pub fn resolve() -> Result<Self> {
        // `BOGBOGPROX_HOME` overrides everything (handy for tests / portable installs).
        if let Ok(home) = std::env::var("BOGBOGPROX_HOME") {
            let home = PathBuf::from(home);
            return Ok(Self {
                config_dir: home.join("config"),
                data_dir: home.join("data"),
            });
        }
        let pd = ProjectDirs::from("dev", "BogBogProx", "bogbogprox")
            .context("cannot determine home directory")?;
        Ok(Self {
            config_dir: pd.config_dir().to_path_buf(),
            data_dir: pd.data_dir().to_path_buf(),
        })
    }

    pub fn ca_dir(&self) -> PathBuf {
        self.config_dir.join("ca")
    }
    pub fn ca_cert(&self) -> PathBuf {
        self.ca_dir().join("bogbogprox-ca.pem")
    }
    pub fn ca_key(&self) -> PathBuf {
        self.ca_dir().join("bogbogprox-ca.key")
    }
    pub fn db(&self) -> PathBuf {
        self.data_dir.join("flows.sqlite")
    }
    /// Persisted rules / scope / scanner settings.
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.json")
    }
}
