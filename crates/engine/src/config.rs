//! Engine configuration (TOML). M1: coordinator URL + dev user + state dir.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Base URL of the coordinator, e.g. "http://127.0.0.1:8080".
    pub coordinator: String,
    /// State directory (WG private key, pinned anchor). Created if missing.
    pub state_dir: PathBuf,
    /// Dev-only: caller identity sent as `?dev_user=` while the coordinator runs in fake mode.
    pub dev_user: Option<u64>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        Ok(toml::from_str(&text)?)
    }
}
