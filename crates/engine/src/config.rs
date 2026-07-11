//! Engine configuration (TOML).

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Base URL of the coordinator, e.g. "http://127.0.0.1:8080".
    pub coordinator: String,
    /// State directory (WG private key, pinned anchor). Created if missing.
    pub state_dir: PathBuf,
    /// One-time enrollment key that binds this device to its owner on first register. Sent until
    /// enrolled; the coordinator then knows this device by its WG pubkey.
    pub enrollment_key: Option<String>,
    /// This machine's device name (the `<device>` DNS label). Defaults to the system hostname.
    #[serde(default)]
    pub device_name: Option<String>,

    // ---- mesh (daemon `run` mode) ----
    /// WireGuard interface name.
    #[serde(default = "default_iface")]
    pub iface: String,
    /// WireGuard UDP listen port.
    #[serde(default = "default_port")]
    pub listen_port: u16,
    /// Reachable endpoint reported to the coordinator (UPnP-mapped in production).
    pub endpoint: Option<SocketAddr>,
    /// How often to refresh attestations + seeds from the coordinator.
    #[serde(default = "default_refresh")]
    pub refresh_secs: u64,
    /// If set, run the `.internal` DNS resolver on this UDP address (e.g. "127.0.0.1:53").
    pub dns_bind: Option<SocketAddr>,
}

fn default_iface() -> String {
    "unl0".to_string()
}
fn default_port() -> u16 {
    51820
}
fn default_refresh() -> u64 {
    15
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        Ok(toml::from_str(&text)?)
    }

    /// This device's name: the configured value, else the system hostname, else `"device"`.
    pub fn device_name(&self) -> String {
        self.device_name
            .clone()
            .or_else(|| std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()))
            .unwrap_or_else(|| "device".to_string())
    }
}
