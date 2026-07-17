//! Engine configuration (TOML).

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Base URL of the coordinator, e.g. "https://coord.example.com" (or loopback http for dev).
    pub coordinator: String,
    /// Allow a plaintext-`http` coordinator URL to a **non-loopback** host. Off by default: the
    /// engine refuses such URLs at load, since an on-path attacker who can tamper the plaintext
    /// control channel could feed the client forged coordinator responses. HTTPS is always allowed,
    /// and loopback `http` (local dev) is always allowed. Set `true` only for a trusted offline
    /// dev/test setup (e.g. the namespace scripts) where the coordinator is reachable only over a
    /// private link you control.
    #[serde(default)]
    pub allow_insecure_http: bool,
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
    /// Reachable endpoint reported to the coordinator. If set, it is advertised as-is (manual
    /// port-forward / known public address) and UPnP is skipped.
    pub endpoint: Option<SocketAddr>,
    /// Auto-map the WireGuard port via UPnP-IGD and advertise the mapped endpoint when `endpoint`
    /// is not set. On by default; best-effort (no gateway → no endpoint, we rely on being dialed).
    #[serde(default = "default_true")]
    pub upnp: bool,
    /// How often to refresh attestations + seeds from the coordinator.
    #[serde(default = "default_refresh")]
    pub refresh_secs: u64,
    /// Run the `.unity.internal` DNS resolver for `<device>.<user>.unity.internal` name resolution.
    /// On by default; set `false` to reach peers by IP and manage DNS yourself. It binds **this
    /// device's own mesh IP on port 53** (not loopback): own-IP keeps `:53` free on every platform
    /// (nothing else owns the wg address) and satisfies Windows NRPT, which forwards to port 53 only.
    #[serde(default = "default_true")]
    pub dns: bool,
    /// Point the OS resolver at our `.unity.internal` server (systemd-resolved per-link routing domain).
    /// On by default; acts only when `dns` is on. Best-effort — needs privilege, and a failure only
    /// means `.unity.internal` names don't auto-resolve. Set `false` to manage DNS yourself.
    #[serde(default = "default_true")]
    pub resolver_hook: bool,
    /// Control socket path for CLI/GUI frontends. Defaults to `<state_dir>/control.sock`.
    pub control_socket: Option<PathBuf>,
    /// Group to own the control socket (mode 660, `root:<group>`) so its members can drive the
    /// daemon. Set by packaged installs (e.g. `"unitylan"`). When unset, the socket is handed to
    /// the `sudo`-invoking user if launched via sudo, else left root-only.
    pub control_group: Option<String>,
    /// Enforce the host firewall (default-deny inbound on the wg iface + explicit `expose`).
    /// On by default — secure posture. Set `false` on platforms without a firewall backend.
    #[serde(default = "default_true")]
    pub firewall: bool,
    /// Ports to expose at startup (before any runtime `ctl expose`).
    #[serde(default)]
    pub expose: Vec<ExposeSeed>,
    /// Loopback redirect for the interactive-login (PKCE) flow. Must match a redirect URI registered
    /// with the Discord app; the port is where the engine binds its one-shot OAuth listener. Being
    /// loopback, it works from any host/VM regardless of LAN address.
    #[serde(default = "default_oauth_redirect")]
    pub oauth_redirect: String,
    /// Default peering posture for networks discovered from now on. `true` (secure default) opts a
    /// newly-seen network out of peering until the user enables it; `false` enrols it automatically.
    /// Seeds the persisted policy on first run; thereafter the GUI toggle is the source of truth.
    #[serde(default = "default_true")]
    pub disable_new_networks: bool,
    /// Always peer with the owner's own other devices (same Discord user), even when they share no
    /// enabled network — so a user's devices stay mutually reachable regardless of network membership.
    /// Default `true`. Seeds the persisted policy on first run; thereafter the GUI toggle is the
    /// source of truth.
    #[serde(default = "default_true")]
    pub peer_own_devices: bool,
    /// Offer this device as a **ciphertext relay** for co-members whose hole punch fails (§7.2,
    /// M5.4). Opt-in (default `false`) — relaying spends this host's uplink for others. Only takes
    /// effect when the device is directly dialable (a self `endpoint`, manual or UPnP): a NAT'd
    /// device can't serve as a relay. Runs an embedded TURN server on `relay_port`.
    #[serde(default)]
    pub relay: bool,
    /// UDP port for the embedded TURN relay server (when `relay` is on). Separate from the WG port,
    /// which boringtun owns. Advertised to co-members via the coordinator as our relay address.
    #[serde(default = "default_relay_port")]
    pub relay_port: u16,
    /// Cap on concurrent relay allocations (when `relay` is on) — bounds the share of this host's
    /// uplink a relayed mesh can spend (§7.2 DoS surface). A new client over the cap is refused.
    #[serde(default = "default_relay_max_allocations")]
    pub relay_max_allocations: usize,
    /// Allow the embedded relay to forward to **private/loopback/CGNAT** destinations. Off by
    /// default: the relay refuses non-public egress so it can't be abused as an open UDP proxy or an
    /// SSRF pivot into the relay host's LAN (§7.2). Set `true` only for an offline test topology
    /// where the mesh's "public" endpoints are themselves RFC1918 (e.g. the namespace scripts).
    #[serde(default)]
    pub relay_allow_private_dst: bool,
    /// Side-socket ICE for stuck peers (M5.5), on the userspace backend only. Default on. When off,
    /// the userspace path falls back to the M5.2 punch + M5.4 relay (the pre-ICE behavior) — an
    /// escape hatch and how the M5.4 relay path is exercised on Linux. No effect on kernel backends.
    #[serde(default = "default_true")]
    pub ice: bool,
}

/// A config-seeded port exposure. `proto` defaults to `tcp`.
#[derive(Debug, Deserialize)]
pub struct ExposeSeed {
    pub port: u16,
    #[serde(default = "default_proto")]
    pub proto: String,
}

fn default_true() -> bool {
    true
}
fn default_proto() -> String {
    "tcp".to_string()
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
fn default_oauth_redirect() -> String {
    "http://127.0.0.1:8765/callback".to_string()
}
fn default_relay_port() -> u16 {
    3478 // the IANA-registered TURN port
}
fn default_relay_max_allocations() -> usize {
    64
}

/// Starter config written by `load_or_init` when the default path is missing. Points at a
/// local coordinator; `device_name` is omitted so it falls back to the system hostname.
const DEFAULT_CONFIG: &str = "\
coordinator = \"http://127.0.0.1:8080\"
state_dir = \"engine-state\"
iface = \"unl0\"
listen_port = 51820
endpoint = \"127.0.0.1:51820\"
refresh_secs = 15
";

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let cfg: Self = toml::from_str(&text)?;
        cfg.validate_coordinator()?;
        Ok(cfg)
    }

    /// Reject a plaintext-`http` coordinator URL to a non-loopback host unless the operator opted in
    /// via `allow_insecure_http`. HTTPS and loopback http are always fine. Fail-closed: a
    /// misconfigured (tamperable) control channel stops the engine at load rather than silently
    /// trusting whatever a MITM returns.
    fn validate_coordinator(&self) -> anyhow::Result<()> {
        let url = reqwest::Url::parse(&self.coordinator)
            .map_err(|e| anyhow::anyhow!("invalid coordinator URL {:?}: {e}", self.coordinator))?;
        match url.scheme() {
            "https" => Ok(()),
            "http" => {
                let host = url.host_str().unwrap_or("");
                let host = host.trim_start_matches('[').trim_end_matches(']');
                let loopback = host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .map(|ip| ip.is_loopback())
                        .unwrap_or(false);
                if loopback {
                    Ok(())
                } else if self.allow_insecure_http {
                    tracing::warn!(
                        "coordinator {:?} uses plaintext http to a non-loopback host — allowed \
                         only because allow_insecure_http is set (dev/test only; the control \
                         channel is unauthenticated and tamperable)",
                        self.coordinator
                    );
                    Ok(())
                } else {
                    anyhow::bail!(
                        "coordinator {:?} uses plaintext http to a non-loopback host; use https:// \
                         (or set allow_insecure_http = true for a trusted offline dev/test link)",
                        self.coordinator
                    )
                }
            }
            other => {
                anyhow::bail!("coordinator URL scheme must be http or https, got {other:?}")
            }
        }
    }

    /// Load `path`, first writing a starter config if it's missing. Used only for the default
    /// path (no config argument) so a bare `unitylan-engine run` bootstraps a local dev config.
    pub fn load_or_init(path: &std::path::Path) -> anyhow::Result<Self> {
        if !path.exists() {
            std::fs::write(path, DEFAULT_CONFIG)
                .map_err(|e| anyhow::anyhow!("writing default {}: {e}", path.display()))?;
            tracing::info!("no config found — wrote default → {}", path.display());
        }
        Self::load(path)
    }

    /// Control-socket path: the configured value, else `<state_dir>/control.sock`. Used as the
    /// unix-domain socket path (on Windows the transport is a named pipe — see `control_name`).
    #[cfg(not(windows))]
    pub fn control_socket_path(&self) -> PathBuf {
        self.control_socket
            .clone()
            .unwrap_or_else(|| self.state_dir.join("control.sock"))
    }

    /// Platform local-socket endpoint name for the control channel: the filesystem socket path on
    /// unix, a named-pipe name (`unitylan-<stem>`, mapped by interprocess to `\\.\pipe\...`) on
    /// Windows. The GUI derives the same pipe name from its socket argument's file stem, so a
    /// default `control.sock` on both sides agrees on `unitylan-control`.
    pub fn control_name(&self) -> String {
        #[cfg(windows)]
        {
            let stem = self
                .control_socket
                .as_ref()
                .and_then(|p| p.file_stem())
                .and_then(|s| s.to_str())
                .unwrap_or("control");
            format!("unitylan-{stem}")
        }
        #[cfg(not(windows))]
        {
            self.control_socket_path().to_string_lossy().into_owned()
        }
    }

    /// This device's name: the configured value, else the system hostname, else `"device"`.
    /// `HOSTNAME` is the unix convention; `COMPUTERNAME` is where Windows keeps the machine name
    /// (`HOSTNAME` is unset there), so check both to avoid falling back to the bare `"device"`.
    pub fn device_name(&self) -> String {
        self.device_name
            .clone()
            .or_else(|| std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()))
            .or_else(|| std::env::var("COMPUTERNAME").ok().filter(|h| !h.is_empty()))
            .unwrap_or_else(|| "device".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validate(url: &str, allow: bool) -> anyhow::Result<()> {
        let toml =
            format!("coordinator = \"{url}\"\nstate_dir = \"s\"\nallow_insecure_http = {allow}");
        let cfg: Config = toml::from_str(&toml).unwrap();
        cfg.validate_coordinator()
    }

    #[test]
    fn coordinator_url_policy() {
        // https and loopback http are always fine.
        assert!(validate("https://coord.example.com", false).is_ok());
        assert!(validate("http://127.0.0.1:8080", false).is_ok());
        assert!(validate("http://localhost:8080", false).is_ok());
        assert!(validate("http://[::1]:8080", false).is_ok());
        // Plaintext http to a non-loopback host is refused unless explicitly opted in.
        assert!(validate("http://10.0.0.1:8080", false).is_err());
        assert!(validate("http://coord.example.com", false).is_err());
        assert!(validate("http://10.0.0.1:8080", true).is_ok());
        // Unsupported scheme.
        assert!(validate("ftp://coord.example.com", false).is_err());
    }
}
