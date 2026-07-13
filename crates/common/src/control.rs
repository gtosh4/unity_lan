//! Control-socket protocol (design.md §3.2, §8): the newline-delimited JSON an unprivileged
//! frontend (CLI, iced GUI) exchanges with the privileged engine daemon.
//!
//! Pure wire types only — the engine owns the server, each frontend its own client transport
//! (Unix socket now, Windows named pipe later). Shared here so frontends need not depend on the
//! engine crate.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::api::{ManageOp, ManageResp, NetworkStatus};

/// The Windows SCM service key the engine installs itself under. Shared so the engine (installer +
/// SCM entry point) and the GUI (status query + start/stop) address the same service.
pub const WINDOWS_SERVICE_NAME: &str = "UnityLANEngine";

#[derive(Serialize, Deserialize)]
pub enum ControlRequest {
    Status,
    Manage(ManageOp),
    /// Firewall port exposure — handled locally by the daemon (not forwarded to the coordinator).
    Expose(ExposeOp),
    /// Enable/disable this device's peering on a network (role@guild). Handled locally (the client
    /// is the source of truth) so it works even when the coordinator is unreachable; the change
    /// rides along to the coordinator on the next register/refresh.
    SetNetwork {
        guild_id: u64,
        role_id: u64,
        enabled: bool,
    },
    /// Begin interactive login: ask the coordinator (via the daemon) for the Discord authorize URL
    /// to open. The daemon's register loop binds the device once the browser completes the flow.
    Login,
    /// Connect (`true`) or disconnect (`false`) the mesh. Disconnect keeps the daemon resident and
    /// still polling the coordinator (so reconnect is instant) but brings the local peer-set down
    /// and withdraws this device from every co-member's seed list — peers see it go offline.
    /// Handled locally (persisted, source of truth), so it works even when the coordinator is
    /// unreachable; the change rides to the coordinator on the next refresh.
    SetConnected {
        connected: bool,
    },
    /// Set the local policy for networks discovered from now on: `disable = true` opts newly-seen
    /// networks out of peering by default (the secure default), `false` enrols them automatically.
    /// Handled locally (persisted, source of truth); returns the updated [`StatusReport`].
    SetNewNetworkDefault {
        disable: bool,
    },
}

#[derive(Serialize, Deserialize)]
pub enum ControlResponse {
    Status(StatusReport),
    Manage(ManageResp),
    Expose(ExposeResp),
    Network(NetworkResp),
    Login(LoginResp),
    Connected(ConnectedResp),
    Error(String),
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConnectedResp {
    /// The mesh connection state after the toggle (`true` = connected).
    pub connected: bool,
    pub message: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LoginResp {
    /// The Discord authorize URL the user opens to complete login.
    pub authorize_url: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkResp {
    pub message: String,
    /// The device's networks after the toggle, with effective (local) enabled state.
    pub networks: Vec<NetworkStatus>,
}

/// Transport protocol of an exposed port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// A firewall exposure op over the control socket. `net` scopes the exposure to one network's
/// peers (source-IP filtered); `None` opens the port to every peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExposeOp {
    List,
    Add {
        proto: Proto,
        port: u16,
        net: Option<String>,
    },
    Remove {
        proto: Proto,
        port: u16,
    },
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExposeResp {
    pub message: String,
    pub exposed: Vec<ExposedPort>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExposedPort {
    pub proto: Proto,
    pub port: u16,
    /// The network this port is scoped to, or `None` for all peers.
    pub net: Option<String>,
}

/// A snapshot of the daemon's live mesh state: this device plus the peers it has meshed with.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatusReport {
    pub device: Option<DeviceStatus>,
    pub peers: Vec<PeerStatus>,
    /// Every network this device's roles grant (role@guild) + per-device enabled state — the
    /// source for the GUI's peering toggle. Empty when not joined.
    #[serde(default)]
    pub networks: Vec<NetworkStatus>,
    /// True while the daemon is up but the device isn't logged in / enrolled — the GUI shows a
    /// "Log in with Discord" button.
    #[serde(default)]
    pub needs_login: bool,
    /// Whether the mesh is connected (vs. locally disconnected/paused). Defaults to `true` so a
    /// status from an older daemon (no field) reads as connected. Toggled by `SetConnected`.
    #[serde(default = "default_true")]
    pub connected: bool,
    /// Whether networks discovered from now on default to *disabled* (opted out of peering). The
    /// secure default is `true`; the GUI toggles it via `SetNewNetworkDefault`.
    #[serde(default = "default_true")]
    pub disable_new_networks: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceStatus {
    pub wg_ip: Ipv4Addr,
    pub hostname: String,
    pub is_primary: bool,
    pub networks: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerStatus {
    pub hostname: String,
    pub wg_ip: Ipv4Addr,
    pub endpoint: Option<SocketAddr>,
    /// How this peer is (or isn't) reachable — surfaces a stuck hole punch. Defaults to `Direct`.
    #[serde(default)]
    pub reach: PeerReach,
}

/// A peer's data-plane reachability, for status display (§7.2 diagnostics).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerReach {
    /// Connected — reached directly (dialable/forwarded) or a hole punch that completed.
    #[default]
    Direct,
    /// Hole punch in progress: we're dialing the peer's reflexive, no handshake yet.
    Punching,
    /// Hole punch attempted but never completed (no handshake). Likely symmetric NAT on both
    /// ends — not traversable without a relay (out of scope for v1, §7.2).
    Unreachable,
}

/// Classify a peer's reachability from whether it needed a hole punch, whether a WG handshake has
/// completed, and how long the punch has been outstanding. Pure, so it's unit-testable.
pub fn classify_reach(punched: bool, connected: bool, punch_age_secs: u64) -> PeerReach {
    if connected || !punched {
        // Connected (directly or via a completed punch), or a normal peer still bootstrapping.
        PeerReach::Direct
    } else if punch_age_secs >= 30 {
        PeerReach::Unreachable
    } else {
        PeerReach::Punching
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_reach, PeerReach};

    #[test]
    fn reach_classification() {
        // A directly-reachable / non-punched peer is always Direct.
        assert_eq!(classify_reach(false, false, 0), PeerReach::Direct);
        assert_eq!(classify_reach(false, true, 999), PeerReach::Direct);
        // A punch that completed (handshake seen) reads as Direct regardless of age.
        assert_eq!(classify_reach(true, true, 5), PeerReach::Direct);
        // Punching in progress, within the grace window.
        assert_eq!(classify_reach(true, false, 5), PeerReach::Punching);
        assert_eq!(classify_reach(true, false, 29), PeerReach::Punching);
        // Punch outstanding past the window with no handshake → unreachable (likely symmetric).
        assert_eq!(classify_reach(true, false, 30), PeerReach::Unreachable);
        assert_eq!(classify_reach(true, false, 120), PeerReach::Unreachable);
    }
}
