//! Control-socket protocol (design.md §3.2, §8): the newline-delimited JSON an unprivileged
//! frontend (CLI, iced GUI) exchanges with the privileged engine daemon.
//!
//! Pure wire types only — the engine owns the server, each frontend its own client transport
//! (Unix socket now, Windows named pipe later). Shared here so frontends need not depend on the
//! engine crate.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::api::{ManageOp, ManageResp, NetworkStatus};

#[derive(Serialize, Deserialize)]
pub enum ControlRequest {
    Status,
    Manage(ManageOp),
    /// Firewall port exposure — handled locally by the daemon (not forwarded to the coordinator).
    Expose(ExposeOp),
}

#[derive(Serialize, Deserialize)]
pub enum ControlResponse {
    Status(StatusReport),
    Manage(ManageResp),
    Expose(ExposeResp),
    Error(String),
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
}
