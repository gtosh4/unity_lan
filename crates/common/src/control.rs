//! Control-socket protocol (design.md §3.2, §8): the newline-delimited JSON an unprivileged
//! frontend (CLI, iced GUI) exchanges with the privileged engine daemon.
//!
//! Pure wire types only — the engine owns the server, each frontend its own client transport
//! (Unix socket now, Windows named pipe later). Shared here so frontends need not depend on the
//! engine crate.

use std::net::{Ipv4Addr, SocketAddr};

use serde::{Deserialize, Serialize};

use crate::api::{ManageOp, ManageResp};

#[derive(Serialize, Deserialize)]
pub enum ControlRequest {
    Status,
    Manage(ManageOp),
}

#[derive(Serialize, Deserialize)]
pub enum ControlResponse {
    Status(StatusReport),
    Manage(ManageResp),
    Error(String),
}

/// A snapshot of the daemon's live mesh state: this device plus the peers it has meshed with.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StatusReport {
    pub device: Option<DeviceStatus>,
    pub peers: Vec<PeerStatus>,
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
