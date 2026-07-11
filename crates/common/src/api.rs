//! Coordinator HTTP API DTOs (design/technical §4.1).
//!
//! Model B: a device has one IP regardless of how many networks it holds, so `/register`
//! returns a single self-`grant` (the device's own attestation + naming) plus `seeds` — the
//! co-members to peer with (anyone sharing ≥1 network). `/refresh` uses the same shapes.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// `POST /register` or `/refresh` request: the client's WG public key, device name, endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterReq {
    pub wg_pubkey: [u8; 32],
    /// Owner-chosen label for this device (the `<device>` DNS label; sanitized by coordinator).
    #[serde(default)]
    pub device_name: String,
    /// One-time enrollment key, sent until this device's pubkey is bound to its owner. Ignored
    /// once enrolled (the coordinator resolves the owner from the pubkey binding).
    #[serde(default)]
    pub enrollment_key: Option<String>,
    /// The client's reachable `ip:port` for the WG listener (UPnP-mapped in production).
    #[serde(default)]
    pub endpoint: Option<SocketAddr>,
}

/// `POST /register` or `/refresh` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterResp {
    /// Ed25519 anchor bytes; the client pins this on first register.
    pub coord_pubkey: [u8; 32],
    /// The caller's own device grant; `None` if they hold no networks.
    #[serde(default)]
    pub grant: Option<Grant>,
    /// Co-members (anyone sharing ≥1 network) to peer with — bootstrap for the mesh.
    #[serde(default)]
    pub seeds: Vec<Seed>,
}

/// The caller's own device: its signed attestation + the names to build its hostname.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    /// base64(`Signed<Attestation>`) for this device.
    pub attestation: String,
    /// Community display name (the `<community>` DNS label; admin-chosen, defaults to guild name).
    pub community_name: String,
    /// Network display names this device belongs to (ACL groups; for status display).
    pub networks: Vec<String>,
}

/// A co-member to peer with: their signed attestation (pubkey + wg_ip) + last-known endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Seed {
    /// base64(`Signed<Attestation>`) for a co-member sharing ≥1 network.
    pub attestation: String,
    /// The co-member's last-reported endpoint (may be stale/absent).
    pub endpoint: Option<SocketAddr>,
}
