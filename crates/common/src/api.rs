//! Coordinator HTTP API DTOs (design/technical §4.1).
//!
//! A coordinator can serve multiple guilds, so `/register` returns a flat list of grants
//! spanning every guild the caller shares with the bot, plus `seeds` — the co-members to
//! bootstrap a mesh from. `/refresh` uses the same request/response shapes.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// `POST /register` or `/refresh` request: the client's WG public key + self-reported endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterReq {
    pub wg_pubkey: [u8; 32],
    /// The client's reachable `ip:port` for the WG listener (UPnP-mapped in production).
    #[serde(default)]
    pub endpoint: Option<SocketAddr>,
}

/// `POST /register` or `/refresh` response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterResp {
    /// Ed25519 anchor bytes; the client pins this on first register.
    pub coord_pubkey: [u8; 32],
    /// One grant per registered network the caller holds.
    pub grants: Vec<Grant>,
    /// Co-members (across the caller's networks) to peer with — bootstrap for the mesh.
    #[serde(default)]
    pub seeds: Vec<Seed>,
}

/// One of the caller's own memberships: a signed attestation + the names to build its hostname.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    /// base64(`Signed<Attestation>`).
    pub attestation: String,
    /// Guild display name (the `<guild>` DNS label source).
    pub guild_name: String,
    /// Network display name (the `<network>` DNS label; admin-chosen, defaults to role name).
    pub network_name: String,
}

/// A co-member to peer with: their signed attestation (pubkey + wg_ip) + last-known endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Seed {
    /// base64(`Signed<Attestation>`) for the co-member in a shared network.
    pub attestation: String,
    /// The co-member's last-reported endpoint (may be stale/absent).
    pub endpoint: Option<SocketAddr>,
}
