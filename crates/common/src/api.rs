//! Coordinator HTTP API DTOs (design/technical §4.1).
//!
//! A coordinator can serve multiple guilds, so `/register` returns a flat list of grants
//! spanning every guild the caller shares with the bot.

use serde::{Deserialize, Serialize};

/// `POST /register` request: the client's WireGuard public key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterReq {
    pub wg_pubkey: [u8; 32],
}

/// `POST /register` response: the trust anchor to pin + one grant per network the caller is in.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterResp {
    /// Ed25519 anchor bytes; the client pins this on first register.
    pub coord_pubkey: [u8; 32],
    pub grants: Vec<Grant>,
}

/// One membership: a signed attestation plus the human names needed to build its hostname.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    /// base64(`Signed<Attestation>`).
    pub attestation: String,
    /// Guild display name (the `<guild>` DNS label source).
    pub guild_name: String,
    /// Network display name (the `<network>` DNS label; admin-chosen, defaults to role name).
    pub network_name: String,
}
