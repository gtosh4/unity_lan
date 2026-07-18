//! Peer-to-peer control channel between meshed engines (`docs/gossip-refresh.md`).
//!
//! A tiny **typed, versioned** request/response ridden *inside* the WireGuard tunnel — so the
//! transport is already mutually authenticated and reachable only by co-members (a stranger's
//! packets never clear WG crypto-routing). The envelope is deliberately extensible: a new message
//! type is an added variant, not a new socket/handshake, and an unknown type maps to
//! [`RespBody::Unsupported`] so mixed-version meshes interoperate (the caller falls back to the
//! coordinator). Scope is fixed, though — it carries only what is valid between already-meshed,
//! mutually-authorized peers, and payloads are self-verifying (checked against the pinned anchor)
//! or purely advisory. Anything needing ACL authority over an *unmet* peer stays on the coordinator.

use serde::{Deserialize, Serialize};

use crate::api::GuildAttestation;

/// UDP port the engine's P2P service listens on, bound to the device's mesh `/32` (distinct from the
/// WireGuard listen port, which lives on the physical interface).
pub const P2P_PORT: u16 = 51830;

/// Upper bound on a P2P datagram we'll read/emit — attestations are small; this just caps a peer's
/// influence on our buffers.
pub const P2P_MAX_DATAGRAM: usize = 16 * 1024;

/// A P2P request envelope. `proto` is [`crate::PROTOCOL_VERSION`] (coarse breaks); `body` is the
/// typed, extensible request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2pRequest {
    pub proto: u32,
    pub body: ReqBody,
}

/// The request payload. Internally tagged (`{"type":"…"}`) so `#[serde(other)]` can map any tag this
/// build doesn't know to [`ReqBody::Unknown`] — a newer peer's request degrades to an `Unsupported`
/// reply instead of a decode failure. Future data-carrying variants must be struct-style (internally
/// tagged enums can't hold a sequence-shaped newtype).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ReqBody {
    /// "Give me your own current coordinator-minted attestation(s)." The asker verifies the reply
    /// against its pinned anchor exactly as if the coordinator had served it.
    GetAttestations,
    /// A request type this build doesn't understand (a newer peer). Answered with `Unsupported`.
    #[serde(other)]
    Unknown,
}

/// A P2P response envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2pResponse {
    pub proto: u32,
    pub body: RespBody,
}

/// The response payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RespBody {
    /// The responder's own current attestations (one per guild it participates in).
    Attestations(Vec<GuildAttestation>),
    /// The responder doesn't support the requested type — the caller falls back to the coordinator.
    Unsupported,
}
