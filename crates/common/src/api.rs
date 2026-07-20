//! Coordinator HTTP API DTOs (design/technical §4.1).
//!
//! Model B: a device has one IP regardless of how many networks it holds, so `/register`
//! returns a single self-`grant` (the device's own attestation + naming) plus `seeds` — the
//! co-members to peer with (anyone sharing ≥1 network). `/refresh` uses the same shapes.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

fn default_true() -> bool {
    true
}

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
    /// Long-poll ETag: the last `version` the client saw. When it equals the coordinator's
    /// current version the request is **held** until membership changes or the hold elapses.
    /// `None` (first register / a stale value) returns immediately.
    #[serde(default)]
    pub since: Option<u64>,
    /// Networks (role@guild) this device has locally opted out of peering on. The client is the
    /// source of truth (so opt-out works even when the coordinator is unreachable); the
    /// coordinator mirrors it here — excluding these from the device's presence/grant/seeds.
    #[serde(default)]
    pub disabled_networks: Vec<NetworkRef>,
    /// Peer-observed endpoints: for each current WG peer, the `ip:port` its packets arrive from
    /// (that peer's reflexive NAT mapping as *we* see it). Reported so the coordinator can hand
    /// two NAT'd co-members each other's reflexive address to hole-punch (§7.2). Empty when we
    /// have no peers or the backend can't report endpoints.
    #[serde(default)]
    pub observed: Vec<ObservedEndpoint>,
    /// Re-key supersede: when this device replaces one whose WG key it just rotated, the old
    /// device's bearer token (still held by the client). The coordinator authenticates ownership
    /// by it and retires the old pubkey immediately (frees its IP, evicts its presence) instead of
    /// waiting for the reaper. `None` in the common case.
    #[serde(default)]
    pub supersede: Option<String>,
    /// The device has locally **disconnected** (paused the mesh): keep the coordinator session
    /// (so reconnect is instant) but withdraw the device from every co-member's seed list, so
    /// peers prune it and see it as offline. Distinct from `disabled_networks` (a per-network
    /// opt-out): pausing withdraws presence globally while still returning the caller's own grant
    /// (its IP) and seeds, so the client can re-mesh the instant it reconnects.
    #[serde(default)]
    pub paused: bool,
    /// This device offers itself as a **ciphertext relay** (§7.2, M5.4): it runs an embedded TURN
    /// server so co-members whose hole punch fails (symmetric NAT / CGNAT / UDP-blocked) can reach
    /// each other through it. Set only when the device is directly dialable *and* the owner opted
    /// in (`relay = true`). `relay_addr` + `relay_secret` accompany it.
    #[serde(default)]
    pub relay_capable: bool,
    /// The dialable `ip:port` of this device's embedded TURN server (distinct from the WG
    /// `endpoint` — boringtun owns the WG port, so TURN listens separately). Present iff
    /// `relay_capable`.
    #[serde(default)]
    pub relay_addr: Option<SocketAddr>,
    /// The HMAC secret this relay's TURN server validates credentials against, shared with the
    /// coordinator so it can mint short-lived TURN credentials for authorized clients (the coturn
    /// `use-auth-secret` / TURN REST pattern). Present iff `relay_capable`. The coordinator is the
    /// trust anchor, so sharing it here (over TLS in prod) is within the existing trust boundary.
    #[serde(default)]
    pub relay_secret: Option<String>,
    /// Pubkeys of current peers this device **cannot reach directly** — its hole punch to each
    /// went `Unreachable` (§7.2). The coordinator matches a relay for each such pair and returns it
    /// in the peer's [`Seed::relay`]. Empty in the common (directly-reachable) case.
    #[serde(default)]
    pub need_relay: Vec<[u8; 32]>,
    /// TURN relayed addresses this device has allocated to reach specific peers (§7.2, M5.4). TURN
    /// assigns each relayed address at allocation time, so the coordinator collects ours and hands
    /// it to the peer as [`RelayInfo::peer_relayed`] — the address it sends to, to reach us. Empty
    /// unless we're relaying.
    #[serde(default)]
    pub relay_allocated: Vec<RelayAllocation>,
    /// ICE session offers (§7.2, M5.5): for each peer this device is reaching via a side-socket ICE
    /// agent, its ufrag/pwd + gathered candidates. The coordinator relays each to the named peer as
    /// its [`Seed::ice`] (never running ICE itself, so it stays off the data path). Empty unless the
    /// userspace ICE path is active for some peer.
    #[serde(default)]
    pub ice: Vec<IceEndpoint>,
    /// Always peer with the caller's **own other devices** (same Discord user), even when they
    /// share no enabled network — so a user's devices stay mutually reachable regardless of network
    /// membership. The client is the source of truth (persisted, GUI-toggleable); it defaults to
    /// `true` (enabled) so an omitted field — an older client, or one that never disabled it — still
    /// gets own-device peering. Withdrawing it (`false`) evicts this device from its siblings' seeds
    /// and drops them from its own.
    #[serde(default = "default_true")]
    pub peer_own_devices: bool,
    /// Highest wire protocol version this client speaks ([`crate::PROTOCOL_VERSION`]) — the ceiling
    /// of the range it offers. `0` from a pre-versioning client, which is served without
    /// negotiation. See [`crate::negotiate_proto`].
    #[serde(default)]
    pub proto: u32,
    /// Lowest wire protocol version this client still speaks ([`crate::MIN_PROTOCOL_VERSION`]) — the
    /// floor of that range. `0` from a client that predates range negotiation and therefore speaks
    /// exactly [`proto`](Self::proto); the coordinator treats its ceiling as its floor.
    #[serde(default)]
    pub proto_min: u32,
    /// Capability flags this client implements ([`crate::CAPABILITIES`]). The coordinator gates
    /// optional behavior on these rather than on [`proto`](Self::proto), so a new feature ships
    /// without a protocol bump. Empty from a client that predates capabilities — infer from `proto`.
    #[serde(default)]
    pub caps: Vec<String>,
    /// This client's release version (semver, [`crate::VERSION`]). The coordinator ignores it today;
    /// it's here so a future coordinator could tailor the update offer per client version. Empty from
    /// a pre-versioning client.
    #[serde(default)]
    pub client_version: String,
    /// Delta sync: the peers this client currently holds, each with the opaque `rev` the coordinator
    /// last minted for that peer's seed ([`Seed::rev`]). The coordinator then returns only seeds that
    /// are **new or changed** (`rev` differs), plus [`RegisterResp::removed`], instead of the full
    /// set — collapsing a membership herd from O(peers)·O(clients) to O(changes). Empty — an older
    /// client, first contact, or one forcing an attestation refresh — requests a **full** snapshot.
    #[serde(default)]
    pub held: Vec<HeldPeer>,
}

/// One peer a client currently holds, for delta sync ([`RegisterReq::held`]): its pubkey and the
/// opaque per-seed revision the coordinator last minted for it ([`Seed::rev`]). The client treats
/// `rev` as opaque — it only ever echoes back the value the coordinator gave it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeldPeer {
    pub pubkey: [u8; 32],
    pub rev: u64,
}

/// ICE session parameters for one (owner → peer) pair (§7.2, M5.5): the owner's short ICE
/// credentials (ufrag/pwd) and its gathered candidates as `webrtc-ice` `Candidate::marshal()`
/// strings. Relayed by the coordinator over the long-poll — it never runs ICE — so the data path
/// stays peer-to-peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceParams {
    pub ufrag: String,
    pub pwd: String,
    pub candidates: Vec<String>,
}

/// "For peer `peer`, here are my ICE session params." Reported in [`RegisterReq::ice`]; the
/// coordinator hands `params` to `peer` as its [`Seed::ice`] so both sides run connectivity checks
/// (the controlling side, min-pubkey, dials; the other accepts).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceEndpoint {
    pub peer: [u8; 32],
    pub params: IceParams,
}

/// "To reach `peer`, I allocated the TURN relayed address `relayed`." Reported so the coordinator
/// can hand `relayed` to `peer` as the address it sends to (the relayed-candidate exchange).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAllocation {
    pub peer: [u8; 32],
    pub relayed: SocketAddr,
}

/// Everything a stuck peer needs to reach a co-member through a relay's TURN server (§7.2, M5.4).
/// Minted by the coordinator (off the data path) for one (caller, peer) pair; the credential is a
/// short-lived HMAC over `username` keyed by the relay's `relay_secret`, so the relay's TURN server
/// authorizes the allocation without the coordinator ever carrying traffic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayInfo {
    /// The relay's TURN server `ip:port` (its `relay_addr`).
    pub turn_addr: SocketAddr,
    /// TURN long-term-credential username: the bare `"<unix_expiry>"` the webrtc-rs handler parses.
    /// The expiry bounds credential lifetime; the relay's server rejects it past that.
    pub username: String,
    /// TURN credential: base64(HMAC-SHA1(relay_secret, username)). Used as the long-term-credential
    /// password when allocating on the relay.
    pub credential: String,
    /// TURN realm the relay's server presents (the relay's identity).
    pub realm: String,
    /// The peer's own TURN relayed address on this same relay — the address we send to, to reach
    /// them. `None` until the peer has allocated and reported it (the coordinator fills it on a
    /// later refresh); until then we allocate + listen but can't yet forward (a ~2-round converge).
    #[serde(default)]
    pub peer_relayed: Option<SocketAddr>,
}

/// "I saw device `pubkey` sending from `endpoint`." A peer's reflexive address as observed across
/// an established tunnel — the punch target for co-members that can't dial it directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedEndpoint {
    pub pubkey: [u8; 32],
    pub endpoint: SocketAddr,
}

/// A reference to a network by its (guild, role) identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRef {
    pub guild_id: u64,
    pub role_id: u64,
}

/// One guild's trust anchor: its per-guild Ed25519 signing key (design.md §3.1) plus that key's
/// rotation chain. The client pins each guild's key independently (TOFU on first contact) and
/// verifies a peer's attestation against the anchor for the guild the attestation is scoped to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuildAnchor {
    pub guild_id: u64,
    /// Ed25519 anchor bytes for this guild; the client pins it on first sight of the guild.
    pub pubkey: [u8; 32],
    /// Trust-anchor rotation certs (base64 `Signed<RotationCert>`), oldest→newest, for this guild's
    /// key. A client whose pinned anchor differs from `pubkey` walks these to re-pin without manual
    /// intervention (design.md §9). Empty until this guild's key has been rotated at least once.
    #[serde(default)]
    pub rotation_chain: Vec<String>,
}

/// `POST /register` or `/refresh` response.
///
/// Every field is `#[serde(default)]`, so [`Default`] is exactly what a caller gets from decoding
/// `{}` — an empty response. Handy for building one field-by-field (`RegisterResp { seeds, ..Default::default() }`).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RegisterResp {
    /// One trust anchor per guild referenced anywhere in this response (the caller's own guilds and
    /// every peer's). The client pins each independently and re-pins via its `rotation_chain`.
    #[serde(default)]
    pub anchors: Vec<GuildAnchor>,
    /// The caller's own device grant; `None` if they hold no networks.
    #[serde(default)]
    pub grant: Option<Grant>,
    /// This device's bearer token for control mutations; the client persists it.
    #[serde(default)]
    pub device_token: Option<String>,
    /// Co-members (anyone sharing ≥1 network) to peer with — bootstrap for the mesh.
    #[serde(default)]
    pub seeds: Vec<Seed>,
    /// Membership version (ETag). The client echoes it as `since` on the next long-poll.
    #[serde(default)]
    pub version: u64,
    /// Every network the caller's roles grant (role@guild), with whether this device is
    /// participating — the source for the GUI's per-network peering toggle. Includes disabled
    /// ones (so they can be re-enabled); disabled networks are excluded from `grant`/`seeds`.
    #[serde(default)]
    pub networks: Vec<NetworkStatus>,
    /// The UDP port of the coordinator-hosted STUN Binding responder (§7.2, M5.5), if configured —
    /// the ICE agent's server-reflexive fallback when no relay co-member is online to STUN. `None`
    /// disables the fallback (clients rely on relay-node STUN only).
    ///
    /// Only the port: the responder always lives on the coordinator's own host (STUN is UDP, so no
    /// HTTP proxy fronts it), and behind NAT — a container bridge, or a cloud VM whose public IP is
    /// NAT'd to the interface rather than assigned to it — the coordinator can't know its own
    /// reachable address anyway. The client pairs this with the coordinator hostname it already
    /// dials, which is reachable by construction.
    #[serde(default)]
    pub stun_port: Option<u16>,
    /// The wire protocol version the coordinator **selected** for this exchange — the highest both
    /// sides speak, not the coordinator's own ceiling ([`crate::negotiate_proto`]). The client
    /// speaks this version back. `0` from a pre-versioning coordinator.
    #[serde(default)]
    pub proto: u32,
    /// The coordinator's own support window, `[proto_min, proto_max]`, independent of what it
    /// selected above. A client whose range sits outside this learns *which side* is out of date
    /// and can say so, rather than reporting a bare failure. `0` from a coordinator that predates
    /// range negotiation.
    #[serde(default)]
    pub proto_min: u32,
    /// See [`proto_min`](Self::proto_min).
    #[serde(default)]
    pub proto_max: u32,
    /// Capability flags the coordinator implements ([`crate::CAPABILITIES`]), so the client can
    /// likewise skip a feature the coordinator lacks. Empty from a pre-capabilities coordinator.
    #[serde(default)]
    pub caps: Vec<String>,
    /// The coordinator's own release version (semver, [`crate::VERSION`]) — the latest release the
    /// mesh should run, since coordinator and engine ship from one monorepo tag. The client compares
    /// it against its own [`crate::VERSION`] and surfaces "update available" to the GUI. Empty from a
    /// pre-versioning coordinator.
    #[serde(default)]
    pub server_version: String,
    /// A base64 [`crate::wire::Signed`]`<`[`crate::update::ReleaseManifest`]`>` — the signed
    /// auto-update manifest, iff the deployment configured one (opt-in). The client verifies it
    /// against its pinned anchor and offers the update when it names a strictly-newer version with an
    /// artifact for the client's platform. `None` when the deployment has no `[release]` configured.
    #[serde(default)]
    pub release: Option<String>,
    /// Delta sync: whether `seeds` is a **delta** to merge into the client's held set (add/replace
    /// the listed peers, drop [`removed`](Self::removed), keep the rest) rather than a **full**
    /// snapshot to replace it. `false` from a pre-delta coordinator, or when the client sent no
    /// [`RegisterReq::held`] (→ full).
    #[serde(default)]
    pub partial: bool,
    /// Delta sync: pubkeys the client should drop — peers it listed in [`RegisterReq::held`] that are
    /// no longer in its snapshot (left, revoked, reaped). Empty on a full response.
    #[serde(default)]
    pub removed: Vec<[u8; 32]>,
}

/// One of a device's networks (a role@guild) and whether this device peers on it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub guild_id: u64,
    pub role_id: u64,
    /// The network's Discord role display name.
    pub name: String,
    /// The guild's community label (admin-set slug, else guild name) for display, e.g. `<role> @ <guild>`.
    #[serde(default)]
    pub guild_name: String,
    pub enabled: bool,
}

/// `GET /oauth/pkce-config`: the public bits the engine needs to run the PKCE flow itself — the
/// Discord app's `client_id`, and whether the coordinator is in offline `fake` mode (so the engine
/// skips the real Discord round-trip and treats the callback `code` as the access token directly).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PkceConfigResp {
    pub client_id: String,
    pub fake: bool,
}

/// `POST /oauth/complete`: the engine, having done the PKCE exchange itself, hands the coordinator
/// the Discord access token to verify (`GET /users/@me`) and bind to this device's pubkey.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OauthCompleteReq {
    pub wg_pubkey: [u8; 32],
    pub access_token: String,
}

/// `POST /devices/manage`: an owner-scoped device operation, authenticated by a device token.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManageReq {
    /// The requesting device's bearer token (identifies the owner + authenticates).
    pub token: String,
    pub op: ManageOp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ManageOp {
    /// List the owner's devices.
    List,
    /// Rename the requesting device.
    Rename { new_name: String },
    /// Make one of the owner's devices (by name) primary.
    SetPrimary { device_name: String },
    /// Remove one of the owner's devices (by name).
    Remove { device_name: String },
}

/// Response to a manage request: the owner's devices after the op, plus a human message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManageResp {
    pub message: String,
    pub devices: Vec<DeviceInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_name: String,
    pub is_primary: bool,
    /// True for the device that made the request.
    pub is_self: bool,
}

/// One guild's attestation for a device, plus that guild's community label. A device that
/// participates in several guilds carries one of these per guild — the attestation is signed by
/// that guild's per-guild key and its `guild_id` names the guild whose anchor verifies it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuildAttestation {
    /// base64(`Signed<Attestation>`), signed by the guild's per-guild key.
    pub attestation: String,
    /// Community slug of that guild (admin-chosen, defaults to guild name). No longer part of the
    /// hostname (see `Attestation::hostname`); surfaced as metadata — the CLI shows it, and it tags
    /// shared networks (`SharedNetwork`).
    pub community_name: String,
    /// Which wire layout `attestation` was signed in
    /// ([`crate::attestation::ATTESTATION_SCHEMA_V1`]). The blob itself is postcard — positional, so
    /// a reader must be told the layout rather than infer it — but *this* envelope is JSON, so the
    /// hint can be added compatibly: absent means `0`, the original layout, which is exactly what a
    /// pre-hint sender emits. That asymmetry is the whole trick; see the constant's docs.
    #[serde(default)]
    pub att_schema: u32,
}

/// A network (ACL role) a peer shares with the caller. A peer met across two of the coordinator's
/// guilds is one device/one IP (Model B), so the guild is carried per shared network rather than in
/// the hostname.
///
/// **`(guild_id, role_id)` is the identity; `name`/`community` are display only.** Both labels are
/// user-chosen and mutable — two guilds may each have an `Engineering`, and either can be renamed —
/// so anything that decides access (firewall scoping in particular) keys on the snowflakes and
/// treats the strings as presentation.
///
/// The ids are `#[serde(default)]` because they were added after the labels: a coordinator that
/// predates them sends neither, and both arrive `0`. Zero is therefore *not* an identity — it means
/// "this coordinator didn't say" — and a network without ids cannot be used as an expose scope at
/// all (see `PeerSets` in the engine). Fail closed: the alternative, treating `0` as a real id,
/// would collapse every such network into one bucket and cross-admit all of them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedNetwork {
    /// Role display name (the ACL group). Display only — see the type docs.
    pub name: String,
    /// Community slug of the guild this role belongs to. Display only — see the type docs.
    pub community: String,
    /// The guild this role lives in. `0` when the coordinator predates this field.
    #[serde(default)]
    pub guild_id: u64,
    /// The Discord role backing this network. `0` when the coordinator predates this field.
    #[serde(default)]
    pub role_id: u64,
}

impl SharedNetwork {
    /// The identity pair, or `None` when the coordinator didn't send one — in which case this
    /// network can be displayed but never scoped to.
    pub fn id(&self) -> Option<(u64, u64)> {
        (self.guild_id != 0 && self.role_id != 0).then_some((self.guild_id, self.role_id))
    }
}

/// The caller's own device: its signed attestation(s) + the names to build its hostname(s).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    /// One attestation per guild this device participates in (design.md §3.1). Each is signed by
    /// that guild's per-guild key; the device gets a hostname within each guild's community.
    pub attestations: Vec<GuildAttestation>,
    /// Network display names this device belongs to (ACL groups; for status display).
    pub networks: Vec<String>,
}

/// A co-member to peer with: their signed attestation(s) (pubkey + wg_ip) + last-known endpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Seed {
    /// One attestation per guild this peer **shares with the caller**, each signed by that guild's
    /// per-guild key. The client admits the peer once any one verifies against the matching pinned
    /// guild anchor (design.md §4.1/§4.3).
    pub attestations: Vec<GuildAttestation>,
    /// The co-member's last-reported (directly dialable) endpoint (may be stale/absent).
    pub endpoint: Option<SocketAddr>,
    /// Hole-punch target: this peer's reflexive `ip:port`, set only when neither we nor the peer
    /// is directly dialable. The client uses it as the peer endpoint; both sides handshake at once
    /// (their long-polls wake on the same version bump) to punch through their NATs (§7.2).
    #[serde(default)]
    pub punch: Option<SocketAddr>,
    /// The networks this peer shares with the caller, each tagged with its community — lets the
    /// client scope `expose --net <role>` to just this network's peers, and lets the GUI show which
    /// server each shared network came from.
    #[serde(default)]
    pub networks: Vec<SharedNetwork>,
    /// Relay reservation for reaching this peer when a direct path and a hole punch both fail
    /// (§7.2, M5.4). Set by the coordinator when either side reported the other in `need_relay`;
    /// the client allocates on the named TURN server and routes this peer's WG traffic through it.
    /// `None` in the common case (direct or punchable).
    #[serde(default)]
    pub relay: Option<RelayInfo>,
    /// The peer's ICE session params for reaching this device (§7.2, M5.5): its ufrag/pwd +
    /// candidates, relayed by the coordinator from the peer's [`RegisterReq::ice`]. `None` until the
    /// peer offers ICE for us. The client feeds these into its ICE agent to run connectivity checks.
    #[serde(default)]
    pub ice: Option<IceParams>,
    /// Opaque revision of this seed's peering-relevant content (identity, endpoint, punch, networks,
    /// relay, ICE — but **not** attestation freshness, so an epoch roll doesn't churn it). The client
    /// stores it and echoes it in [`RegisterReq::held`]; the coordinator resends this seed only when
    /// it changes. `0` from a pre-delta coordinator (which never diffs, so it always sends full).
    #[serde(default)]
    pub rev: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // A pre-versioning peer's JSON omits the version fields; they must default (proto=0, empty
    // string) rather than fail to decode — the whole compatibility story rests on this.
    #[test]
    fn register_resp_decodes_without_version_fields() {
        // A minimal response (no version fields, no anchors) must decode with the fields defaulting
        // rather than failing — proto=0, empty server_version, no anchors.
        let old = r#"{}"#;
        let resp: RegisterResp = serde_json::from_str(old).unwrap();
        assert_eq!(resp.proto, 0);
        assert_eq!(resp.server_version, "");
        assert!(resp.anchors.is_empty());
    }

    #[test]
    fn register_req_decodes_without_version_fields() {
        let old =
            r#"{"wg_pubkey":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#;
        let req: RegisterReq = serde_json::from_str(old).unwrap();
        assert_eq!(req.proto, 0);
        assert_eq!(req.client_version, "");
        // No range and no capabilities: negotiation reads the absent floor as "exactly `proto`",
        // and an empty cap set as "infer from proto".
        assert_eq!(req.proto_min, 0);
        assert!(req.caps.is_empty());
    }

    // Golden fixtures for the previous protocol version — what a v4 peer actually puts on the wire.
    // The support window (current + 1 previous) is a promise these tests keep honest: if a change
    // makes a v4 message undecodable, the floor in `MIN_PROTOCOL_VERSION` is a lie and this fails.
    const V4_REGISTER_REQ: &str = r#"{
        "wg_pubkey":[1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        "device_name":"laptop",
        "endpoint":"203.0.113.7:51820",
        "since":42,
        "peer_own_devices":true,
        "proto":4,
        "client_version":"0.2.0",
        "held":[{"pubkey":[2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"rev":99}]
    }"#;

    const V4_REGISTER_RESP: &str = r#"{
        "version":42,
        "proto":4,
        "server_version":"0.2.0",
        "stun_port":3478,
        "partial":true
    }"#;

    #[test]
    fn v4_register_req_still_decodes() {
        let req: RegisterReq = serde_json::from_str(V4_REGISTER_REQ).unwrap();
        assert_eq!(req.proto, 4);
        assert_eq!(req.device_name, "laptop");
        assert_eq!(req.since, Some(42));
        assert_eq!(req.held.len(), 1);
        assert_eq!(req.held[0].rev, 99);
        // v4 predates both, so they must default rather than fail the decode.
        assert_eq!(req.proto_min, 0);
        assert!(req.caps.is_empty());
        // And a v4 client negotiates to v4 — inside the window, not rejected.
        assert_eq!(crate::negotiate_proto(req.proto_min, req.proto), Ok(4));
    }

    #[test]
    fn v4_register_resp_still_decodes() {
        let resp: RegisterResp = serde_json::from_str(V4_REGISTER_RESP).unwrap();
        assert_eq!(resp.proto, 4);
        assert_eq!(resp.version, 42);
        assert_eq!(resp.stun_port, Some(3478));
        assert!(resp.partial);
        assert_eq!(resp.proto_min, 0);
        assert_eq!(resp.proto_max, 0);
        assert!(resp.caps.is_empty());
    }

    #[test]
    fn register_resp_roundtrips_version_fields() {
        let resp = RegisterResp {
            version: 7,
            proto: crate::PROTOCOL_VERSION,
            server_version: crate::VERSION.to_string(),
            ..Default::default()
        };
        let round: RegisterResp =
            serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
        assert_eq!(round.proto, crate::PROTOCOL_VERSION);
        assert_eq!(round.server_version, crate::VERSION);
    }
}
