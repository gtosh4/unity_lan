//! Axum HTTP API — the coordinator's whole surface.
//!
//! The shared spine lives here: [`AppState`] (everything a handler can reach), the [`router`] that
//! wires paths to handlers, and the error type they all return. Each route's logic lives in its own
//! module beside this one, because the parts differ enough in what they must get right that reading
//! one shouldn't mean scrolling past the others:
//!
//! | module | what it owns |
//! | --- | --- |
//! | [`register`] | `/register` + `/refresh`: negotiate, then answer now or park |
//! | [`snapshot`] | building one caller's grant + seeds — the hot path |
//! | [`auth`] | who is calling: device token, or possession proof when enrolling |
//! | [`nat`] | the peer-keyed reflexive/relay/ICE exchange (design.md §7.2) |
//! | [`devices`] | `/devices/manage`: owner-scoped device operations |
//! | [`login`] | OAuth PKCE hand-off and the public enrollment key |
//! | [`admin`] | the operator dashboard and Prometheus metrics |
//! | [`wake`] | parking a long-poll and waking it (herd or targeted) |
//! | [`ratelimit`] | per-source request limiting, and the proxy-corrected source IP |

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::http::StatusCode;
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use common::api::IceParams;
use common::update::ReleaseManifest;

mod admin;
mod auth;
mod devices;
mod login;
mod nat;
mod ratelimit;
mod register;
mod snapshot;
#[cfg(test)]
mod tests;
mod wake;

use admin::{admin_dashboard, admin_graph, admin_metrics, admin_stats};
use ratelimit::{rate_limit, RateLimitState};
pub use wake::{ParkSlots, Wakers};

use crate::oauth::OauthProvider;
use crate::presence::Presence;
use crate::roles::RoleSource;
use crate::signer::{GuildKeys, SignCache};
use crate::store::Store;
use crate::versions::Versions;

#[derive(Clone)]
pub struct AppState {
    /// Per-guild signing keys (design.md §3.1), created lazily on first contact with a guild.
    pub guild_keys: Arc<GuildKeys>,
    /// Reuses signed peer attestations across snapshots so a herd of long-pollers doesn't re-sign
    /// the same viewer-independent attestation once per caller (`N²` Ed25519 signs → `N`).
    pub sign_cache: Arc<SignCache>,
    /// Per-client targeted-wake registry. Pair-specific updates (a reflexive/relay/ICE report *about*
    /// one peer) wake only that peer, not the whole herd — the scoped `versions` are reserved for
    /// membership changes that concern every co-member of a guild.
    pub wakers: Arc<Wakers>,
    /// How long a `/register` long-poll is held before a renewal rebuild (≈ attestation TTL / 2, from
    /// config). A client refreshes its own attestation when its poll returns, so this bounds how stale
    /// a served attestation can get — it must stay below the attestation TTL.
    pub longpoll_hold_secs: u64,
    /// Hard concurrency ceiling plus one-active-poll-per-device admission.
    pub park_slots: Arc<ParkSlots>,
    pub roles: Arc<dyn RoleSource>,
    pub store: Arc<Store>,
    pub presence: Arc<Presence>,
    /// Per-scope membership counters behind the long-poll ETag. A change is scoped to the guild (or,
    /// for own-device peering, the user) it happened in, and a caller's wire `version` covers only
    /// its own scopes — so a membership change in one guild leaves clients of every other guild
    /// parked. `watch` has no lost wakeups.
    pub versions: Arc<Versions>,
    /// Interactive-login provider (Discord OAuth, or a fake in tests); `None` disables login.
    pub oauth: Option<Arc<dyn OauthProvider>>,
    /// Proxy hops whose `X-Forwarded-For` we trust, so `client_ip` can recover a caller's real
    /// address behind a reverse proxy. Shared with the rate-limit middleware; also used to record
    /// each device's coordinator-observed source IP for reflexive validation (see
    /// [`AppState::source_ip`]).
    pub trusted_proxies: Arc<Vec<ipnet::IpNet>>,
    /// Each device's source IP as the coordinator itself observed it on that device's own
    /// register/refresh (proxy-corrected via `client_ip`). A peer-reported reflexive for device `V`
    /// is only accepted if its IP matches `source_ip[V]` — a co-member can't then redirect `V`'s
    /// punch target to an arbitrary address it invents (§7.2). Last write wins; lost on restart.
    pub source_ip: Arc<Mutex<HashMap<[u8; 32], std::net::IpAddr>>>,
    /// Peer-observed reflexive endpoints: device pubkey → the `ip:port` a peer last saw it send
    /// from. Populated from `RegisterReq.observed`; read when handing a punch target to a NAT'd
    /// co-member (§7.2). Last observation wins; lost on restart (repopulated as peers refresh).
    pub reflexive: Arc<Mutex<HashMap<[u8; 32], std::net::SocketAddr>>>,
    /// Relay-capable devices: pubkey → its embedded TURN server address + HMAC secret. Populated
    /// from `RegisterReq.{relay_addr,relay_secret}` when a device advertises `relay_capable`, cleared
    /// when it stops. Read when matching a relay for a stuck pair (§7.2, M5.4). Last write wins; lost
    /// on restart (repopulated as relays refresh). A stale entry only means an allocation attempt
    /// fails and the client falls back — no correctness impact.
    pub relays: Arc<Mutex<HashMap<[u8; 32], RelayReg>>>,
    /// TURN relayed-address exchange (§7.2, M5.4): `(owner, peer)` → the relayed address `owner`
    /// allocated to reach `peer`. Populated from `RegisterReq.relay_allocated`; when building
    /// `peer`'s snapshot the coordinator hands back `(owner, peer)` as `peer`'s
    /// [`common::api::RelayInfo::peer_relayed`] for reaching `owner`. Last write wins; lost on restart.
    pub relay_allocs: Arc<Mutex<RelayAllocs>>,
    /// ICE candidate exchange (§7.2, M5.5): `(owner, peer)` → `owner`'s ICE session params (ufrag/pwd
    /// and candidates) for reaching `peer`. Populated from `RegisterReq.ice`; when building `peer`'s
    /// snapshot the coordinator hands `(owner, peer)` back as `peer`'s [`common::api::Seed::ice`] for
    /// reaching `owner`. Last write wins; lost on restart (repopulated as peers refresh).
    pub ice: Arc<Mutex<IceExchange>>,
    /// The UDP port of the coordinator-hosted STUN Binding responder (M5.5 ICE bootstrap fallback),
    /// advertised in every `RegisterResp`. `None` when no responder is configured.
    pub stun_port: Option<u16>,
    /// The parsed auto-update manifest, signed per-request with a guild key the caller holds and
    /// served in `RegisterResp.release` (design.md §3.1: no deployment-wide key, so the manifest is
    /// signed under a guild the client has pinned). Loaded from `[release]` at startup and swapped on
    /// SIGHUP (unix) so an admin can publish without a restart; `None` disables auto-update. A
    /// `RwLock` because reads are per-request but writes are rare; the read clones and never holds
    /// across an await.
    pub release: Arc<std::sync::RwLock<Option<ReleaseManifest>>>,
    /// The **pre-signed** release manifest blob (`[release] signed_blob`) — a base64
    /// [`common::wire::Signed`] the release pipeline produced offline with the dedicated release key.
    /// Served **verbatim** in `RegisterResp.release_signed` to every caller (no guild needed, and the
    /// coordinator never holds the release key — it can't and doesn't sign this). A client with a baked
    /// release pubkey verifies it against that key and ignores the guild-signed [`release`](Self::release).
    /// `None` disables the strong path (clients fall back to `release`). `RwLock` so SIGHUP can swap it.
    pub release_signed: Arc<std::sync::RwLock<Option<String>>>,
    /// Operator admin-surface bearer token (`[admin] token`). `None` → `/admin` and `/metrics` are
    /// disabled (return 404), so an instance exposes no admin surface until its operator opts in.
    /// Compared in constant time; never logged. Read-only counts only — no traffic path.
    pub admin_token: Option<String>,
    /// The deployment's X25519 enrollment secret. Its public half (`GET /enroll/pubkey`) lets a client
    /// build a DH proof it holds the WG private key behind the pubkey it enrolls, so a party who only
    /// learned that pubkey can't bind it under their own account. Persisted (`load_or_create_enroll_seed`).
    pub enroll_secret: [u8; 32],
    /// Require a valid possession proof on every enrolling register (`[enrollment] require_proof`).
    /// `false` = observe-only: admit a proof-less enrollment (logged + counted), still reject a
    /// malformed one. See [`crate::config::EnrollmentConfig`].
    pub require_enroll_proof: bool,
    /// Enrollments that presented a valid possession proof, process lifetime
    /// (`unitylan_enrollments_proven_total`).
    pub enroll_proven: Arc<std::sync::atomic::AtomicU64>,
    /// Enrollments admitted **without** a proof under observe-only mode, process lifetime
    /// (`unitylan_enrollments_unproven_total`) — the signal for when it's safe to flip `require_proof`.
    pub enroll_unproven: Arc<std::sync::atomic::AtomicU64>,
}

/// `(owner, peer)` → the relayed address `owner` allocated to reach `peer` (the relayed-candidate
/// exchange table in [`AppState::relay_allocs`]).
pub type RelayAllocs = HashMap<([u8; 32], [u8; 32]), std::net::SocketAddr>;

/// `(owner, peer)` → `owner`'s ICE session params for reaching `peer` (the candidate-exchange table
/// in [`AppState::ice`]).
pub type IceExchange = HashMap<([u8; 32], [u8; 32]), IceParams>;

/// A relay-capable device's TURN reachability, kept in [`AppState::relays`].
#[derive(Clone, Debug)]
pub struct RelayReg {
    /// The relay's dialable TURN server `ip:port`.
    pub addr: std::net::SocketAddr,
    /// The HMAC secret its TURN server validates minted credentials against.
    pub secret: String,
}

/// Drop per-device NAT side-table entries for devices no longer present, so these maps track live
/// membership instead of growing with every pubkey ever seen (they are otherwise only overwritten or
/// cleared on restart). Pair-keyed tables (`ice`, `relay_allocs`) drop an entry if *either* endpoint
/// is gone. Called from the presence reaper; a still-connected device repopulates its own entries on
/// its next refresh, so a rare over-prune is self-healing.
pub fn prune_nat_tables(st: &AppState, present: &std::collections::HashSet<[u8; 32]>) {
    st.source_ip
        .lock()
        .unwrap()
        .retain(|pk, _| present.contains(pk));
    st.reflexive
        .lock()
        .unwrap()
        .retain(|pk, _| present.contains(pk));
    st.relays
        .lock()
        .unwrap()
        .retain(|pk, _| present.contains(pk));
    st.relay_allocs
        .lock()
        .unwrap()
        .retain(|(owner, peer), _| present.contains(owner) && present.contains(peer));
    st.ice
        .lock()
        .unwrap()
        .retain(|(owner, peer), _| present.contains(owner) && present.contains(peer));
    // Same reasoning for the targeted-wake registry: an entry holding a wake for a device that never
    // returns would otherwise outlive it (that wake is deliberately kept across the gaps between a
    // live device's requests, so the ordinary sweep can't drop it).
    st.wakers.retain(present);
}

pub fn router(state: AppState) -> Router {
    let limiter = RateLimitState {
        limiter: Arc::new(Mutex::new(ratelimit::new_limiter(Instant::now()))),
        trusted_proxies: state.trusted_proxies.clone(),
    };
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // register and refresh share the same logic: issue grants, record presence, return seeds.
        .route("/register", post(register::register))
        .route("/refresh", post(register::register))
        .route("/devices/manage", post(devices::manage))
        // interactive login (engine-owned PKCE): pkce-config hands the engine the public client_id;
        // complete verifies the engine's access token and binds pubkey → user.
        .route("/oauth/pkce-config", get(login::oauth_pkce_config))
        .route("/oauth/complete", post(login::oauth_complete))
        // The public enrollment key: a client combines it with its WG private key to prove possession
        // when it first binds that pubkey. Unauthenticated — the value is public by design.
        .route("/enroll/pubkey", get(login::enroll_pubkey))
        // Operator admin surface. The `/admin` shell is unauthenticated (it holds no data); the
        // `/admin/stats` feed and `/metrics` are token-gated. All 404 when `[admin]` is unset.
        .route("/admin", get(admin_dashboard))
        .route("/admin/stats", get(admin_stats))
        .route("/admin/graph", get(admin_graph))
        .route("/metrics", get(admin_metrics))
        .with_state(state)
        // Rate-limit every route. The API is internet-facing and `/oauth/complete` is unauthenticated
        // yet makes an outbound Discord call per request; without a bound it's a DoS + Discord-REST
        // amplifier. Requires the connect-info make-service (see `main`) for the source IP.
        .layer(middleware::from_fn_with_state(limiter, rate_limit))
}
fn internal(e: anyhow::Error) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

#[derive(Debug)]
pub struct ApiError {
    /// `pub(super)` so each route module's tests can assert on the status it produced.
    pub(super) status: StatusCode,
    pub(super) message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

/// Fixtures shared by the route modules' unit tests.
#[cfg(test)]
mod testsupport {
    use common::api::RegisterReq;

    pub(super) fn addr(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    /// Build a request from the JSON a client of the given range would actually send — omitting a
    /// field entirely, as an older client does, rather than defaulting it in Rust.
    pub(super) fn req_speaking(range: &str) -> RegisterReq {
        let pk = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        serde_json::from_str(&format!(r#"{{"wg_pubkey":{pk},{range}}}"#)).unwrap()
    }
}
