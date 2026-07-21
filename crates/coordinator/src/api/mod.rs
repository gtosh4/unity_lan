//! Axum HTTP API. M1: `POST /register` issues signed attestations across all guilds the
//! caller shares with the bot, for every registered network whose role they hold.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::api::{
    DeviceInfo, Grant, GuildAnchor, GuildAttestation, IceParams, ManageOp, ManageReq, ManageResp,
    NetworkStatus, OauthCompleteReq, ObservedEndpoint, PkceConfigResp, RegisterReq, RegisterResp,
    RelayInfo, Seed, SharedNetwork,
};
use common::netid::sanitize_label;
use common::update::ReleaseManifest;

mod admin;
mod ratelimit;
mod wake;

use admin::{admin_dashboard, admin_graph, admin_metrics, admin_stats};
use ratelimit::{rate_limit, RateLimitState, RateLimiter};
pub use wake::Wakers;
use wake::{wait_park, wake_jitter, Woke};

use crate::oauth::OauthProvider;
use crate::presence::{MemberPresence, Presence};
use crate::roles::{MemberRoles, RoleSource};
use crate::signer::{GuildKeys, SignCache};
use crate::store::{match_device_by_name, DeviceMatch, Store};
use crate::versions::{Scope, Versions};

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
    /// each device's coordinator-observed source IP for reflexive validation (see [`source_ip`]).
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
    /// [`RelayInfo::peer_relayed`] for reaching `owner`. Last write wins; lost on restart.
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
    /// Operator admin-surface bearer token (`[admin] token`). `None` → `/admin` and `/metrics` are
    /// disabled (return 404), so an instance exposes no admin surface until its operator opts in.
    /// Compared in constant time; never logged. Read-only counts only — no traffic path.
    pub admin_token: Option<String>,
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

pub fn router(state: AppState) -> Router {
    let limiter = RateLimitState {
        limiter: Arc::new(Mutex::new(RateLimiter::new(Instant::now()))),
        trusted_proxies: state.trusted_proxies.clone(),
    };
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // register and refresh share the same logic: issue grants, record presence, return seeds.
        .route("/register", post(register))
        .route("/refresh", post(register))
        .route("/devices/manage", post(manage))
        // interactive login (engine-owned PKCE): pkce-config hands the engine the public client_id;
        // complete verifies the engine's access token and binds pubkey → user.
        .route("/oauth/pkce-config", get(oauth_pkce_config))
        .route("/oauth/complete", post(oauth_complete))
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

/// `POST /register` | `/refresh`: record presence + return the caller's grant and seeds.
///
/// Long-poll: build the snapshot once; if the client is already up to date (`since` == current
/// version) hold the request until membership changes or the hold elapses, then rebuild (fresh,
/// re-signed attestations — the renewal path). `since = None`/stale returns immediately.
async fn register(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<RegisterReq>,
) -> Result<Json<RegisterResp>, ApiError> {
    // Negotiate before doing any work: a client we can't speak to should cost us a range check, not
    // a snapshot build (and its Discord fan-out). Rejecting here is the whole point of the version —
    // serving a snapshot a client will misread is worse than telling it to upgrade.
    negotiate(&req)?;
    // The caller's real source IP (proxy-corrected), recorded so a peer-reported reflexive for this
    // device can be checked against where the device itself actually connects from.
    let caller_ip = ratelimit::client_ip(peer.ip(), &headers, &st.trusted_proxies);
    // Subscribe to our targeted-wake channel *before* building, so a pair-specific update that
    // targets us while we build (or decide to park) isn't lost.
    let mut personal = st.wakers.subscribe(req.wg_pubkey);
    let built = build_snapshot(&st, &req, caller_ip).await?;
    // Park only when the client is up to date *and* its own request changed nothing. A request that
    // reports data (reflexive/relay/ICE) returns immediately so the client can continue its report
    // loop — exactly as the old global bump made it — but now without waking the herd; the affected
    // peer is woken by a targeted wake instead.
    if !built.caller_changed && req.since == Some(built.resp.version) {
        // Free the snapshot *before* parking. We hold this request for minutes and rebuild on wake
        // anyway, so keeping its `seeds` alive would pin one full peer list per parked client —
        // O(clients × peers) bytes across the deployment, for data we already decided not to send.
        // Measured on a 3000-device guild: 8.3 GB parked before this drop, 82 MB after.
        let Built { resp, scopes, .. } = built;
        let version = resp.version;
        drop(resp);
        let woke = wait_park(&st, &scopes, version, &mut personal).await;
        // Jitter only a herd wake — a membership bump released every parked client at once, so
        // stagger the rebuilds to flatten the fan-in. A targeted personal wake is a single client
        // (no fan-in), and a hold-elapsed renewal already spreads over each client's own clock.
        if matches!(woke, Woke::Herd) {
            tokio::time::sleep(wake_jitter(&req.wg_pubkey)).await;
        }
        return Ok(Json(build_snapshot(&st, &req, caller_ip).await?.resp));
    }
    Ok(Json(built.resp))
}

/// Reconcile the client's advertised protocol range with ours, returning the version to speak.
///
/// A non-overlapping range is a `426 Upgrade Required` naming both ranges and which side is stale —
/// the operator needs to know *what to upgrade*, and a bare "version mismatch" doesn't say. This is
/// the only place a request is refused on protocol grounds; everything downstream can then assume a
/// version it understands.
fn negotiate(req: &RegisterReq) -> Result<u32, ApiError> {
    common::negotiate_proto(req.proto_min, req.proto).map_err(|why| {
        let advice = match why {
            common::ProtoReject::PeerTooOld => "the client is too old; update it",
            common::ProtoReject::PeerTooNew => "the coordinator is too old; update it",
        };
        tracing::warn!(
            client_proto = req.proto,
            client_proto_min = req.proto_min,
            server_proto = common::PROTOCOL_VERSION,
            server_proto_min = common::MIN_PROTOCOL_VERSION,
            "rejecting client on protocol version: {advice}"
        );
        // Report the floor we actually negotiated against: a client that sent none speaks exactly
        // `proto`, and printing the raw `0` would read as "speaks 0..=3" — which is not what we
        // decided, and not something an operator can act on.
        let client_min = if req.proto_min == 0 {
            req.proto
        } else {
            req.proto_min
        };
        ApiError::new(
            StatusCode::UPGRADE_REQUIRED,
            format!(
                "wire protocol mismatch: client speaks {}..={}, coordinator speaks {}..={} — {advice}",
                client_min, req.proto, common::MIN_PROTOCOL_VERSION, common::PROTOCOL_VERSION
            ),
        )
    })
}

/// An opaque revision of a seed's **peering-relevant** content, for delta sync ([`Seed::rev`]).
/// Deliberately excludes the attestation blob: its `issued_at`/`expires_at` roll every epoch, and a
/// rev that churned on refresh would force a full resend each epoch (the renewal herd we're avoiding)
/// — attestation freshness is the client's own Option-A concern instead. The client treats the value
/// as opaque, so the hash need only be stable within one coordinator process.
fn seed_rev(
    mp: &MemberPresence,
    endpoint: Option<SocketAddr>,
    punch: Option<SocketAddr>,
    networks: &[SharedNetwork],
    relay: &Option<RelayInfo>,
    ice: &Option<IceParams>,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    // Serialize the peering-relevant fields to a canonical byte string (struct/vec order is stable)
    // and hash that — avoids requiring `Hash` on every wire type.
    let bytes = serde_json::to_vec(&(
        mp.pubkey,
        mp.ip.octets(),
        mp.is_primary,
        &mp.username,
        &mp.device_name,
        endpoint,
        punch,
        networks,
        relay,
        ice,
    ))
    .unwrap_or_default();
    bytes.hash(&mut h);
    h.finish()
}

/// What [`build_snapshot`] produced for one caller.
struct Built {
    resp: RegisterResp,
    /// `true` when the caller's own request changed something (membership or a pair table) — the
    /// signal for [`register`] to return now rather than park, so the client can continue its
    /// report loop.
    caller_changed: bool,
    /// The scopes whose membership this caller cares about: its own user scope (own-device peering)
    /// plus every guild it holds a network role in. Backs both the wire `version` and [`wait_park`].
    scopes: BTreeSet<Scope>,
}

/// Compute the caller's grant + seeds and record their presence. Bumps the **scoped** membership
/// versions for the guilds (and users) whose membership actually changed — waking only clients of
/// those scopes — and fires **targeted** wakes for peers named in the caller's pair-specific reports
/// (reflexive/relay/ICE). Re-signs all attestations with the current time (so a rebuild renews them).
async fn build_snapshot(
    st: &AppState,
    req: &RegisterReq,
    caller_ip: std::net::IpAddr,
) -> Result<Built, ApiError> {
    let (user_id, already_enrolled) = resolve_user(st, req).await?;
    // Record where this device connects from (as the coordinator sees it), so a peer's reflexive
    // report about it can be validated against its real source address (see `accepted_reflexives`).
    st.source_ip
        .lock()
        .unwrap()
        .insert(req.wg_pubkey, caller_ip);
    let now = common::now_unix();
    // Which attestation layout this client gets. Gated on the client *saying* it can read V2: the
    // blob is postcard, so a client handed a layout it doesn't know decodes neither its own grant
    // nor any peer — and cannot tell that's what happened. Absent capability → the original layout,
    // which every released client reads. See `common::caps::ATTESTATION_V2`.
    let att_schema = if req.caps.iter().any(|c| c == common::caps::ATTESTATION_V2) {
        common::attestation::ATTESTATION_SCHEMA_V2
    } else {
        common::attestation::ATTESTATION_SCHEMA_V1
    };
    let networks = st.store.all_networks().await.map_err(internal)?;
    // One IP + one name per device (keyed by pubkey), reused across every network it holds. The
    // request name only seeds these on first enrollment; thereafter `allocate_device` returns the
    // stored (possibly renamed / auto-suffixed) name, and we build the attestation/hostname from
    // *that* so DNS tracks renames and never advertises a duplicate label.
    let (ip, device_name) = st
        .store
        .allocate_device(
            st.guild_keys.wg_net(),
            &req.wg_pubkey,
            user_id,
            &sanitize_label(&req.device_name),
        )
        .await
        .map_err(internal)?;

    // Primary device: first-enrolled auto-becomes primary; reassigned via `/unitylan primary`.
    st.store
        .ensure_primary(user_id, &req.wg_pubkey)
        .await
        .map_err(internal)?;
    let is_primary = st
        .store
        .primary_pubkey(user_id)
        .await
        .map_err(internal)?
        .is_some_and(|p| p == req.wg_pubkey);

    // Cache per-guild member lookups so we hit the role source once per guild.
    let mut member_cache: HashMap<u64, Option<MemberRoles>> = HashMap::new();
    let mut held: Vec<(u64, u64)> = Vec::new(); // (guild, role) the caller holds
                                                // Scopes whose membership this request changed → bumped at the end, waking the clients of those
                                                // scopes only. A presence change in a guild is scoped to that guild; an own-device (`*_self`)
                                                // change crosses guilds, so it's scoped to the owning user instead.
    let mut changed: BTreeSet<Scope> = BTreeSet::new();
    // Peers named in this caller's pair-specific reports (reflexive/relay/ICE) — each is woken
    // individually instead of bumping a membership scope, so a NAT-traversal exchange doesn't wake
    // a whole guild for a change only the one target cares about.
    let mut wake_targets: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    // Re-key supersede (design.md §9): a device regenerating its WG key registers under a *new*
    // pubkey, orphaning the old one — its presence would linger (never self-evicted, since its
    // owner now refreshes under the new key) until the reaper ages it out. If the client still
    // holds the old device token it proves ownership and we retire the old device *now*: drop its
    // store row (frees the IP + stale DNS name) and evict its presence everywhere. Possession of
    // the old token is the authorization; we still require it resolve to the same owner so one
    // member can't retire another's device even with a leaked token.
    if let Some(old_token) = &req.supersede {
        if let Some((owner, old_pubkey)) = st
            .store
            .device_by_token(old_token)
            .await
            .map_err(internal)?
        {
            if should_supersede(owner, old_pubkey, user_id, req.wg_pubkey) {
                st.store
                    .remove_device(user_id, &old_pubkey)
                    .await
                    .map_err(internal)?;
                for (g, r) in st.presence.networks_of(&old_pubkey) {
                    if st.presence.evict(g, r, &old_pubkey) {
                        changed.insert(Scope::Guild(g));
                    }
                }
                // …and from the per-user own-device set, so a re-keyed device's siblings prune the
                // retired pubkey immediately rather than waiting for the reaper.
                if st.presence.evict_self(owner, &old_pubkey) {
                    changed.insert(Scope::User(owner));
                }
            }
        }
    }
    let mut network_names: Vec<String> = Vec::new();
    let mut community_cache: HashMap<u64, String> = HashMap::new();
    let mut username = format!("user-{user_id}"); // fallback until a role source gives a handle

    // Networks this device has opted out of peering on. The client is the source of truth and
    // sends its current set on every register/refresh, so this works even across coordinator
    // restarts and while the coordinator was unreachable.
    let optouts: std::collections::HashSet<(u64, u64)> = req
        .disabled_networks
        .iter()
        .map(|n| (n.guild_id, n.role_id))
        .collect();
    let mut networks_status: Vec<NetworkStatus> = Vec::new();

    for net in networks {
        let member = match member_cache.get(&net.guild_id) {
            Some(m) => m.clone(),
            None => {
                let m = st.roles.member(net.guild_id, user_id).await;
                member_cache.insert(net.guild_id, m.clone());
                m
            }
        };
        let Some(member) = member else {
            tracing::debug!(
                user = user_id,
                guild = net.guild_id,
                role = net.role_id,
                net = %net.name,
                "snapshot: skip network — caller not a member of its guild"
            );
            continue;
        };
        if !member.role_ids.contains(&net.role_id) {
            tracing::debug!(
                user = user_id,
                guild = net.guild_id,
                role = net.role_id,
                net = %net.name,
                held = ?member.role_ids,
                "snapshot: skip network — caller does not hold its role"
            );
            continue;
        }

        // The user holds this role. Record it for the toggle UI; a disabled network is listed but
        // contributes no presence / grant / seeds (so it doesn't peer, in either direction).
        let guild_label = match community_cache.get(&net.guild_id) {
            Some(l) => l.clone(),
            None => {
                let l = community_of(st, net.guild_id).await.map_err(internal)?;
                community_cache.insert(net.guild_id, l.clone());
                l
            }
        };
        // Resolve the name live from the role source so it tracks Discord role renames; fall back
        // to the snapshot captured at registration if the lookup fails.
        let name = st
            .roles
            .role_name(net.guild_id, net.role_id)
            .await
            .unwrap_or_else(|| net.name.clone());
        let enabled = !optouts.contains(&(net.guild_id, net.role_id));
        networks_status.push(NetworkStatus {
            guild_id: net.guild_id,
            role_id: net.role_id,
            name: name.clone(),
            guild_name: guild_label.clone(),
            enabled,
        });

        // Identity resolves from any held role — even a disabled one — so the device still gets a
        // grant (stable name/IP/hostname) and the client can render the toggle list. Otherwise a
        // network that is auto-disabled on discovery (secure default) would yield no grant, the
        // engine would treat us as holding no networks, and the toggle needed to *enable* it would
        // never appear: a chicken-and-egg lockout.
        // Chunk 2 (enrollment) wires the global handle; for now derive it from the nick.
        username = sanitize_label(&member.nick);

        // A disabled network is listed (above) but contributes no presence / grant-network / seeds
        // (so it doesn't peer, in either direction) until the user enables it.
        if !enabled {
            continue;
        }
        network_names.push(name);

        // Record the device as present in this network (for others' seeds) — unless it has locally
        // disconnected (`paused`), in which case we still build its grant + seeds (so it can
        // re-mesh instantly on reconnect) but advertise no presence, so co-members prune it.
        if !req.paused
            && st.presence.record(
                net.guild_id,
                net.role_id,
                MemberPresence {
                    pubkey: req.wg_pubkey,
                    ip,
                    user_id,
                    username: username.clone(),
                    device_name: device_name.clone(),
                    is_primary,
                    endpoint: req.endpoint,
                },
                req.client_version.clone(),
                now,
            )
        {
            changed.insert(Scope::Guild(net.guild_id));
        }
        held.push((net.guild_id, net.role_id));
    }

    // Self-eviction: drop our presence from any network we were recorded in but no longer hold
    // (role revoked) — or from *every* network while disconnected (`paused`). Peers pick this up
    // on their next (long-poll-woken) refresh and prune us.
    for (g, r) in st.presence.networks_of(&req.wg_pubkey) {
        if (req.paused || !held.contains(&(g, r))) && st.presence.evict(g, r, &req.wg_pubkey) {
            changed.insert(Scope::Guild(g));
        }
    }

    // Own-device peering: record this device in the per-user online set (independent of networks) so
    // its siblings can seed it even with no shared enabled network. Gated on the client opting in
    // (`peer_own_devices`, default on), not being paused, and holding an identity (≥1 role → a grant
    // is issued below; without one there's no anchor to attest a sibling under). Evict in every other
    // case so an opt-out / pause / role-loss withdraws this device from its siblings' seeds.
    let has_identity = !networks_status.is_empty();
    let self_changed = if req.peer_own_devices && !req.paused && has_identity {
        st.presence.record_self(
            user_id,
            MemberPresence {
                pubkey: req.wg_pubkey,
                ip,
                user_id,
                username: username.clone(),
                device_name: device_name.clone(),
                is_primary,
                endpoint: req.endpoint,
            },
            req.client_version.clone(),
            now,
        )
    } else {
        st.presence.evict_self(user_id, &req.wg_pubkey)
    };
    // Own-device peering ignores networks, so this wakes the owner's *other* devices wherever they
    // are — the user scope, not any guild.
    if self_changed {
        changed.insert(Scope::User(user_id));
    }

    // Every guild the caller holds a role in (enabled or not). Drives the self-grant attestations
    // and the response anchors; peers' shared guilds are a subset of this, so it covers them too.
    let grant_guilds: BTreeSet<u64> = networks_status.iter().map(|n| n.guild_id).collect();

    // Self-grant: one device attestation **per guild**, each signed by that guild's key (design.md
    // §3.1/§4.1). Issued whenever the caller holds ≥1 network role, even if every one is currently
    // disabled — the device still needs its identity/IP and the client needs the grant to surface
    // the toggle list. `None` only when the caller holds no network roles at all.
    let grant = if networks_status.is_empty() {
        None
    } else {
        let mut attestations = Vec::with_capacity(grant_guilds.len());
        for &g in &grant_guilds {
            let key = st.guild_keys.get(g).await.map_err(internal)?;
            let signed = key
                .signer
                .sign_attestation(
                    &crate::signer::AttIdentity {
                        user_id,
                        username: &username,
                        device_name: &device_name,
                        is_primary,
                        ip,
                        pubkey: req.wg_pubkey,
                    },
                    att_schema,
                )
                .map_err(internal)?;
            attestations.push(GuildAttestation {
                att_schema,
                attestation: signed.to_base64(),
                community_name: community_cache.get(&g).cloned().unwrap_or_default(),
            });
        }
        Some(Grant {
            attestations,
            networks: network_names.clone(),
        })
    };

    // Seeds: every other device sharing ≥1 network with the caller, deduplicated by pubkey but
    // accumulating the shared networks (name + community, so the client can scope `expose --net` per
    // network and show which server each came from). Third slot: the set of guilds this peer shares
    // with the caller (always a subset of the caller's held guilds). Each shared guild yields one
    // attestation, signed by that guild's key.
    let mut by_pubkey: HashMap<[u8; 32], (MemberPresence, Vec<SharedNetwork>, BTreeSet<u64>)> =
        HashMap::new();
    for ((guild_id, role_id), net_name) in held.iter().zip(network_names.iter()) {
        let net = SharedNetwork {
            name: net_name.clone(),
            community: community_cache.get(guild_id).cloned().unwrap_or_default(),
            // The identity clients scope on; the two strings above are display only.
            guild_id: *guild_id,
            role_id: *role_id,
        };
        for mp in st.presence.others_in(*guild_id, *role_id, &req.wg_pubkey) {
            let entry = by_pubkey
                .entry(mp.pubkey)
                .or_insert_with(|| (mp.clone(), Vec::new(), BTreeSet::new()));
            if !entry.1.contains(&net) {
                entry.1.push(net.clone());
            }
            entry.2.insert(*guild_id);
        }
    }
    // Own-device peering: fold in the caller's other online devices (same user) not already seeded
    // via a shared network. They carry no `SharedNetwork` (they share none) and are attested under
    // the caller's own guilds — same user → identical guild membership → the caller already pins each
    // anchor, so every attestation verifies. Guarded on the caller opting in *and* holding an identity
    // (`grant_guilds` non-empty), since each seed needs ≥1 guild-signed attestation or the client
    // rejects the whole batch. `or_insert_with` keeps a sibling already present via a shared network
    // (its narrower shared-guild set stands).
    if req.peer_own_devices && has_identity {
        for mp in st.presence.others_of_user(user_id, &req.wg_pubkey) {
            by_pubkey
                .entry(mp.pubkey)
                .or_insert_with(|| (mp, Vec::new(), grant_guilds.clone()));
        }
    }
    // Record peer-observed reflexive endpoints (for hole punching). Each entry says "I saw device
    // X arriving from ip:port" — X's NAT mapping seen from the outside. Accepted *only* for a pubkey
    // the caller actually meshes with (a co-member seed): you can only report a reflexive for a peer
    // you share a network with — and thus have a tunnel to observe. This bounds a spoofed endpoint to
    // the victim's own co-members (the network trust boundary), instead of letting any authenticated
    // member redirect any device's punch target to an attacker-chosen address. A first sighting or a
    // roam (address change) wakes that one observed peer (targeted) so it picks up the punch target.
    // The caller's co-members: every device it shares ≥1 network with. This is the trust boundary
    // for all peer-keyed exchange tables below — the caller may only publish reflexive/relay/ICE
    // state *about a peer it actually meshes with*. Without this gate an authenticated member could
    // inject entries for arbitrary pubkeys, growing the tables unbounded and forcing wakes for
    // arbitrary pubkeys.
    let comembers: std::collections::HashSet<[u8; 32]> = by_pubkey.keys().copied().collect();
    {
        // Lock order: source_ip before reflexive (the only site holding both).
        let src = st.source_ip.lock().unwrap();
        let mut refl = st.reflexive.lock().unwrap();
        for obs in accepted_reflexives(&req.observed, &comembers, &src) {
            if refl.get(&obs.pubkey) != Some(&obs.endpoint) {
                refl.insert(obs.pubkey, obs.endpoint);
                wake_targets.insert(obs.pubkey);
            }
        }
    }

    // Record / clear this device's relay capability: an opted-in, directly-dialable co-member that
    // runs an embedded TURN server for stuck pairs. Not a membership change, so it deliberately
    // doesn't bump the version (a new relay must not wake the whole herd — a stuck peer re-polls on
    // its own cadence and picks it up). Cleared when the device stops advertising.
    {
        let mut relays = st.relays.lock().unwrap();
        match (req.relay_capable, req.relay_addr, req.relay_secret.as_ref()) {
            (true, Some(addr), Some(secret)) => {
                relays.insert(
                    req.wg_pubkey,
                    RelayReg {
                        addr,
                        secret: secret.clone(),
                    },
                );
            }
            _ => {
                relays.remove(&req.wg_pubkey);
            }
        }
    }

    // Record this device's TURN relayed addresses (relayed-candidate exchange). A new/changed
    // relayed address wakes that one peer (targeted) so it learns it as its `peer_relayed` — the
    // second half of the ~2-round relay converge.
    {
        let mut allocs = st.relay_allocs.lock().unwrap();
        for a in &req.relay_allocated {
            // Only accept a relayed address for a peer the caller actually meshes with (mirrors the
            // reflexive gate) — otherwise the map grows unbounded.
            if !comembers.contains(&a.peer) {
                continue;
            }
            if allocs.get(&(req.wg_pubkey, a.peer)) != Some(&a.relayed) {
                allocs.insert((req.wg_pubkey, a.peer), a.relayed);
                wake_targets.insert(a.peer);
            }
        }
    }

    // Record this device's ICE session offers (candidate exchange, M5.5). A new/changed offer (fresh
    // candidates, or an ICE restart's new ufrag/pwd) wakes that one peer (targeted) so it picks up
    // the candidates as its `Seed::ice` and runs connectivity checks — turning ICE exchange into a
    // targeted ping-pong rather than a herd wake. The coordinator only relays; it never runs ICE.
    {
        let mut ice = st.ice.lock().unwrap();
        for e in &req.ice {
            // Same co-member gate as reflexive/relay: an ICE offer is only accepted for a peer the
            // caller shares a network with, so the map stays bounded and can't be used to force
            // wakes for arbitrary pubkeys.
            if !comembers.contains(&e.peer) {
                continue;
            }
            if ice.get(&(req.wg_pubkey, e.peer)) != Some(&e.params) {
                ice.insert((req.wg_pubkey, e.peer), e.params.clone());
                wake_targets.insert(e.peer);
            }
        }
    }

    // Relay candidates for the caller: co-members that advertise a TURN relay, captured with their
    // shared-with-caller network names before the seed loop consumes `by_pubkey`. A relay is used
    // for a peer only if it *also* shares a network with that peer (symmetric authorization) — and
    // both endpoints, building their own snapshots, pick the same min-pubkey relay from the same
    // set, so they meet on it.
    let relay_regs = st.relays.lock().unwrap().clone();
    let relay_candidates: Vec<([u8; 32], Vec<SharedNetwork>, RelayReg)> = by_pubkey
        .iter()
        .filter_map(|(pk, (_mp, nets, _c))| {
            relay_regs
                .get(pk)
                .map(|reg| (*pk, nets.clone(), reg.clone()))
        })
        .collect();
    let need_relay: std::collections::HashSet<[u8; 32]> = req.need_relay.iter().copied().collect();
    let relay_allocs = st.relay_allocs.lock().unwrap().clone();
    let ice_exchange = st.ice.lock().unwrap().clone();

    // Whether the caller itself is directly dialable (self-reported endpoint: UPnP / manual
    // forward). If so, a NAT'd peer just dials us and no punch is needed on either side.
    let caller_dialable = req.endpoint.is_some();
    let reflexive = st.reflexive.lock().unwrap().clone();
    // (pubkey, seed) pairs — the pubkey (carried inside each attestation, not a top-level Seed field)
    // is tracked here so the delta filter below can diff against the client's `held` set.
    let mut all: Vec<([u8; 32], Seed)> = Vec::new();
    for (_pubkey, (mp, networks, shared_guilds)) in by_pubkey {
        let punch = punch_target(
            caller_dialable,
            mp.endpoint,
            reflexive.get(&mp.pubkey).copied(),
        );
        // If we told the coordinator we can't reach this peer directly (punch went Unreachable),
        // hand back a relay we both share a network with, plus the peer's own relayed address on it
        // (once the peer has reported one) so we know where to send.
        let relay = if need_relay.contains(&mp.pubkey) {
            relay_target(&mp.pubkey, &networks, &relay_candidates, now).map(|mut info| {
                info.peer_relayed = relay_allocs.get(&(mp.pubkey, req.wg_pubkey)).copied();
                info
            })
        } else {
            None
        };
        // One attestation per guild this peer shares with the caller, each signed by that guild's
        // key. The client admits the peer once any one verifies against the matching pinned anchor.
        let peer_id = crate::signer::AttIdentity {
            user_id: mp.user_id,
            username: &mp.username,
            device_name: &mp.device_name,
            is_primary: mp.is_primary,
            ip: mp.ip,
            pubkey: mp.pubkey,
        };
        let mut attestations = Vec::with_capacity(shared_guilds.len());
        for &g in &shared_guilds {
            let blob = st
                .sign_cache
                .attestation(&st.guild_keys, g, &peer_id, now, att_schema)
                .await
                .map_err(internal)?;
            attestations.push(GuildAttestation {
                att_schema,
                attestation: blob.to_string(),
                community_name: community_cache.get(&g).cloned().unwrap_or_default(),
            });
        }
        // The peer's ICE offer for reaching us (if it has run ICE toward this caller): key is
        // (owner=peer, peer=caller). The client feeds it into its agent to run connectivity checks.
        let ice = ice_exchange.get(&(mp.pubkey, req.wg_pubkey)).cloned();
        let rev = seed_rev(&mp, mp.endpoint, punch, &networks, &relay, &ice);
        all.push((
            mp.pubkey,
            Seed {
                attestations,
                endpoint: mp.endpoint,
                punch,
                networks,
                relay,
                ice,
                rev,
            },
        ));
    }

    // Delta sync: if the client sent its held set (pubkey → last-seen rev), return only the seeds that
    // are new or whose rev changed, plus the pubkeys it should drop — collapsing a herd wake from
    // O(peers) per client to O(changes). An empty `held` (older client, first contact, or a client
    // forcing an attestation refresh) gets the full set.
    let (seeds, removed, partial) = if req.held.is_empty() {
        (
            all.into_iter().map(|(_, s)| s).collect::<Vec<_>>(),
            Vec::new(),
            false,
        )
    } else {
        let held: HashMap<[u8; 32], u64> = req.held.iter().map(|h| (h.pubkey, h.rev)).collect();
        let current: std::collections::HashSet<[u8; 32]> = all.iter().map(|(pk, _)| *pk).collect();
        let removed: Vec<[u8; 32]> = held
            .keys()
            .filter(|pk| !current.contains(*pk))
            .copied()
            .collect();
        let seeds: Vec<Seed> = all
            .into_iter()
            .filter(|(pk, s)| held.get(pk) != Some(&s.rev))
            .map(|(_, s)| s)
            .collect();
        (seeds, removed, true)
    };

    // Hand back the device's bearer token *only* on the register that first enrolls it — i.e. when
    // the pubkey was resolved via a secret (enrollment key / OAuth binding), not by naming an
    // already-enrolled pubkey. A WG public key is not a secret here (it rides in every co-member's
    // seed), so re-issuing the token to anyone who names a known pubkey would let a co-member pull
    // a victim's token and drive `/devices/manage` (rename/remove/set-primary) against them. The
    // client persists the token from this first delivery; refresh never needs it re-sent.
    let device_token = if already_enrolled {
        None
    } else {
        st.store
            .device_token(&req.wg_pubkey)
            .await
            .map_err(internal)?
    };

    // Bump each scope whose membership changed → wake every parked client *of that scope*. A guild's
    // co-members wake; an unrelated guild's clients stay parked and cost nothing.
    st.versions.bump_all(changed.iter().copied());
    // Fire targeted wakes for the peers named in this caller's pair-specific reports — each learns
    // its new reflexive/relay/ICE state on its own parked request, without a global herd wake.
    for t in &wake_targets {
        st.wakers.wake(t);
    }

    // The caller's own scopes: its user scope (own-device peering) plus every guild it holds a role
    // in. Its wire `version` aggregates exactly these, so nothing outside them can wake it. A
    // network registered in a guild the caller has no role in is therefore picked up on its next
    // renewal rather than instantly — that's an admin-rare event, unlike presence churn.
    let scopes: BTreeSet<Scope> = std::iter::once(Scope::User(user_id))
        .chain(grant_guilds.iter().map(|&g| Scope::Guild(g)))
        .collect();
    let version = st.versions.aggregate(&scopes);

    tracing::debug!(
        user = user_id,
        since = ?req.since,
        version,
        scopes = ?scopes,
        held_networks = networks_status.len(),
        networks = ?networks_status
            .iter()
            .map(|n| format!("{}({}/{})={}", n.name, n.guild_id, n.role_id, n.enabled))
            .collect::<Vec<_>>(),
        grant = if networks_status.is_empty() { "none" } else { "issued" },
        enabled_networks = held.len(),
        "snapshot built"
    );

    // One trust anchor per guild the caller participates in (covers every peer's guild too, since
    // shared guilds are a subset). The client pins each independently and re-pins via its chain.
    let mut anchors = Vec::with_capacity(grant_guilds.len());
    for &g in &grant_guilds {
        let key = st.guild_keys.get(g).await.map_err(internal)?;
        anchors.push(GuildAnchor {
            guild_id: g,
            pubkey: key.signer.anchor_bytes(),
            rotation_chain: key.rotation_chain.clone(),
        });
    }

    // Auto-update manifest: signed on demand with a guild key the caller holds (the smallest
    // guild_id, deterministically) so the client verifies it against an anchor it has pinned
    // (design.md §3.1 — no deployment-wide key). Clone the manifest out before the await so the
    // RwLock guard isn't held across it.
    let manifest = st.release.read().unwrap().clone();
    let release = match (manifest, grant_guilds.iter().next()) {
        (Some(m), Some(&g)) => {
            let key = st.guild_keys.get(g).await.map_err(internal)?;
            Some(key.signer.sign_to_base64(&m).map_err(internal)?)
        }
        _ => None,
    };

    Ok(Built {
        caller_changed: !changed.is_empty() || !wake_targets.is_empty(),
        scopes,
        resp: RegisterResp {
            anchors,
            grant,
            device_token,
            seeds,
            version,
            networks: networks_status,
            stun_port: st.stun_port,
            // The version we *selected* for this client, not our ceiling. `register` already
            // rejected a non-overlapping range, so the fallback here is unreachable.
            proto: negotiate(req).unwrap_or(common::PROTOCOL_VERSION),
            proto_min: common::MIN_PROTOCOL_VERSION,
            proto_max: common::PROTOCOL_VERSION,
            caps: common::CAPABILITIES.iter().map(|c| c.to_string()).collect(),
            server_version: common::VERSION.to_string(),
            release,
            partial,
            removed,
        },
    })
}

/// `POST /devices/manage`: owner-scoped device ops authenticated by a device bearer token.
async fn manage(
    State(st): State<AppState>,
    Json(req): Json<ManageReq>,
) -> Result<Json<ManageResp>, ApiError> {
    let (user_id, self_pubkey) = st
        .store
        .device_by_token(&req.token)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid device token"))?;

    let message = match req.op {
        ManageOp::List => "ok".to_string(),
        ManageOp::Rename { new_name } => {
            let name = st
                .store
                .rename_device(user_id, &self_pubkey, &sanitize_label(&new_name))
                .await
                .map_err(internal)?;
            format!("renamed this device to {name}")
        }
        ManageOp::SetPrimary { device_name } => {
            let pk = find_device(&st, user_id, &device_name).await?;
            st.store.set_primary(user_id, &pk).await.map_err(internal)?;
            format!("primary set to {}", sanitize_label(&device_name))
        }
        ManageOp::Remove { device_name } => {
            let pk = find_device(&st, user_id, &device_name).await?;
            st.store
                .remove_device(user_id, &pk)
                .await
                .map_err(internal)?;
            // The store row is gone, but the device's presence would linger under its pubkey until
            // the reaper ages it out — long enough that a device logging out (un-enroll + re-key)
            // keeps showing up as a stale peer to everyone, including its own re-keyed self. Evict
            // it now and bump each affected guild so its parked long-pollers wake and prune it.
            let mut changed = BTreeSet::new();
            for (g, r) in st.presence.networks_of(&pk) {
                if st.presence.evict(g, r, &pk) {
                    changed.insert(Scope::Guild(g));
                }
            }
            // The device also leaves its owner's own-device set, which no guild covers.
            if st.presence.evict_self(user_id, &pk) {
                changed.insert(Scope::User(user_id));
            }
            st.versions.bump_all(changed);
            format!("removed {}", sanitize_label(&device_name))
        }
    };

    // Report the owner's devices after the op.
    let primary = st.store.primary_pubkey(user_id).await.map_err(internal)?;
    let devices = st
        .store
        .user_devices(user_id)
        .await
        .map_err(internal)?
        .into_iter()
        .map(|(pk, name)| DeviceInfo {
            device_name: name,
            is_primary: primary == Some(pk),
            is_self: pk == self_pubkey,
        })
        .collect();
    Ok(Json(ManageResp { message, devices }))
}

/// Resolve one of a user's devices by (sanitized) name to its pubkey; error if 0 or >1 match.
async fn find_device(st: &AppState, user_id: u64, name: &str) -> Result<[u8; 32], ApiError> {
    let want = sanitize_label(name);
    let devices = st.store.user_devices(user_id).await.map_err(internal)?;
    match match_device_by_name(&devices, &want) {
        DeviceMatch::One(pk) => Ok(pk),
        DeviceMatch::None => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("no device named '{want}'"),
        )),
        DeviceMatch::Many => Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("multiple devices named '{want}'; rename one first"),
        )),
    }
}

/// The community label for a guild: the admin-set slug, else the guild name.
async fn community_of(st: &AppState, guild_id: u64) -> anyhow::Result<String> {
    match st.store.community_slug(guild_id).await? {
        Some(s) => Ok(s),
        None => Ok(st.roles.guild_name(guild_id).await.unwrap_or_default()),
    }
}

/// Resolve the caller's user id, plus whether the device was **already enrolled** (resolved by its
/// pubkey binding alone). `device_owner` is checked first, so a `true` flag means the device row
/// already existed; `false` means this register is the one that binds the pubkey (via OAuth binding
/// or a one-time enrollment key) and freshly mints the device row. Callers use the flag to gate the
/// one-time `device_token` delivery — see `build_snapshot`.
async fn resolve_user(st: &AppState, req: &RegisterReq) -> Result<(u64, bool), ApiError> {
    if let Some(uid) = st
        .store
        .device_owner(&req.wg_pubkey)
        .await
        .map_err(internal)?
    {
        return Ok((uid, true));
    }
    if let Some(uid) = st
        .store
        .oauth_user(&req.wg_pubkey)
        .await
        .map_err(internal)?
    {
        return Ok((uid, false));
    }
    let Some(key) = req.enrollment_key.as_deref() else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "device not enrolled; log in (oauth) or provide an enrollment_key",
        ));
    };
    let uid = st
        .store
        .consume_enrollment_key(key, &req.wg_pubkey, common::now_unix())
        .await
        .map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, e.to_string()))?;
    Ok((uid, false))
}

/// `GET /oauth/pkce-config`: the public bits the engine needs to run the PKCE flow itself.
async fn oauth_pkce_config(State(st): State<AppState>) -> Result<Json<PkceConfigResp>, ApiError> {
    let oauth = st.oauth.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "interactive login not configured",
        )
    })?;
    Ok(Json(PkceConfigResp {
        client_id: oauth.client_id().to_string(),
        fake: oauth.is_fake(),
    }))
}

/// `POST /oauth/complete`: the engine finished the PKCE exchange and sends us the access token.
/// Verify it against Discord (`GET /users/@me`) and bind the resulting user to the device pubkey,
/// so the client's next register succeeds.
async fn oauth_complete(
    State(st): State<AppState>,
    Json(req): Json<OauthCompleteReq>,
) -> Result<StatusCode, ApiError> {
    let oauth = st.oauth.as_ref().ok_or_else(|| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "interactive login not configured",
        )
    })?;
    let user_id = oauth
        .verify(&req.access_token)
        .await
        .map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, format!("login failed: {e:#}")))?;
    st.store
        .bind_oauth(&req.wg_pubkey, user_id)
        .await
        .map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

fn internal(e: anyhow::Error) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// The hole-punch target to hand a caller for one peer (§7.2): the peer's reflexive address, but
/// only when *neither* side is directly dialable. If either the caller or the peer has a dialable
/// endpoint, that side is reached directly (via the seed `endpoint`) and no punch is needed.
fn punch_target(
    caller_dialable: bool,
    peer_endpoint: Option<std::net::SocketAddr>,
    peer_reflexive: Option<std::net::SocketAddr>,
) -> Option<std::net::SocketAddr> {
    if !caller_dialable && peer_endpoint.is_none() {
        peer_reflexive
    } else {
        None
    }
}

/// The relay to hand a caller for one `peer` it can't punch to (§7.2, M5.4). Picks the
/// lowest-pubkey candidate relay that shares a network with the peer (the caller already shares one
/// with every candidate — they're its co-members — and it is itself excluded, so a node never
/// relays for itself). Deterministic + symmetric: the peer, building its own snapshot from the same
/// candidate set, selects the same relay, so the pair meets on it. Returns freshly-minted TURN
/// credentials for that relay, or `None` if no third-party relay serves both.
fn relay_target(
    peer: &[u8; 32],
    peer_networks: &[SharedNetwork],
    candidates: &[([u8; 32], Vec<SharedNetwork>, RelayReg)],
    now: u64,
) -> Option<common::api::RelayInfo> {
    candidates
        .iter()
        .filter(|(pk, nets, _)| pk != peer && nets.iter().any(|n| peer_networks.contains(n)))
        .min_by_key(|(pk, _, _)| *pk)
        .map(|(_, _, reg)| {
            common::relay::issue_relay_creds(
                reg.addr,
                &reg.secret,
                now,
                common::RELAY_CRED_TTL_SECS,
            )
        })
}

/// Whether a re-key supersede request should retire the old device. The old device token proved
/// possession; we retire the pubkey it names iff it belongs to the *same* owner (a leaked token
/// can't retire another member's device) and it's a *different* key than the one now registering
/// (a steady-state register carrying its own current token is a no-op, not a self-retire).
fn should_supersede(
    token_owner: u64,
    old_pubkey: [u8; 32],
    caller_user: u64,
    caller_pubkey: [u8; 32],
) -> bool {
    token_owner == caller_user && old_pubkey != caller_pubkey
}

/// Peer-observed reflexives the caller may legitimately report. Two independent gates:
/// 1. **Co-membership** — you can only observe a peer's reflexive across a tunnel you share, so the
///    reported pubkey must be one of the caller's co-members (`comembers`).
/// 2. **Source-IP correlation** — the reported reflexive IP must equal the IP the coordinator itself
///    saw that peer connect from (`source_ip[pubkey]`, recorded on the peer's own register). A NAT'd
///    peer egresses from one address, so its coordinator source IP and the reflexive its peers
///    observe share that IP; a co-member that *invents* a reflexive can't make the victim's own
///    traffic appear to originate there, so a mismatched (attacker-chosen) address is dropped. This
///    is what stops a co-member redirecting a NAT'd peer's punch target to an arbitrary host (an
///    SSRF/DoS lever). The port may differ (symmetric NAT), so only the IP is correlated. A peer we
///    haven't seen register yet has no `source_ip` entry and its reports are held until it does.
fn accepted_reflexives<'a>(
    observed: &'a [ObservedEndpoint],
    comembers: &'a std::collections::HashSet<[u8; 32]>,
    source_ip: &'a HashMap<[u8; 32], std::net::IpAddr>,
) -> impl Iterator<Item = &'a ObservedEndpoint> {
    observed.iter().filter(move |o| {
        comembers.contains(&o.pubkey) && source_ip.get(&o.pubkey) == Some(&o.endpoint.ip())
    })
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
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

#[cfg(test)]
mod tests {
    use super::{
        accepted_reflexives, negotiate, punch_target, relay_target, should_supersede, RelayReg,
        StatusCode,
    };
    use common::api::{ObservedEndpoint, RegisterReq, SharedNetwork};

    fn addr(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
    }

    /// Build a request from the JSON a client of the given range would actually send — omitting a
    /// field entirely, as an older client does, rather than defaulting it in Rust.
    fn req_speaking(range: &str) -> RegisterReq {
        let pk = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
        serde_json::from_str(&format!(r#"{{"wg_pubkey":{pk},{range}}}"#)).unwrap()
    }

    #[test]
    fn negotiation_selects_the_shared_version() {
        let sel = negotiate(&req_speaking(r#""proto":5,"proto_min":4"#)).unwrap();
        assert_eq!(sel, common::PROTOCOL_VERSION);
        // A client capped below us is served at *its* ceiling, not ours.
        assert_eq!(
            negotiate(&req_speaking(r#""proto":4,"proto_min":4"#)).unwrap(),
            4
        );
    }

    #[test]
    fn stale_client_gets_426_naming_both_ranges() {
        let err = negotiate(&req_speaking(r#""proto":2,"proto_min":1"#)).unwrap_err();
        assert_eq!(err.status, StatusCode::UPGRADE_REQUIRED);
        // The message has to say what to upgrade — a bare "mismatch" leaves an operator stuck.
        assert!(err.message.contains("client is too old"), "{}", err.message);
        assert!(err.message.contains("1..=2"), "{}", err.message);
    }

    #[test]
    fn client_newer_than_coordinator_says_so() {
        let err = negotiate(&req_speaking(r#""proto":99,"proto_min":98"#)).unwrap_err();
        assert_eq!(err.status, StatusCode::UPGRADE_REQUIRED);
        assert!(
            err.message.contains("coordinator is too old"),
            "{}",
            err.message
        );
    }

    #[test]
    fn message_reports_the_floor_we_negotiated_against() {
        // A client that named no floor speaks exactly `proto`. The message must say "3..=3", not
        // the raw "0..=3" — the latter isn't the range we judged, and can't be acted on.
        let err = negotiate(&req_speaking(r#""proto":3"#)).unwrap_err();
        assert!(
            err.message.contains("client speaks 3..=3"),
            "{}",
            err.message
        );
    }

    #[test]
    fn pre_versioning_client_is_still_served() {
        // No `proto` at all — a client from before the field existed. Refusing it would impose a
        // flag day on clients that never had a say.
        assert!(negotiate(&req_speaking(r#""device_name":"old""#)).is_ok());
    }

    fn reg(s: &str) -> RelayReg {
        RelayReg {
            addr: addr(s),
            secret: "sekret".into(),
        }
    }

    #[test]
    fn relay_target_picks_shared_network_lowest_pubkey_third_party() {
        let net = |name: &str| SharedNetwork {
            name: name.into(),
            community: "c".into(),
            guild_id: 1,
            role_id: 2,
        };
        let peer = [9u8; 32];
        // Two relay candidates sharing "mesh" with the peer, plus one on an unrelated network.
        let candidates = vec![
            ([5u8; 32], vec![net("mesh")], reg("203.0.113.5:3478")),
            ([2u8; 32], vec![net("mesh")], reg("203.0.113.2:3478")),
            ([1u8; 32], vec![net("other")], reg("203.0.113.1:3478")),
        ];
        let now = 1_000;

        // Lowest pubkey among those sharing the peer's network wins → the [2;32] relay at .2.
        let info = relay_target(&peer, &[net("mesh")], &candidates, now)
            .expect("a shared-network relay exists");
        assert_eq!(info.turn_addr, addr("203.0.113.2:3478"));
        // Credential is the HMAC over the minted username (verifiable by the relay).
        assert_eq!(
            info.credential,
            common::relay::relay_credential("sekret", &info.username)
        );

        // A peer on a network no candidate shares → no relay.
        assert!(relay_target(&peer, &[net("lonely")], &candidates, now).is_none());

        // The peer is never handed itself as a relay (no self-relay).
        let only_self = vec![(peer, vec![net("mesh")], reg("203.0.113.9:3478"))];
        assert!(relay_target(&peer, &[net("mesh")], &only_self, now).is_none());
    }

    #[test]
    fn reflexive_reports_accepted_only_for_comembers() {
        let comember = [1u8; 32];
        let stranger = [2u8; 32];
        let observed = vec![
            ObservedEndpoint {
                pubkey: comember,
                endpoint: addr("203.0.113.5:51820"),
            },
            // A device the caller does NOT share a network with — a spoofed / unrelated report.
            ObservedEndpoint {
                pubkey: stranger,
                endpoint: addr("203.0.113.9:51820"),
            },
        ];
        let comembers = std::collections::HashSet::from([comember]);
        // The observed peer's coordinator-seen source IP matches the reported reflexive IP.
        let source_ip = std::collections::HashMap::from([
            (comember, addr("203.0.113.5:51820").ip()),
            (stranger, addr("203.0.113.9:51820").ip()),
        ]);

        let accepted: Vec<_> = accepted_reflexives(&observed, &comembers, &source_ip).collect();
        assert_eq!(accepted.len(), 1, "only the co-member's report is accepted");
        assert_eq!(accepted[0].pubkey, comember);

        // With no co-members, every report is rejected.
        let none = std::collections::HashSet::new();
        assert_eq!(accepted_reflexives(&observed, &none, &source_ip).count(), 0);
    }

    #[test]
    fn reflexive_report_rejects_ip_the_peer_did_not_connect_from() {
        let peer = [1u8; 32];
        let comembers = std::collections::HashSet::from([peer]);
        // The peer actually connects to the coordinator from 198.51.100.4.
        let source_ip = std::collections::HashMap::from([(peer, addr("198.51.100.4:9999").ip())]);

        // A co-member invents a different reflexive address for the peer → rejected (it isn't where
        // the peer's own traffic originates), so the punch target can't be redirected.
        let forged = vec![ObservedEndpoint {
            pubkey: peer,
            endpoint: addr("203.0.113.7:51820"),
        }];
        assert_eq!(
            accepted_reflexives(&forged, &comembers, &source_ip).count(),
            0
        );

        // A report whose IP matches the peer's source IP is accepted (the port may differ under
        // symmetric NAT — only the IP is correlated).
        let genuine = vec![ObservedEndpoint {
            pubkey: peer,
            endpoint: addr("198.51.100.4:41000"),
        }];
        assert_eq!(
            accepted_reflexives(&genuine, &comembers, &source_ip).count(),
            1
        );

        // A peer the coordinator has never seen register has no source_ip entry → held (rejected).
        let empty = std::collections::HashMap::new();
        assert_eq!(accepted_reflexives(&genuine, &comembers, &empty).count(), 0);
    }

    #[test]
    fn supersede_retires_only_same_owner_different_key() {
        let old = [7u8; 32];
        let new = [8u8; 32];
        // Re-key: same owner, token names the old key → retire it.
        assert!(should_supersede(42, old, 42, new));
        // Steady state: token names the key now registering → no-op (don't self-retire).
        assert!(!should_supersede(42, new, 42, new));
        // Leaked/foreign token: names another owner's device → refuse (can't retire theirs).
        assert!(!should_supersede(99, old, 42, new));
    }

    #[test]
    fn punch_only_when_neither_side_dialable() {
        let refl = Some(addr("203.0.113.5:51820"));

        // Both behind NAT (no dialable endpoint), peer reflexive known → punch it.
        assert_eq!(punch_target(false, None, refl), refl);

        // Caller dialable → peer dials caller, no punch.
        assert_eq!(punch_target(true, None, refl), None);

        // Peer dialable → caller dials peer via `endpoint`, no punch.
        assert_eq!(
            punch_target(false, Some(addr("198.51.100.9:51820")), refl),
            None
        );

        // Neither dialable but no reflexive on file yet → nothing to punch to.
        assert_eq!(punch_target(false, None, None), None);
    }
}
