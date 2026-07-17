//! Axum HTTP API. M1: `POST /register` issues signed attestations across all guilds the
//! caller shares with the bot, for every registered network whose role they hold.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::api::{
    DeviceInfo, Grant, GuildAnchor, GuildAttestation, IceParams, ManageOp, ManageReq, ManageResp,
    NetworkStatus, OauthCompleteReq, ObservedEndpoint, PkceConfigResp, RegisterReq, RegisterResp,
    Seed, SharedNetwork,
};
use common::netid::sanitize_label;
use common::update::ReleaseManifest;

use crate::oauth::OauthProvider;
use crate::presence::{MemberPresence, Presence};
use crate::roles::{MemberRoles, RoleSource};
use crate::signer::GuildKeys;
use crate::store::{match_device_by_name, DeviceMatch, Store};

#[derive(Clone)]
pub struct AppState {
    /// Per-guild signing keys (design.md §3.1), created lazily on first contact with a guild.
    pub guild_keys: Arc<GuildKeys>,
    pub roles: Arc<dyn RoleSource>,
    pub store: Arc<Store>,
    pub presence: Arc<Presence>,
    /// Monotonic membership version (the long-poll ETag). Bumped whenever presence changes;
    /// parked `/refresh` handlers subscribe and wake on any bump. `watch` has no lost wakeups.
    pub version: Arc<tokio::sync::watch::Sender<u64>>,
    /// Interactive-login provider (Discord OAuth, or a fake in tests); `None` disables login.
    pub oauth: Option<Arc<dyn OauthProvider>>,
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
    /// The coordinator-hosted STUN Binding responder's client-reachable address (M5.5 ICE bootstrap
    /// fallback), advertised in every `RegisterResp`. `None` when no responder is configured.
    pub stun_addr: Option<std::net::SocketAddr>,
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
    let limiter = Arc::new(Mutex::new(RateLimiter::new(Instant::now())));
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
        .route("/metrics", get(admin_metrics))
        .with_state(state)
        // Rate-limit every route. The API is internet-facing and `/oauth/complete` is unauthenticated
        // yet makes an outbound Discord call per request; without a bound it's a DoS + Discord-REST
        // amplifier. Requires the connect-info make-service (see `main`) for the source IP.
        .layer(middleware::from_fn_with_state(limiter, rate_limit))
}

/// Rate-limit window and caps for the HTTP API. Generous per-IP so a legitimate NAT'd herd of
/// clients (all waking on one version bump) isn't throttled — long-pollers issue well under 1 req/s
/// each — while a real flood (thousands/s) is refused. The global cap bounds total work regardless of
/// source spoofing; the per-IP table is cleared every window and hard-capped so it can't grow
/// unbounded. Tune `RL_MAX_PER_IP` up for deployments behind a large shared NAT.
const RL_WINDOW: Duration = Duration::from_secs(1);
const RL_MAX_PER_IP: u32 = 30;
const RL_MAX_TOTAL: u32 = 500;
const RL_MAX_TRACKED_IPS: usize = 65_536;

/// A per-source + global windowed request counter, shared across handlers behind an `Arc<Mutex>`.
struct RateLimiter {
    window_start: Instant,
    total: u32,
    per_ip: HashMap<IpAddr, u32>,
}

impl RateLimiter {
    fn new(now: Instant) -> Self {
        Self {
            window_start: now,
            total: 0,
            per_ip: HashMap::new(),
        }
    }

    /// Whether to admit a request from `ip` at `now`, accounting it against the window if so.
    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if now.duration_since(self.window_start) >= RL_WINDOW {
            self.window_start = now;
            self.total = 0;
            self.per_ip.clear();
        }
        if self.total >= RL_MAX_TOTAL {
            return false;
        }
        match self.per_ip.get_mut(&ip) {
            Some(count) if *count >= RL_MAX_PER_IP => return false,
            Some(count) => *count += 1,
            None => {
                if self.per_ip.len() >= RL_MAX_TRACKED_IPS {
                    return false; // table full this window — refuse unknown sources
                }
                self.per_ip.insert(ip, 1);
            }
        }
        self.total += 1;
        true
    }
}

/// Axum middleware: refuse a request with `429 Too Many Requests` once the caller's source IP (or the
/// deployment as a whole) exceeds the window budget. The source IP comes from `ConnectInfo`; if it's
/// absent the request still counts against the global cap under the unspecified-address bucket.
async fn rate_limit(
    State(limiter): State<Arc<Mutex<RateLimiter>>>,
    req: Request,
    next: Next,
) -> Response {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let admit = limiter.lock().unwrap().allow(ip, Instant::now());
    if admit {
        next.run(req).await
    } else {
        StatusCode::TOO_MANY_REQUESTS.into_response()
    }
}

/// `POST /register` | `/refresh`: record presence + return the caller's grant and seeds.
///
/// Long-poll: build the snapshot once; if the client is already up to date (`since` == current
/// version) hold the request until membership changes or the hold elapses, then rebuild (fresh,
/// re-signed attestations — the renewal path). `since = None`/stale returns immediately.
async fn register(
    State(st): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<RegisterResp>, ApiError> {
    if req.proto != 0 && req.proto != common::PROTOCOL_VERSION {
        tracing::warn!(
            client_proto = req.proto,
            server_proto = common::PROTOCOL_VERSION,
            "protocol version mismatch; relying on additive-field compatibility"
        );
    }
    let resp = build_snapshot(&st, &req).await?;
    if req.since == Some(resp.version) {
        wait_for_change(&st, resp.version).await;
        return Ok(Json(build_snapshot(&st, &req).await?));
    }
    Ok(Json(resp))
}

/// Park until the membership version moves off `since`, or the client-renewal hold elapses. `watch`
/// tracks the latest version internally, so a bump between snapshot and subscribe is not lost.
async fn wait_for_change(st: &AppState, since: u64) {
    wait_for_change_until(
        st,
        since,
        std::time::Duration::from_secs(common::LONGPOLL_HOLD_SECS),
    )
    .await
}

/// [`wait_for_change`] with a caller-chosen hold. The register path uses the ≈attestation-TTL hold
/// (a renewal cycle); the admin dashboard passes a short heartbeat so its held request survives
/// reverse-proxy idle timeouts and its "updated" clock stays fresh, at the cost of a cheap re-poll.
async fn wait_for_change_until(st: &AppState, since: u64, hold: std::time::Duration) {
    let mut rx = st.version.subscribe();
    let deadline = tokio::time::sleep(hold);
    tokio::pin!(deadline);
    loop {
        if *rx.borrow_and_update() != since {
            return;
        }
        tokio::select! {
            r = rx.changed() => if r.is_err() { return; },
            _ = &mut deadline => return,
        }
    }
}

/// Compute the caller's grant + seeds and record their presence, bumping the version if presence
/// changed. Re-signs all attestations with the current time (so a rebuild renews them).
async fn build_snapshot(st: &AppState, req: &RegisterReq) -> Result<RegisterResp, ApiError> {
    let user_id = resolve_user(st, req).await?;
    let now = common::now_unix();
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
    let mut changed = false; // did recording our presence alter the map? → bump version

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
                    changed |= st.presence.evict(g, r, &old_pubkey);
                }
                // …and from the per-user own-device set, so a re-keyed device's siblings prune the
                // retired pubkey immediately rather than waiting for the reaper.
                changed |= st.presence.evict_self(owner, &old_pubkey);
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
        if !req.paused {
            changed |= st.presence.record(
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
                now,
            );
        }
        held.push((net.guild_id, net.role_id));
    }

    // Self-eviction: drop our presence from any network we were recorded in but no longer hold
    // (role revoked) — or from *every* network while disconnected (`paused`). Peers pick this up
    // on their next (long-poll-woken) refresh and prune us.
    for (g, r) in st.presence.networks_of(&req.wg_pubkey) {
        if req.paused || !held.contains(&(g, r)) {
            changed |= st.presence.evict(g, r, &req.wg_pubkey);
        }
    }

    // Own-device peering: record this device in the per-user online set (independent of networks) so
    // its siblings can seed it even with no shared enabled network. Gated on the client opting in
    // (`peer_own_devices`, default on), not being paused, and holding an identity (≥1 role → a grant
    // is issued below; without one there's no anchor to attest a sibling under). Evict in every other
    // case so an opt-out / pause / role-loss withdraws this device from its siblings' seeds.
    let has_identity = !networks_status.is_empty();
    if req.peer_own_devices && !req.paused && has_identity {
        changed |= st.presence.record_self(
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
            now,
        );
    } else {
        changed |= st.presence.evict_self(user_id, &req.wg_pubkey);
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
                    user_id,
                    username.clone(),
                    device_name.clone(),
                    is_primary,
                    ip,
                    req.wg_pubkey,
                )
                .map_err(internal)?;
            attestations.push(GuildAttestation {
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
    // roam (address change) bumps the version so a parked co-member wakes and picks up the target.
    // The caller's co-members: every device it shares ≥1 network with. This is the trust boundary
    // for all peer-keyed exchange tables below — the caller may only publish reflexive/relay/ICE
    // state *about a peer it actually meshes with*. Without this gate an authenticated member could
    // inject entries for arbitrary pubkeys, growing the tables unbounded and (since a novel entry
    // bumps the version) waking the whole long-poll herd for free.
    let comembers: std::collections::HashSet<[u8; 32]> = by_pubkey.keys().copied().collect();
    {
        let mut refl = st.reflexive.lock().unwrap();
        for obs in accepted_reflexives(&req.observed, &comembers) {
            if refl.get(&obs.pubkey) != Some(&obs.endpoint) {
                refl.insert(obs.pubkey, obs.endpoint);
                changed = true;
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
    // relayed address bumps the version so the peer wakes and learns it as its `peer_relayed` — the
    // second half of the ~2-round relay converge.
    {
        let mut allocs = st.relay_allocs.lock().unwrap();
        for a in &req.relay_allocated {
            // Only accept a relayed address for a peer the caller actually meshes with (mirrors the
            // reflexive gate) — otherwise the map grows unbounded and each novel entry wakes the herd.
            if !comembers.contains(&a.peer) {
                continue;
            }
            if allocs.get(&(req.wg_pubkey, a.peer)) != Some(&a.relayed) {
                allocs.insert((req.wg_pubkey, a.peer), a.relayed);
                changed = true;
            }
        }
    }

    // Record this device's ICE session offers (candidate exchange, M5.5). A new/changed offer (fresh
    // candidates, or an ICE restart's new ufrag/pwd) bumps the version so the peer wakes, picks up
    // the candidates as its `Seed::ice`, and runs connectivity checks. The coordinator only relays —
    // it never runs ICE — so the data path stays peer-to-peer.
    {
        let mut ice = st.ice.lock().unwrap();
        for e in &req.ice {
            // Same co-member gate as reflexive/relay: an ICE offer is only accepted for a peer the
            // caller shares a network with, so the map stays bounded and can't be used to force herd
            // wakeups for arbitrary pubkeys.
            if !comembers.contains(&e.peer) {
                continue;
            }
            if ice.get(&(req.wg_pubkey, e.peer)) != Some(&e.params) {
                ice.insert((req.wg_pubkey, e.peer), e.params.clone());
                changed = true;
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
    let mut seeds = Vec::new();
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
        let mut attestations = Vec::with_capacity(shared_guilds.len());
        for &g in &shared_guilds {
            let key = st.guild_keys.get(g).await.map_err(internal)?;
            let signed = key
                .signer
                .sign_attestation(
                    mp.user_id,
                    mp.username.clone(),
                    mp.device_name.clone(),
                    mp.is_primary,
                    mp.ip,
                    mp.pubkey,
                )
                .map_err(internal)?;
            attestations.push(GuildAttestation {
                attestation: signed.to_base64(),
                community_name: community_cache.get(&g).cloned().unwrap_or_default(),
            });
        }
        // The peer's ICE offer for reaching us (if it has run ICE toward this caller): key is
        // (owner=peer, peer=caller). The client feeds it into its agent to run connectivity checks.
        let ice = ice_exchange.get(&(mp.pubkey, req.wg_pubkey)).cloned();
        seeds.push(Seed {
            attestations,
            endpoint: mp.endpoint,
            punch,
            networks,
            relay,
            ice,
        });
    }

    let device_token = st
        .store
        .device_token(&req.wg_pubkey)
        .await
        .map_err(internal)?;

    // Bump the version if our presence changed → wake peers parked in long-poll.
    if changed {
        st.version.send_modify(|v| *v += 1);
    }

    tracing::debug!(
        user = user_id,
        since = ?req.since,
        version = *st.version.borrow(),
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

    Ok(RegisterResp {
        anchors,
        grant,
        device_token,
        seeds,
        version: *st.version.borrow(),
        networks: networks_status,
        stun_addr: st.stun_addr,
        proto: common::PROTOCOL_VERSION,
        server_version: common::VERSION.to_string(),
        release,
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
            // it now and bump the version so parked long-pollers wake and prune it.
            let mut changed = false;
            for (g, r) in st.presence.networks_of(&pk) {
                changed |= st.presence.evict(g, r, &pk);
            }
            if changed {
                st.version.send_modify(|v| *v += 1);
            }
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

/// Resolve the caller's user id: an already-enrolled device is known by its pubkey; a device bound
/// via interactive login (OAuth) is known too; otherwise a new device must present a valid
/// one-time enrollment key (which binds its pubkey to the owner on use).
async fn resolve_user(st: &AppState, req: &RegisterReq) -> Result<u64, ApiError> {
    if let Some(uid) = st
        .store
        .device_owner(&req.wg_pubkey)
        .await
        .map_err(internal)?
    {
        return Ok(uid);
    }
    if let Some(uid) = st
        .store
        .oauth_user(&req.wg_pubkey)
        .await
        .map_err(internal)?
    {
        return Ok(uid);
    }
    let Some(key) = req.enrollment_key.as_deref() else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "device not enrolled; log in (oauth) or provide an enrollment_key",
        ));
    };
    st.store
        .consume_enrollment_key(key, &req.wg_pubkey, common::now_unix())
        .await
        .map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, e.to_string()))
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

/// Peer-observed reflexives the caller may legitimately report: only those for a device the caller
/// actually meshes with (`comembers` = the caller's co-member seed pubkeys). You can only observe a
/// peer's reflexive across a tunnel you share, so a report about anyone else is spoofed/irrelevant.
/// This bounds a forged endpoint to the victim's own co-members (the network trust boundary) rather
/// than letting any authenticated member redirect any device's punch target.
fn accepted_reflexives<'a>(
    observed: &'a [ObservedEndpoint],
    comembers: &'a std::collections::HashSet<[u8; 32]>,
) -> impl Iterator<Item = &'a ObservedEndpoint> {
    observed
        .iter()
        .filter(move |o| comembers.contains(&o.pubkey))
}

// ---- operator admin surface (`/admin` dashboard + `/metrics`) ----

/// One network's live count within a guild.
struct NetStat {
    role_id: u64,
    name: String,
    online: usize,
}

/// One guild's admin view: display name (falls back to the id) and its networks.
struct GuildStat {
    id: u64,
    name: Option<String>,
    networks: Vec<NetStat>,
}

/// A point-in-time operational snapshot for the admin surface. Assembled from the store (enrolled
/// devices, registered networks, guilds contacted), live presence (online counts), and the role
/// source (guild names). Read-only and off the client hot path — served only to the operator, on
/// rare admin requests, from cheap SQLite/in-memory reads plus cached guild-name lookups.
struct AdminStats {
    guilds: Vec<GuildStat>,
    total_networks: usize,
    online_devices: usize,
    online_users: usize,
    enrolled_devices: u64,
    longpoll_waiters: usize,
    version: u64,
}

async fn gather_stats(st: &AppState) -> Result<AdminStats, ApiError> {
    let networks = st.store.all_networks().await.map_err(internal)?;
    let enrolled_devices = st.store.count_devices().await.map_err(internal)?;
    let guild_ids = st.store.guild_ids().await.map_err(internal)?;
    let pres = st.presence.stats();

    // Guild set = guilds with a signing key ∪ guilds owning a network ∪ guilds with anyone online.
    let mut ids: BTreeSet<u64> = guild_ids.into_iter().collect();
    ids.extend(networks.iter().map(|n| n.guild_id));
    ids.extend(pres.online_per_network.keys().map(|(g, _)| *g));

    let mut guilds = Vec::with_capacity(ids.len());
    for id in ids {
        let name = st.roles.guild_name(id).await;
        let mut nets: Vec<NetStat> = networks
            .iter()
            .filter(|n| n.guild_id == id)
            .map(|n| NetStat {
                role_id: n.role_id,
                name: n.name.clone(),
                online: pres
                    .online_per_network
                    .get(&(id, n.role_id))
                    .copied()
                    .unwrap_or(0),
            })
            .collect();
        nets.sort_by(|a, b| a.name.cmp(&b.name));
        guilds.push(GuildStat {
            id,
            name,
            networks: nets,
        });
    }

    Ok(AdminStats {
        guilds,
        total_networks: networks.len(),
        online_devices: pres.online_devices,
        online_users: pres.online_users,
        enrolled_devices,
        longpoll_waiters: st.version.receiver_count(),
        version: *st.version.borrow(),
    })
}

/// Gate an admin request on the `[admin]` token. `Err(404)` when no token is configured (surface
/// disabled — indistinguishable from a missing route); `Err(401)` on a missing or wrong bearer.
/// Constant-time comparison so a wrong token leaks no timing signal about matching prefix length.
fn admin_auth(st: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(token) = st.admin_token.as_deref() else {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "not found"));
    };
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(p) if ct_eq(p.as_bytes(), token.as_bytes()) => Ok(()),
        _ => Err(ApiError::new(StatusCode::UNAUTHORIZED, "unauthorized")),
    }
}

/// Constant-time byte-slice equality. Length still differs observably, acceptable for a secret.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `GET /admin`: the operator dashboard **shell** (a self-contained HTML+JS app). Unauthenticated
/// by necessity — a browser sends no bearer header on navigation — but it carries **no data**: the
/// JS prompts for the `[admin]` token (stored in `localStorage`) and fetches the gated
/// `/admin/stats` itself. Served only when admin is enabled; otherwise 404, same as the data route.
async fn admin_dashboard(State(st): State<AppState>) -> Result<Html<&'static str>, ApiError> {
    if st.admin_token.is_none() {
        return Err(ApiError::new(StatusCode::NOT_FOUND, "not found"));
    }
    Ok(Html(ADMIN_HTML))
}

/// Heartbeat hold for the `/admin/stats` long-poll — short (unlike the register renewal hold) so a
/// held dashboard request survives reverse-proxy idle timeouts and its "updated" clock stays fresh.
const ADMIN_POLL_HOLD_SECS: u64 = 25;

#[derive(serde::Deserialize)]
struct StatsQuery {
    /// The membership `version` the client last rendered. When it equals the current version the
    /// request long-polls (holds until membership changes or the heartbeat elapses); absent/stale
    /// returns immediately. Drives the dashboard's realtime feed off the existing `watch`.
    since: Option<u64>,
}

/// `GET /admin/stats[?since=N]`: token-gated JSON snapshot, the dashboard's data feed. With `since`
/// at the current version it long-polls via the same machinery as `/register` — so the browser
/// re-renders the instant a peer joins/leaves/reaps, with a ~heartbeat tick otherwise. One held
/// request per open tab; wakes only on real version bumps, so idle cost is negligible.
async fn admin_stats(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<StatsQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    admin_auth(&st, &headers)?;
    let version = *st.version.borrow();
    if q.since == Some(version) {
        wait_for_change_until(
            &st,
            version,
            std::time::Duration::from_secs(ADMIN_POLL_HOLD_SECS),
        )
        .await;
    }
    Ok(Json(stats_json(&gather_stats(&st).await?)))
}

/// Serialize a snapshot for the dashboard. Guild/role snowflakes go out as **strings** — they
/// exceed 2^53 and a JS `Number` would silently mangle them.
fn stats_json(s: &AdminStats) -> serde_json::Value {
    serde_json::json!({
        "version": s.version,
        "totals": {
            "guilds": s.guilds.len(),
            "networks": s.total_networks,
            "devices_online": s.online_devices,
            "users_online": s.online_users,
            "devices_enrolled": s.enrolled_devices,
            "longpoll_waiters": s.longpoll_waiters,
        },
        "guilds": s.guilds.iter().map(|g| serde_json::json!({
            "id": g.id.to_string(),
            "name": g.name,
            "networks": g.networks.iter().map(|n| serde_json::json!({
                "role_id": n.role_id.to_string(),
                "name": n.name,
                "online": n.online,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

/// `GET /metrics`: Prometheus text exposition of the same counts.
async fn admin_metrics(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    admin_auth(&st, &headers)?;
    let body = render_metrics(&gather_stats(&st).await?);
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response())
}

/// The operator dashboard: a self-contained HTML+CSS+JS app (no external assets). It reads the
/// `[admin]` token from `localStorage` (prompting once), then long-polls `/admin/stats` with a
/// `Bearer` header and re-renders on every response — realtime with no server-rendered data here.
const ADMIN_HTML: &str = include_str!("admin.html");

/// Escape a Prometheus label value (backslash, double-quote, newline).
fn esc_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn gauge(out: &mut String, name: &str, help: &str, val: impl std::fmt::Display) {
    use std::fmt::Write;
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} gauge");
    let _ = writeln!(out, "{name} {val}");
}

fn render_metrics(s: &AdminStats) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    gauge(
        &mut out,
        "unitylan_guilds",
        "Guilds this coordinator has contacted.",
        s.guilds.len(),
    );
    gauge(
        &mut out,
        "unitylan_networks",
        "Registered networks (roles) across all guilds.",
        s.total_networks,
    );
    gauge(
        &mut out,
        "unitylan_devices_enrolled",
        "Enrolled devices (persistent registrations).",
        s.enrolled_devices,
    );
    gauge(
        &mut out,
        "unitylan_devices_online",
        "Distinct devices currently online.",
        s.online_devices,
    );
    gauge(
        &mut out,
        "unitylan_users_online",
        "Distinct users currently online.",
        s.online_users,
    );
    gauge(
        &mut out,
        "unitylan_longpoll_waiters",
        "Parked long-poll requests.",
        s.longpoll_waiters,
    );
    gauge(
        &mut out,
        "unitylan_membership_version",
        "Monotonic membership version.",
        s.version,
    );
    let _ = writeln!(
        out,
        "# HELP unitylan_peers_online Devices online per network."
    );
    let _ = writeln!(out, "# TYPE unitylan_peers_online gauge");
    for g in &s.guilds {
        let gname = esc_label(g.name.as_deref().unwrap_or(""));
        for n in &g.networks {
            let _ = writeln!(
                out,
                "unitylan_peers_online{{guild_id=\"{}\",guild=\"{}\",network=\"{}\",role_id=\"{}\"}} {}",
                g.id,
                gname,
                esc_label(&n.name),
                n.role_id,
                n.online
            );
        }
    }
    out
}

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
        accepted_reflexives, punch_target, relay_target, should_supersede, RateLimiter, RelayReg,
        RL_MAX_PER_IP, RL_MAX_TOTAL, RL_WINDOW,
    };
    use common::api::{ObservedEndpoint, SharedNetwork};
    use std::net::IpAddr;
    use std::time::Instant;

    #[test]
    fn rate_limiter_per_ip_and_window_reset() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(t0);
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        for _ in 0..RL_MAX_PER_IP {
            assert!(rl.allow(ip, t0));
        }
        assert!(!rl.allow(ip, t0)); // over the per-IP cap
        let other: IpAddr = "198.51.100.9".parse().unwrap();
        assert!(rl.allow(other, t0)); // a different source is unaffected
        assert!(rl.allow(ip, t0 + RL_WINDOW)); // a new window clears the counters
    }

    #[test]
    fn rate_limiter_global_cap() {
        let t0 = Instant::now();
        let mut rl = RateLimiter::new(t0);
        let mut allowed = 0u32;
        for i in 0..(RL_MAX_TOTAL + 200) {
            let ip = IpAddr::from([10, 0, (i >> 8) as u8, (i & 0xff) as u8]);
            if rl.allow(ip, t0) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, RL_MAX_TOTAL);
    }

    fn addr(s: &str) -> std::net::SocketAddr {
        s.parse().unwrap()
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

        let accepted: Vec<_> = accepted_reflexives(&observed, &comembers).collect();
        assert_eq!(accepted.len(), 1, "only the co-member's report is accepted");
        assert_eq!(accepted[0].pubkey, comember);

        // With no co-members, every report is rejected.
        let none = std::collections::HashSet::new();
        assert_eq!(accepted_reflexives(&observed, &none).count(), 0);
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
