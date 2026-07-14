//! Axum HTTP API. M1: `POST /register` issues signed attestations across all guilds the
//! caller shares with the bot, for every registered network whose role they hold.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::api::{
    DeviceInfo, Grant, IceParams, ManageOp, ManageReq, ManageResp, NetworkStatus, OauthCompleteReq,
    ObservedEndpoint, PkceConfigResp, RegisterReq, RegisterResp, Seed,
};
use common::netid::sanitize_label;

use crate::oauth::OauthProvider;
use crate::presence::{MemberPresence, Presence};
use crate::roles::{MemberRoles, RoleSource};
use crate::signer::Signer;
use crate::store::Store;

#[derive(Clone)]
pub struct AppState {
    pub signer: Arc<Signer>,
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
    /// Trust-anchor rotation chain (base64 `Signed<RotationCert>`, oldest→newest), served in every
    /// `RegisterResp` so a client pinned to a superseded anchor can re-pin (design.md §9). Loaded at
    /// startup; changes only via the `rotate-key` subcommand (which requires a restart).
    pub rotation_chain: Vec<String>,
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
        .with_state(state)
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
    let resp = build_snapshot(&st, &req).await?;
    if req.since == Some(resp.version) {
        wait_for_change(&st, resp.version).await;
        return Ok(Json(build_snapshot(&st, &req).await?));
    }
    Ok(Json(resp))
}

/// Park until the membership version moves off `since`, or the hold elapses. `watch` tracks the
/// latest version internally, so a bump between snapshot and subscribe is not lost.
async fn wait_for_change(st: &AppState, since: u64) {
    let mut rx = st.version.subscribe();
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(common::LONGPOLL_HOLD_SECS));
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
    let device_name = sanitize_label(&req.device_name);

    // One IP per device (keyed by pubkey), reused across every network it holds.
    let ip = st
        .store
        .allocate_device_ip(&req.wg_pubkey, user_id, &device_name)
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
            }
        }
    }
    let mut network_names: Vec<String> = Vec::new();
    let mut community_name: Option<String> = None;
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
        if community_name.is_none() {
            community_name = Some(guild_label);
        }

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

    // Self-grant: one device attestation. Issued whenever the caller holds ≥1 network role, even if
    // every one is currently disabled (`networks` is then empty) — the device still needs its
    // identity/IP and the client needs the grant to surface the toggle list. `None` only when the
    // caller holds no network roles at all.
    let grant = if networks_status.is_empty() {
        None
    } else {
        let signed = st
            .signer
            .sign_attestation(
                user_id,
                username,
                device_name,
                is_primary,
                ip,
                req.wg_pubkey,
            )
            .map_err(internal)?;
        Some(Grant {
            attestation: signed.to_base64(),
            community_name: community_name.unwrap_or_default(),
            networks: network_names.clone(),
        })
    };

    // Seeds: every other device sharing ≥1 network with the caller, deduplicated by pubkey but
    // accumulating the shared network *names* (so the client can scope `expose --net` per network).
    let mut by_pubkey: HashMap<[u8; 32], (MemberPresence, Vec<String>, String)> = HashMap::new();
    for ((guild_id, role_id), net_name) in held.iter().zip(network_names.iter()) {
        let seed_community = community_of(st, *guild_id).await.map_err(internal)?;
        for mp in st.presence.others_in(*guild_id, *role_id, &req.wg_pubkey) {
            let entry = by_pubkey
                .entry(mp.pubkey)
                .or_insert_with(|| (mp.clone(), Vec::new(), seed_community.clone()));
            if !entry.1.contains(net_name) {
                entry.1.push(net_name.clone());
            }
        }
    }
    // Record peer-observed reflexive endpoints (for hole punching). Each entry says "I saw device
    // X arriving from ip:port" — X's NAT mapping seen from the outside. Accepted *only* for a pubkey
    // the caller actually meshes with (a co-member seed): you can only report a reflexive for a peer
    // you share a network with — and thus have a tunnel to observe. This bounds a spoofed endpoint to
    // the victim's own co-members (the network trust boundary), instead of letting any authenticated
    // member redirect any device's punch target to an attacker-chosen address. A first sighting or a
    // roam (address change) bumps the version so a parked co-member wakes and picks up the target.
    {
        let comembers: std::collections::HashSet<[u8; 32]> = by_pubkey.keys().copied().collect();
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
    let relay_candidates: Vec<([u8; 32], Vec<String>, RelayReg)> = by_pubkey
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
    let now = common::now_unix();

    // Whether the caller itself is directly dialable (self-reported endpoint: UPnP / manual
    // forward). If so, a NAT'd peer just dials us and no punch is needed on either side.
    let caller_dialable = req.endpoint.is_some();
    let reflexive = st.reflexive.lock().unwrap().clone();
    let mut seeds = Vec::new();
    for (_pubkey, (mp, networks, community)) in by_pubkey {
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
        let signed = st
            .signer
            .sign_attestation(
                mp.user_id,
                mp.username,
                mp.device_name,
                mp.is_primary,
                mp.ip,
                mp.pubkey,
            )
            .map_err(internal)?;
        // The peer's ICE offer for reaching us (if it has run ICE toward this caller): key is
        // (owner=peer, peer=caller). The client feeds it into its agent to run connectivity checks.
        let ice = ice_exchange.get(&(mp.pubkey, req.wg_pubkey)).cloned();
        seeds.push(Seed {
            attestation: signed.to_base64(),
            community_name: community,
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

    Ok(RegisterResp {
        coord_pubkey: st.signer.anchor_bytes(),
        rotation_chain: st.rotation_chain.clone(),
        grant,
        device_token,
        seeds,
        version: *st.version.borrow(),
        networks: networks_status,
        stun_addr: st.stun_addr,
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
            let name = sanitize_label(&new_name);
            st.store
                .rename_device(&self_pubkey, &name)
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
    let matches: Vec<[u8; 32]> = st
        .store
        .user_devices(user_id)
        .await
        .map_err(internal)?
        .into_iter()
        .filter(|(_, n)| *n == want)
        .map(|(pk, _)| pk)
        .collect();
    match matches.as_slice() {
        [pk] => Ok(*pk),
        [] => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            format!("no device named '{want}'"),
        )),
        _ => Err(ApiError::new(
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
    peer_networks: &[String],
    candidates: &[([u8; 32], Vec<String>, RelayReg)],
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
    use super::{accepted_reflexives, punch_target, relay_target, should_supersede, RelayReg};
    use common::api::ObservedEndpoint;

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
        let peer = [9u8; 32];
        // Two relay candidates sharing "mesh" with the peer, plus one on an unrelated network.
        let candidates = vec![
            ([5u8; 32], vec!["mesh".into()], reg("203.0.113.5:3478")),
            ([2u8; 32], vec!["mesh".into()], reg("203.0.113.2:3478")),
            ([1u8; 32], vec!["other".into()], reg("203.0.113.1:3478")),
        ];
        let now = 1_000;

        // Lowest pubkey among those sharing the peer's network wins → the [2;32] relay at .2.
        let info = relay_target(&peer, &["mesh".into()], &candidates, now)
            .expect("a shared-network relay exists");
        assert_eq!(info.turn_addr, addr("203.0.113.2:3478"));
        // Credential is the HMAC over the minted username (verifiable by the relay).
        assert_eq!(
            info.credential,
            common::relay::relay_credential("sekret", &info.username)
        );

        // A peer on a network no candidate shares → no relay.
        assert!(relay_target(&peer, &["lonely".into()], &candidates, now).is_none());

        // The peer is never handed itself as a relay (no self-relay).
        let only_self = vec![(peer, vec!["mesh".into()], reg("203.0.113.9:3478"))];
        assert!(relay_target(&peer, &["mesh".into()], &only_self, now).is_none());
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
