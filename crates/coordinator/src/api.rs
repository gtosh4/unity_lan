//! Axum HTTP API. M1: `POST /register` issues signed attestations across all guilds the
//! caller shares with the bot, for every registered network whose role they hold.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::api::{
    DeviceInfo, Grant, ManageOp, ManageReq, ManageResp, NetworkStatus, RegisterReq, RegisterResp,
    Seed,
};
use common::netid::sanitize_label;

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
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // register and refresh share the same logic: issue grants, record presence, return seeds.
        .route("/register", post(register))
        .route("/refresh", post(register))
        .route("/devices/manage", post(manage))
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
    let mut network_names: Vec<String> = Vec::new();
    let mut community_name: Option<String> = None;
    let mut username = format!("user-{user_id}"); // fallback until a role source gives a handle

    // Networks this device has opted out of peering on (the GUI toggle).
    let optouts = st.store.network_optouts(&req.wg_pubkey).await.map_err(internal)?;
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
        let Some(member) = member else { continue };
        if !member.role_ids.contains(&net.role_id) {
            continue;
        }

        // The user holds this role. Record it for the toggle UI; a disabled network is listed but
        // contributes no presence / grant / seeds (so it doesn't peer, in either direction).
        let enabled = !optouts.contains(&(net.guild_id, net.role_id));
        networks_status.push(NetworkStatus {
            guild_id: net.guild_id,
            role_id: net.role_id,
            name: net.name.clone(),
            enabled,
        });
        if !enabled {
            continue;
        }

        // Chunk 2 (enrollment) wires the global handle; for now derive it from the nick.
        username = sanitize_label(&member.nick);
        if community_name.is_none() {
            community_name = Some(community_of(&st, net.guild_id).await.map_err(internal)?);
        }
        network_names.push(net.name);

        // Record the device as present in this network (for others' seeds).
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
        );
        held.push((net.guild_id, net.role_id));
    }

    // Self-eviction: drop our presence from any network we were recorded in but no longer hold
    // (role revoked). Peers pick this up on their next (long-poll-woken) refresh and prune us.
    for (g, r) in st.presence.networks_of(&req.wg_pubkey) {
        if !held.contains(&(g, r)) {
            changed |= st.presence.evict(g, r, &req.wg_pubkey);
        }
    }

    // Self-grant: one device attestation (None if the caller holds no networks).
    let grant = if held.is_empty() {
        None
    } else {
        let signed = st
            .signer
            .sign_attestation(user_id, username, device_name, is_primary, ip, req.wg_pubkey)
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
        let seed_community = community_of(&st, *guild_id).await.map_err(internal)?;
        for mp in st.presence.others_in(*guild_id, *role_id, &req.wg_pubkey) {
            let entry = by_pubkey
                .entry(mp.pubkey)
                .or_insert_with(|| (mp.clone(), Vec::new(), seed_community.clone()));
            if !entry.1.contains(net_name) {
                entry.1.push(net_name.clone());
            }
        }
    }
    let mut seeds = Vec::new();
    for (_pubkey, (mp, networks, community)) in by_pubkey {
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
        seeds.push(Seed {
            attestation: signed.to_base64(),
            community_name: community,
            endpoint: mp.endpoint,
            networks,
        });
    }

    let device_token = st.store.device_token(&req.wg_pubkey).await.map_err(internal)?;

    // Bump the version if our presence changed → wake peers parked in long-poll.
    if changed {
        st.version.send_modify(|v| *v += 1);
    }

    Ok(RegisterResp {
        coord_pubkey: st.signer.anchor_bytes(),
        grant,
        device_token,
        seeds,
        version: *st.version.borrow(),
        networks: networks_status,
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
            format!("removed {}", sanitize_label(&device_name))
        }
        ManageOp::SetNetwork { guild_id, role_id, enabled } => {
            st.store
                .set_network_optout(&self_pubkey, guild_id, role_id, enabled)
                .await
                .map_err(internal)?;
            // Disabling: drop this device from that network's presence now so peers prune it on
            // their next (version-woken) refresh. Enabling: the bump re-meshes it.
            if !enabled {
                st.presence.evict(guild_id, role_id, &self_pubkey);
            }
            st.version.send_modify(|v| *v += 1);
            format!(
                "network {guild_id}/{role_id} peering {}",
                if enabled { "enabled" } else { "disabled" }
            )
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

/// Resolve the caller's user id: an already-enrolled device is known by its pubkey; a new device
/// must present a valid one-time enrollment key (which binds its pubkey to the owner on use).
async fn resolve_user(st: &AppState, req: &RegisterReq) -> Result<u64, ApiError> {
    if let Some(uid) = st.store.device_owner(&req.wg_pubkey).await.map_err(internal)? {
        return Ok(uid);
    }
    let Some(key) = req.enrollment_key.as_deref() else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "device not enrolled; provide an enrollment_key",
        ));
    };
    st.store
        .consume_enrollment_key(key, &req.wg_pubkey, common::now_unix())
        .await
        .map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, e.to_string()))
}

fn internal(e: anyhow::Error) -> ApiError {
    ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
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
