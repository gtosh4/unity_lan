//! Axum HTTP API. M1: `POST /register` issues signed attestations across all guilds the
//! caller shares with the bot, for every registered network whose role they hold.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::api::{Grant, RegisterReq, RegisterResp, Seed};
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
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // register and refresh share the same logic: issue grants, record presence, return seeds.
        .route("/register", post(register))
        .route("/refresh", post(register))
        .with_state(state)
}

async fn register(
    State(st): State<AppState>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<RegisterResp>, ApiError> {
    let user_id = resolve_user(&st, &req).await?;
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
    let mut network_names: Vec<String> = Vec::new();
    let mut community_name: Option<String> = None;
    let mut username = format!("user-{user_id}"); // fallback until a role source gives a handle

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

        // Chunk 2 (enrollment) wires the global handle; for now derive it from the nick.
        username = sanitize_label(&member.nick);
        if community_name.is_none() {
            community_name = Some(community_of(&st, net.guild_id).await.map_err(internal)?);
        }
        network_names.push(net.name);

        // Record the device as present in this network (for others' seeds).
        st.presence.record(
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
            networks: network_names,
        })
    };

    // Seeds: every other device sharing ≥1 network with the caller, deduplicated by pubkey.
    let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    let mut seeds = Vec::new();
    for (guild_id, role_id) in &held {
        let seed_community = community_of(&st, *guild_id).await.map_err(internal)?;
        for mp in st.presence.others_in(*guild_id, *role_id, &req.wg_pubkey) {
            if !seen.insert(mp.pubkey) {
                continue;
            }
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
                community_name: seed_community.clone(),
                endpoint: mp.endpoint,
            });
        }
    }

    Ok(Json(RegisterResp {
        coord_pubkey: st.signer.anchor_bytes(),
        grant,
        seeds,
    }))
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
