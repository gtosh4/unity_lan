//! Axum HTTP API. M1: `POST /register` issues signed attestations across all guilds the
//! caller shares with the bot, for every registered network whose role they hold.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use common::api::{Grant, RegisterReq, RegisterResp, Seed};
use common::netid::{host_addr, sanitize_label, subnet_of};
use serde::Deserialize;

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
    /// Dev/testing: trust the `dev_user` query param as the caller's identity (no OAuth).
    pub allow_dev: bool,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        // register and refresh share the same logic: issue grants, record presence, return seeds.
        .route("/register", post(register))
        .route("/refresh", post(register))
        .with_state(state)
}

#[derive(Deserialize)]
struct RegisterQuery {
    /// Dev-only caller identity (fake mode). Ignored once real OAuth sessions exist.
    dev_user: Option<u64>,
}

async fn register(
    State(st): State<AppState>,
    Query(q): Query<RegisterQuery>,
    Json(req): Json<RegisterReq>,
) -> Result<Json<RegisterResp>, ApiError> {
    let user_id = resolve_user(&st, &q)?;
    let networks = st.store.all_networks().await.map_err(internal)?;

    // Cache per-guild member lookups so we hit the role source once per guild.
    let mut member_cache: HashMap<u64, Option<MemberRoles>> = HashMap::new();
    let mut grants = Vec::new();
    let mut held: Vec<(u64, u64)> = Vec::new(); // (guild, role) the caller holds

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

        let host = st
            .store
            .allocate_host(net.guild_id, net.role_id, user_id)
            .await
            .map_err(internal)?;
        let ip = host_addr(subnet_of(net.guild_id, net.role_id), host);
        let guild_name = st.roles.guild_name(net.guild_id).await.unwrap_or_default();
        let nick = sanitize_label(&member.nick);

        // Record the caller as present in this network (for others' seeds).
        st.presence.record(
            net.guild_id,
            net.role_id,
            user_id,
            MemberPresence {
                pubkey: req.wg_pubkey,
                ip,
                nick: nick.clone(),
                endpoint: req.endpoint,
            },
        );

        let signed = st
            .signer
            .sign_attestation(net.guild_id, net.role_id, user_id, nick, ip, req.wg_pubkey)
            .map_err(internal)?;

        grants.push(Grant {
            attestation: signed.to_base64(),
            guild_name,
            network_name: net.name,
        });
        held.push((net.guild_id, net.role_id));
    }

    // Seeds: every other member present in a network the caller holds.
    let mut seeds = Vec::new();
    for (guild_id, role_id) in &held {
        for (other_user, mp) in st.presence.others_in(*guild_id, *role_id, user_id) {
            let signed = st
                .signer
                .sign_attestation(*guild_id, *role_id, other_user, mp.nick, mp.ip, mp.pubkey)
                .map_err(internal)?;
            seeds.push(Seed {
                attestation: signed.to_base64(),
                endpoint: mp.endpoint,
            });
        }
    }

    Ok(Json(RegisterResp {
        coord_pubkey: st.signer.anchor_bytes(),
        grants,
        seeds,
    }))
}

fn resolve_user(st: &AppState, q: &RegisterQuery) -> Result<u64, ApiError> {
    if st.allow_dev {
        q.dev_user
            .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "dev_auth requires ?dev_user="))
    } else {
        Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "live OAuth session not implemented yet (set dev_auth=true to use ?dev_user=)",
        ))
    }
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
