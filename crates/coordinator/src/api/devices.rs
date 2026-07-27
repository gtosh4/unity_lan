//! `POST /devices/manage`: owner-scoped device operations (list, rename, set-primary, remove),
//! authenticated by the device bearer token the coordinator issued at enrollment.
//!
//! The token identifies both the owner and the calling device, so every operation here is confined
//! to that owner's own devices — there is no admin path through this route.

use std::collections::BTreeSet;

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use common::api::{DeviceInfo, ManageOp, ManageReq, ManageResp};
use common::netid::sanitize_label;

use super::{internal, ApiError, AppState};
use crate::store::{match_device_by_name, DeviceMatch};
use crate::versions::Scope;

pub(super) async fn manage(
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
