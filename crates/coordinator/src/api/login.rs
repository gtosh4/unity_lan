//! Interactive login and the public enrollment key.
//!
//! The engine, not the coordinator, is the OAuth public client: it runs the PKCE flow itself and
//! hands us only the resulting access token, so no client secret ever reaches a device. All three
//! routes here are unauthenticated by design — two hand out public values, and the third is the one
//! that *establishes* who a device belongs to.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use common::api::{OauthCompleteReq, PkceConfigResp};

use super::{internal, ApiError, AppState};

/// `GET /oauth/pkce-config`: the public bits the engine needs to run the PKCE flow itself.
pub(super) async fn oauth_pkce_config(
    State(st): State<AppState>,
) -> Result<Json<PkceConfigResp>, ApiError> {
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
pub(super) async fn oauth_complete(
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

/// `GET /enroll/pubkey`: the deployment's X25519 enrollment public key. A client combines it with its
/// WG private key to build the possession proof it sends on an enrolling register. Public by design.
pub(super) async fn enroll_pubkey(State(st): State<AppState>) -> Json<[u8; 32]> {
    Json(common::crypto::enroll_public_from_secret(&st.enroll_secret))
}
