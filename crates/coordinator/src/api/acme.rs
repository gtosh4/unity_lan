//! `POST /acme-challenge`: publish a device's ACME DNS-01 challenge values, so a CA can validate the
//! certificate order that device is running against it.
//!
//! The coordinator's whole role in certificate issuance is this route plus [`crate::zone`]. The
//! device generates its own key, talks to the CA itself, and keeps the private key — the coordinator
//! only ever holds a TXT string for a few minutes, and never sees key material. That keeps it on the
//! control plane, consistent with everything else it does.
//!
//! **The request carries values, never names.** The names are derived here from the calling device's
//! own allocation. A client-supplied name would let any enrolled device request a challenge for
//! another user's hostname and walk away with a publicly-trusted certificate for it — the exact
//! impersonation the per-deployment label allocation (`Store::user_label`) exists to prevent.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use common::api::{AcmeChallengeReq, AcmeChallengeResp};

use super::{internal, ApiError, AppState};

pub(super) async fn acme_challenge(
    State(st): State<AppState>,
    Json(req): Json<AcmeChallengeReq>,
) -> Result<Json<AcmeChallengeResp>, ApiError> {
    let Some(dns) = st.dns.as_ref() else {
        return Err(ApiError::new(
            StatusCode::NOT_IMPLEMENTED,
            "this deployment issues no certificates ([dns] is not configured)",
        ));
    };

    let (user_id, pubkey) = st
        .store
        .device_by_token(&req.token)
        .await
        .map_err(internal)?
        .ok_or_else(|| ApiError::new(StatusCode::UNAUTHORIZED, "invalid device token"))?;

    // Both names come from the device's own rows. A device that has never completed a register has
    // no allocated label and no name to be validated for, so it is refused rather than allocated one
    // here — allocation belongs on the path that consulted the role source.
    let Some(username) = st
        .store
        .allocated_user_label(user_id)
        .await
        .map_err(internal)?
    else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "this device has no mesh identity yet; register before requesting a certificate",
        ));
    };
    let Some(device_name) = st.store.device_name_of(&pubkey).await.map_err(internal)? else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "this device has no mesh identity yet; register before requesting a certificate",
        ));
    };

    if req.device.is_empty() || req.device.len() > common::api::MAX_DEVICE_CHALLENGES {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "a certificate order raises one or two challenges for a device's own name",
        ));
    }

    // One name, possibly two values: the certificate covers `<device>.<user>` and its wildcard, and
    // a wildcard authorization validates at the same `_acme-challenge` name as the base one.
    let device_challenge = challenge_name(&format!("{device_name}.{username}"), &dns.domain);
    let mut records: Vec<_> = req
        .device
        .iter()
        .map(|value| (device_challenge.clone(), value.clone()))
        .collect();

    // The bare `<user>` alias is the primary device's alone, so a non-primary device asking for it
    // is ignored rather than honoured — otherwise any of an owner's devices could hold a certificate
    // for the name that is supposed to identify one of them.
    if let Some(value) = &req.primary {
        let is_primary = st
            .store
            .primary_pubkey(user_id)
            .await
            .map_err(internal)?
            .is_some_and(|p| p == pubkey);
        if is_primary {
            records.push((challenge_name(&username, &dns.domain), value.clone()));
        }
    }

    dns.challenges
        .publish(&records)
        .map_err(|e| ApiError::new(StatusCode::TOO_MANY_REQUESTS, e.to_string()))?;

    // Distinct names, not one per record: the device's two values share a name, and the client is
    // checking which names were published, not how many values sit under each.
    let mut names: Vec<String> = Vec::new();
    for (name, _) in records {
        if !names.contains(&name) {
            names.push(name);
        }
    }
    Ok(Json(AcmeChallengeResp { names }))
}

/// `_acme-challenge.<name>.<domain>`, lower-case and without a trailing dot — the key form
/// [`crate::zone`] looks up.
fn challenge_name(name: &str, domain: &str) -> String {
    format!("_acme-challenge.{name}.{domain}").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_names_are_lowercase_and_unrooted() {
        assert_eq!(
            challenge_name("laptop.gordon", "mesh.example.com"),
            "_acme-challenge.laptop.gordon.mesh.example.com"
        );
        assert_eq!(
            challenge_name("Laptop.Gordon", "Mesh.Example.COM"),
            "_acme-challenge.laptop.gordon.mesh.example.com"
        );
    }
}
