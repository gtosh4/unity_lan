//! Who is calling, and may they act as this device?
//!
//! Two distinct gates, and the split matters. An **already-enrolled** register authenticates with
//! the device bearer token — a WireGuard public key is not a secret (it rides in every co-member's
//! seed), so possession of one proves nothing. An **enrolling** register instead proves possession
//! of the private key behind the pubkey it's binding, so a party who merely learned an unbound
//! pubkey can't claim it under their own account.

use axum::http::StatusCode;
use common::api::RegisterReq;

use super::{internal, ApiError, AppState};

/// Resolve the caller's user id, plus whether the device was **already enrolled** (resolved by its
/// pubkey binding alone). `device_owner` is checked first, so a `true` flag means the device row
/// already existed; `false` means this register is the one that binds the pubkey (via OAuth binding
/// or a one-time enrollment key) and freshly mints the device row. Callers use the flag to gate the
/// one-time `device_token` delivery — see [`super::snapshot::build_snapshot`].
pub(super) async fn resolve_user(
    st: &AppState,
    req: &RegisterReq,
) -> Result<(u64, bool), ApiError> {
    if let Some(uid) = st
        .store
        .device_owner(&req.wg_pubkey)
        .await
        .map_err(internal)?
    {
        authenticate_enrolled(st, req).await?;
        return Ok((uid, true));
    }
    if let Some(uid) = st
        .store
        .oauth_user(&req.wg_pubkey)
        .await
        .map_err(internal)?
    {
        verify_possession(st, req)?;
        return Ok((uid, false));
    }
    let Some(key) = req.enrollment_key.as_deref() else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "device not enrolled; log in (oauth) or provide an enrollment_key",
        ));
    };
    verify_possession(st, req)?;
    let uid = st
        .store
        .consume_enrollment_key(key, &req.wg_pubkey, common::now_unix())
        .await
        .map_err(|e| ApiError::new(StatusCode::UNAUTHORIZED, e.to_string()))?;
    Ok((uid, false))
}

/// Device-auth decision for an already-enrolled register/refresh. Only the bearer token admits the
/// request; a public WireGuard key and legacy tokenless rows fail closed.
fn decide_device_auth(stored: Option<&str>, presented: Option<&str>) -> AuthOutcome {
    let valid = matches!((stored, presented), (Some(s), Some(p)) if common::crypto::ct_eq(s.as_bytes(), p.as_bytes()));
    if valid {
        AuthOutcome::Admit
    } else {
        AuthOutcome::Reject
    }
}

enum AuthOutcome {
    Admit,
    Reject,
}

/// Enforce device-bearer auth on every already-enrolled register/refresh.
/// Without it, anyone who learned a victim's WG pubkey — which rides in every co-member's seed —
/// could pull the victim's snapshot and forge its presence/endpoint/relay/ICE state.
async fn authenticate_enrolled(st: &AppState, req: &RegisterReq) -> Result<(), ApiError> {
    // The row can vanish between `device_owner` and here (concurrent remove); treat that as
    // not-our-concern and let the rebuild handle it, rather than 401-ing a benign race.
    let Some(stored) = st
        .store
        .device_auth(&req.wg_pubkey)
        .await
        .map_err(internal)?
    else {
        return Ok(());
    };
    match decide_device_auth(stored.as_deref(), req.device_token.as_deref()) {
        AuthOutcome::Admit => Ok(()),
        AuthOutcome::Reject => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "device token missing or invalid",
        )),
    }
}

/// Gate an *enrolling* register (one about to mint a fresh device row) on a DH proof that the caller
/// holds the WG private key behind `wg_pubkey` — so a party who only learned a not-yet-enrolled pubkey
/// can't bind it under their own account. Called from [`resolve_user`]'s enrolling branches only;
/// already-enrolled registers authenticate by `device_token` (see [`authenticate_enrolled`]) instead.
///
/// A **present** proof is always verified — a malformed one is a `401` in both modes (a wrong proof is
/// never merely an old client). A **missing** proof depends on policy: rejected under `require_proof`
/// (the default since the fleet passed the release that started sending one), else admitted with a
/// warning and a counter bump, for a deployment still enrolling from pre-v0.4.1 engines.
fn verify_possession(st: &AppState, req: &RegisterReq) -> Result<(), ApiError> {
    use std::sync::atomic::Ordering;
    let valid = req
        .possession_proof
        .map(|p| common::crypto::verify_enroll_proof(&st.enroll_secret, &req.wg_pubkey, &p));
    match decide_possession(valid, st.require_enroll_proof) {
        PossessionOutcome::Proven => {
            st.enroll_proven.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        PossessionOutcome::Unproven => {
            st.enroll_unproven.fetch_add(1, Ordering::Relaxed);
            let pubkey: String = req.wg_pubkey.iter().map(|b| format!("{b:02x}")).collect();
            tracing::warn!(
                %pubkey,
                "enrolling device without a possession proof (admitted: [enrollment] require_proof is off)"
            );
            Ok(())
        }
        PossessionOutcome::RejectInvalid => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "enrollment possession proof invalid",
        )),
        PossessionOutcome::RejectMissing => Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "enrollment requires a possession proof; update the client",
        )),
    }
}

enum PossessionOutcome {
    /// A valid proof was presented.
    Proven,
    /// No proof, admitted under observe-only mode (counted + logged).
    Unproven,
    /// A proof was presented but did not verify — rejected in **both** modes (a wrong proof is never
    /// merely an old client).
    RejectInvalid,
    /// No proof under `require_proof` — rejected.
    RejectMissing,
}

/// The enrollment possession-proof policy, factored out for testing. `valid` is `None` when the
/// client sent no proof, `Some(true|false)` when it sent one that did|didn't verify. A malformed
/// proof always rejects; a missing proof rejects only when `require` is set.
fn decide_possession(valid: Option<bool>, require: bool) -> PossessionOutcome {
    match (valid, require) {
        (Some(true), _) => PossessionOutcome::Proven,
        (Some(false), _) => PossessionOutcome::RejectInvalid,
        (None, true) => PossessionOutcome::RejectMissing,
        (None, false) => PossessionOutcome::Unproven,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn possession_policy_rejects_bad_proof_in_both_modes_missing_only_when_required() {
        use PossessionOutcome::*;
        // A valid proof always enrolls.
        assert!(matches!(decide_possession(Some(true), false), Proven));
        assert!(matches!(decide_possession(Some(true), true), Proven));
        // A malformed proof is rejected regardless of mode — never treated as "just an old client".
        assert!(matches!(
            decide_possession(Some(false), false),
            RejectInvalid
        ));
        assert!(matches!(
            decide_possession(Some(false), true),
            RejectInvalid
        ));
        // A missing proof is admitted (observe-only) unless enforcement is on.
        assert!(matches!(decide_possession(None, false), Unproven));
        assert!(matches!(decide_possession(None, true), RejectMissing));
    }

    #[test]
    fn device_auth_always_requires_the_bearer_token() {
        let admit = |o| matches!(o, AuthOutcome::Admit);
        let rejects = |o| matches!(o, AuthOutcome::Reject);

        // A correct bearer token admits the enrolled device.
        assert!(admit(decide_device_auth(Some("tok"), Some("tok"))));

        // Wrong, absent, and legacy missing tokens all fail closed. A public WG key is never auth.
        assert!(rejects(decide_device_auth(Some("tok"), Some("wrong"))));
        assert!(rejects(decide_device_auth(Some("tok"), None)));
        assert!(rejects(decide_device_auth(None, Some("anything"))));
    }
}
