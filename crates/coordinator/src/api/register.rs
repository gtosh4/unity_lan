//! `POST /register` and `/refresh` — the one route the whole mesh lives on.
//!
//! The two paths are identical: build the caller's snapshot, and if nothing has changed for it,
//! park the request until something does (or the hold elapses) and rebuild. Everything expensive
//! happens in [`super::snapshot`]; what lives here is the decision of whether to answer now or hold,
//! which is what keeps a deployment's request rate proportional to *changes* rather than to clients.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use common::api::{RegisterReq, RegisterResp};

use super::snapshot::{build_snapshot, Built};
use super::wake::{wait_park, wake_jitter, Woke};
use super::{ratelimit, ApiError, AppState};

/// `POST /register` | `/refresh`: record presence + return the caller's grant and seeds.
///
/// Long-poll: build the snapshot once; if the client is already up to date (`since` == current
/// version) hold the request until membership changes or the hold elapses, then rebuild (fresh,
/// re-signed attestations — the renewal path). `since = None`/stale returns immediately.
pub(super) async fn register(
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
    // targets us while we build (or decide to park) isn't lost. `woken_while_away` covers the much
    // larger window either side of that: a wake fired while this device had no request in flight,
    // which the snapshot below therefore already reflects.
    let (mut personal, woken_while_away) = st.wakers.subscribe(req.wg_pubkey);
    let built = build_snapshot(&st, &req, caller_ip).await?;
    // Park only when the client is up to date, its own request changed nothing, and nothing was
    // published *about* it while it was away. A request that reports data (reflexive/relay/ICE)
    // returns immediately so the client can continue its report loop — exactly as the old global
    // bump made it — but now without waking the herd; the affected peer is woken by a targeted wake
    // instead, and picks it up here whether or not it happened to be parked when that fired.
    if !built.caller_changed && !woken_while_away && req.since == Some(built.resp.version) {
        // Displaces this device's own earlier park, if any — a client that abandoned a held request
        // (report to send, restart, crash) must not have to wait out the old one. Only the
        // deployment-wide ceiling refuses.
        let mut park_permit = st.park_slots.try_acquire(req.wg_pubkey).ok_or_else(|| {
            ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "the coordinator is at its long-poll capacity; retry shortly",
            )
        })?;
        // Free the snapshot *before* parking. We hold this request for minutes and rebuild on wake
        // anyway, so keeping its `seeds` alive would pin one full peer list per parked client —
        // O(clients × peers) bytes across the deployment, for data we already decided not to send.
        // Measured on a 3000-device guild: 8.3 GB parked before this drop, 82 MB after.
        let Built { resp, scopes, .. } = built;
        let version = resp.version;
        drop(resp);
        let woke = wait_park(
            &st,
            &scopes,
            version,
            &mut personal,
            park_permit.preempted(),
        )
        .await;
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
pub(super) fn negotiate(req: &RegisterReq) -> Result<u32, ApiError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::testsupport::req_speaking;

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
}
