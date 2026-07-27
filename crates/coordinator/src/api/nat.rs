//! NAT-traversal brokering: the peer-keyed state clients publish *about each other*, and the punch
//! and relay targets handed back in a snapshot (design.md §7.2).
//!
//! The coordinator only exchanges this — it never runs ICE, never allocates a relay, and never sees
//! a packet of the resulting path. Two trust rules run through everything here: a caller may publish
//! state only about a peer it actually meshes with, and a reported address is believed only when it
//! agrees with where the coordinator itself saw that peer connect from.

use std::collections::{HashMap, HashSet};

use axum::http::StatusCode;
use common::api::{ObservedEndpoint, RegisterReq, SharedNetwork};

use super::{ApiError, AppState, RelayReg};

/// Record the peer-keyed reports this device sent — reflexive sightings (a co-member's NAT mapping
/// seen from the outside, for hole punching), TURN relayed addresses, and ICE session offers — plus
/// record/clear the device's own relay capability. Every peer-keyed entry is accepted **only** for a
/// `comembers` pubkey: the caller may publish state only *about a peer it actually meshes with*, which
/// is the trust boundary that keeps these tables bounded (an authenticated member otherwise could
/// inject entries for arbitrary pubkeys and force wakes for them). A first sighting or a change wakes
/// just that one target (`wake_targets`) rather than bumping a whole membership scope — a NAT-traversal
/// exchange doesn't wake a guild for a change only the one target cares about.
pub(super) fn record_peer_reports(
    st: &AppState,
    req: &RegisterReq,
    comembers: &HashSet<[u8; 32]>,
    wake_targets: &mut HashSet<[u8; 32]>,
) {
    {
        // Lock order: source_ip before reflexive (the only site holding both). A reflexive is
        // accepted only when the reporter is a co-member *and* the reported address matches where the
        // reported device actually connects from (see `accepted_reflexives`).
        let src = st.source_ip.lock().unwrap();
        let mut refl = st.reflexive.lock().unwrap();
        for obs in accepted_reflexives(&req.observed, comembers, &src) {
            if refl.get(&obs.pubkey) != Some(&obs.endpoint) {
                refl.insert(obs.pubkey, obs.endpoint);
                wake_targets.insert(obs.pubkey);
            }
        }
    }

    // This device's own relay capability: an opted-in, directly-dialable co-member that runs an
    // embedded TURN server for stuck pairs. Not a membership change, so it deliberately doesn't bump
    // the version (a new relay must not wake the whole herd — a stuck peer re-polls on its own cadence
    // and picks it up). Cleared when the device stops advertising.
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

    // TURN relayed addresses (relayed-candidate exchange). A new/changed relayed address wakes that
    // one peer so it learns it as its `peer_relayed` — the second half of the ~2-round relay converge.
    {
        let mut allocs = st.relay_allocs.lock().unwrap();
        for a in &req.relay_allocated {
            if !comembers.contains(&a.peer) {
                continue;
            }
            if allocs.get(&(req.wg_pubkey, a.peer)) != Some(&a.relayed) {
                allocs.insert((req.wg_pubkey, a.peer), a.relayed);
                wake_targets.insert(a.peer);
            }
        }
    }

    // ICE session offers (candidate exchange, M5.5). A new/changed offer (fresh candidates, or an ICE
    // restart's new ufrag/pwd) wakes that one peer so it picks up the candidates as its `Seed::ice` and
    // runs connectivity checks — a targeted ping-pong rather than a herd wake. The coordinator only
    // relays; it never runs ICE.
    {
        let mut ice = st.ice.lock().unwrap();
        for e in &req.ice {
            if !comembers.contains(&e.peer) {
                continue;
            }
            if ice.get(&(req.wg_pubkey, e.peer)) != Some(&e.params) {
                ice.insert((req.wg_pubkey, e.peer), e.params.clone());
                wake_targets.insert(e.peer);
            }
        }
    }
}

const MAX_PEER_REPORTS: usize = 256;
const MAX_ICE_REPORTS: usize = 128;
const MAX_ICE_CANDIDATES: usize = 16;
const MAX_ICE_CREDENTIAL_BYTES: usize = 256;
const MAX_ICE_CANDIDATE_BYTES: usize = 512;
const MAX_RELAY_SECRET_BYTES: usize = 256;

/// Bound all attacker-controlled collections and strings before cloning them into persistent NAT
/// tables. The HTTP body cap alone is insufficient because reports accumulate across requests.
pub(super) fn validate_peer_reports(req: &RegisterReq) -> Result<(), ApiError> {
    let bad = |m| ApiError::new(StatusCode::BAD_REQUEST, m);
    if req.observed.len() > MAX_PEER_REPORTS
        || req.need_relay.len() > MAX_PEER_REPORTS
        || req.relay_allocated.len() > MAX_PEER_REPORTS
    {
        return Err(bad("too many peer reports"));
    }
    if req.ice.len() > MAX_ICE_REPORTS {
        return Err(bad("too many ICE reports"));
    }
    if req
        .relay_secret
        .as_ref()
        .is_some_and(|s| s.len() > MAX_RELAY_SECRET_BYTES)
    {
        return Err(bad("relay secret is too long"));
    }
    for e in &req.ice {
        if e.params.ufrag.len() > MAX_ICE_CREDENTIAL_BYTES
            || e.params.pwd.len() > MAX_ICE_CREDENTIAL_BYTES
            || e.params.candidates.len() > MAX_ICE_CANDIDATES
            || e.params
                .candidates
                .iter()
                .any(|c| c.len() > MAX_ICE_CANDIDATE_BYTES)
        {
            return Err(bad("ICE parameters exceed the allowed limits"));
        }
    }
    Ok(())
}

/// The hole-punch target to hand a caller for one peer (§7.2): the peer's reflexive address, but
/// only when *neither* side is directly dialable. If either the caller or the peer has a dialable
/// endpoint, that side is reached directly (via the seed `endpoint`) and no punch is needed.
pub(super) fn punch_target(
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
pub(super) fn relay_target(
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

/// Peer-observed reflexives the caller may legitimately report. Two independent gates:
/// 1. **Co-membership** — you can only observe a peer's reflexive across a tunnel you share, so the
///    reported pubkey must be one of the caller's co-members (`comembers`).
/// 2. **Source-IP correlation** — the reported reflexive IP must equal the IP the coordinator itself
///    saw that peer connect from (`source_ip[pubkey]`, recorded on the peer's own register). A NAT'd
///    peer egresses from one address, so its coordinator source IP and the reflexive its peers
///    observe share that IP; a co-member that *invents* a reflexive can't make the victim's own
///    traffic appear to originate there, so a mismatched (attacker-chosen) address is dropped. This
///    is what stops a co-member redirecting a NAT'd peer's punch target to an arbitrary host (an
///    SSRF/DoS lever). The port may differ (symmetric NAT), so only the IP is correlated. A peer we
///    haven't seen register yet has no `source_ip` entry and its reports are held until it does.
pub(super) fn accepted_reflexives<'a>(
    observed: &'a [ObservedEndpoint],
    comembers: &'a HashSet<[u8; 32]>,
    source_ip: &'a HashMap<[u8; 32], std::net::IpAddr>,
) -> impl Iterator<Item = &'a ObservedEndpoint> {
    observed.iter().filter(move |o| {
        comembers.contains(&o.pubkey) && source_ip.get(&o.pubkey) == Some(&o.endpoint.ip())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::testsupport::{addr, req_speaking};
    use common::api::{IceEndpoint, IceParams};

    fn reg(s: &str) -> RelayReg {
        RelayReg {
            addr: addr(s),
            secret: "sekret".into(),
        }
    }

    #[test]
    fn peer_report_sizes_fail_closed() {
        let mut req = req_speaking(r#""proto":5,"proto_min":4"#);
        req.relay_secret = Some("x".repeat(MAX_RELAY_SECRET_BYTES + 1));
        assert_eq!(
            validate_peer_reports(&req).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );

        req.relay_secret = None;
        req.ice.push(IceEndpoint {
            peer: [1; 32],
            params: IceParams {
                ufrag: "u".into(),
                pwd: "p".into(),
                candidates: vec!["x".repeat(MAX_ICE_CANDIDATE_BYTES + 1)],
            },
        });
        assert_eq!(
            validate_peer_reports(&req).unwrap_err().status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn relay_target_picks_shared_network_lowest_pubkey_third_party() {
        let net = |name: &str| SharedNetwork {
            name: name.into(),
            community: "c".into(),
            guild_id: 1,
            role_id: 2,
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
        let comembers = HashSet::from([comember]);
        // The observed peer's coordinator-seen source IP matches the reported reflexive IP.
        let source_ip = HashMap::from([
            (comember, addr("203.0.113.5:51820").ip()),
            (stranger, addr("203.0.113.9:51820").ip()),
        ]);

        let accepted: Vec<_> = accepted_reflexives(&observed, &comembers, &source_ip).collect();
        assert_eq!(accepted.len(), 1, "only the co-member's report is accepted");
        assert_eq!(accepted[0].pubkey, comember);

        // With no co-members, every report is rejected.
        let none = HashSet::new();
        assert_eq!(accepted_reflexives(&observed, &none, &source_ip).count(), 0);
    }

    #[test]
    fn reflexive_report_rejects_ip_the_peer_did_not_connect_from() {
        let peer = [1u8; 32];
        let comembers = HashSet::from([peer]);
        // The peer actually connects to the coordinator from 198.51.100.4.
        let source_ip = HashMap::from([(peer, addr("198.51.100.4:9999").ip())]);

        // A co-member invents a different reflexive address for the peer → rejected (it isn't where
        // the peer's own traffic originates), so the punch target can't be redirected.
        let forged = vec![ObservedEndpoint {
            pubkey: peer,
            endpoint: addr("203.0.113.7:51820"),
        }];
        assert_eq!(
            accepted_reflexives(&forged, &comembers, &source_ip).count(),
            0
        );

        // A report whose IP matches the peer's source IP is accepted (the port may differ under
        // symmetric NAT — only the IP is correlated).
        let genuine = vec![ObservedEndpoint {
            pubkey: peer,
            endpoint: addr("198.51.100.4:41000"),
        }];
        assert_eq!(
            accepted_reflexives(&genuine, &comembers, &source_ip).count(),
            1
        );

        // A peer the coordinator has never seen register has no source_ip entry → held (rejected).
        let empty = HashMap::new();
        assert_eq!(accepted_reflexives(&genuine, &comembers, &empty).count(), 0);
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
