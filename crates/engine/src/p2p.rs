//! Peer-direct attestation refresh (`docs/gossip-refresh.md`, stage 1: serve-own).
//!
//! We **serve** our own coordinator-minted attestations to meshed co-members over the WG tunnel, so
//! the mesh can keep credentials fresh without the coordinator fanning them out. Single-hop and
//! authoritative: a device only ever hands out its *own* attestations, which the asker verifies
//! against its pinned anchor exactly as on the coordinator path — so a peer can't forge or substitute
//! one. Reachable only through the tunnel (co-members), so the channel is already authenticated; the
//! coordinator stays the always-present fallback. Stage 2 adds the peer-direct *pull* + fallback that
//! consumes this endpoint.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use common::api::GuildAttestation;
use common::p2p::{P2pRequest, P2pResponse, ReqBody, RespBody, P2P_MAX_DATAGRAM};
use common::service::MeshService;
use tokio::net::UdpSocket;

/// This device's own current attestations (its coordinator grant), refreshed each register/refresh.
/// Shared with the serve loop so a pull always gets the freshest blobs.
#[derive(Clone, Default)]
pub struct OwnAttestations(Arc<Mutex<Vec<GuildAttestation>>>);

impl OwnAttestations {
    pub fn set(&self, atts: Vec<GuildAttestation>) {
        *self.0.lock().unwrap() = atts;
    }
    fn get(&self) -> Vec<GuildAttestation> {
        self.0.lock().unwrap().clone()
    }
}

/// Where the serve loop gets the services to announce. Implemented by [`crate::fw::Firewall`],
/// which is the one place that knows both what is named and who its scope admits — so a peer that
/// cannot reach a port cannot learn its name either.
pub trait ServiceSource: Send + Sync {
    /// The services this address may reach.
    fn services_for(&self, peer: std::net::Ipv4Addr) -> Vec<MeshService>;
}

/// Serve-side handle to [`ServiceSource`]. `None` before the firewall exists (early startup), which
/// answers an empty list rather than failing — a device with nothing to announce is normal.
#[derive(Clone, Default)]
pub struct OwnServices(Option<Arc<dyn ServiceSource>>);

impl OwnServices {
    pub fn new(source: Arc<dyn ServiceSource>) -> Self {
        Self(Some(source))
    }
    fn visible_to(&self, peer: SocketAddr) -> Vec<MeshService> {
        let SocketAddr::V4(v4) = peer else {
            return Vec::new();
        };
        self.0
            .as_ref()
            .map(|s| s.services_for(*v4.ip()))
            .unwrap_or_default()
    }
}

/// Answer P2P requests on an already-bound socket until the task is dropped (the daemon binds this
/// device's own mesh `/32` — known only after register — so it controls the address). Malformed
/// datagrams are ignored; a request type we don't recognize is answered `Unsupported`.
pub async fn serve(
    sock: UdpSocket,
    own: OwnAttestations,
    services: OwnServices,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; P2P_MAX_DATAGRAM];
    loop {
        // A `recv_from` error here is transient, not fatal: on Linux a prior `send_to` to a peer that
        // has no listener elicits an ICMP port-unreachable, delivered as an error on the *next* socket
        // op. Propagating it would tear down the whole serve loop, killing peer-direct refresh until
        // the engine restarts — so log and keep serving, like the DNS responder (`dns.rs`).
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("p2p recv: {e}");
                continue;
            }
        };
        let body = match serde_json::from_slice::<P2pRequest>(&buf[..n]) {
            // A peer outside our support window gets a clean `Unsupported` (→ it falls back to the
            // coordinator) rather than a reply it may misread. `proto == 0` predates the envelope.
            Ok(req)
                if req.proto != 0
                    && !(common::MIN_PROTOCOL_VERSION..=common::PROTOCOL_VERSION)
                        .contains(&req.proto) =>
            {
                tracing::debug!(
                    peer_proto = req.proto,
                    "p2p request outside our version window"
                );
                RespBody::Unsupported
            }
            Ok(req) => match req.body {
                ReqBody::GetAttestations => RespBody::Attestations {
                    attestations: own.get(),
                },
                // Scoped to the *asker's* address, which is the source address of this datagram.
                // Spoofable in general, but this socket is bound to our mesh `/32` and reachable
                // only through the tunnel, so an address that arrives here was crypto-routed by
                // WireGuard from the peer that owns it.
                ReqBody::GetServices => RespBody::Services {
                    services: services.visible_to(from),
                },
                ReqBody::Unknown => RespBody::Unsupported,
            },
            Err(_) => continue, // not a P2P request we can parse → stay silent
        };
        let resp = P2pResponse {
            proto: common::PROTOCOL_VERSION,
            body,
        };
        if let Ok(bytes) = serde_json::to_vec(&resp) {
            let _ = sock.send_to(&bytes, from).await;
        }
    }
}

/// Pull a peer's own current attestations directly over the tunnel. Returns the raw blobs; the caller
/// verifies them against the pinned anchor (the same gate as the coordinator path), so this
/// establishes no trust on its own. Bounded by `timeout` so a silent or older peer falls back to the
/// coordinator quickly.
pub async fn pull(target: SocketAddr, timeout: Duration) -> anyhow::Result<Vec<GuildAttestation>> {
    match ask(target, ReqBody::GetAttestations, timeout).await? {
        RespBody::Attestations { attestations } => Ok(attestations),
        other => Err(unexpected(other, "attestation pull")),
    }
}

/// Ask a peer which of its services we may reach. The labels are the peer's; the *names* they
/// resolve as are composed by the caller under the peer's verified user label, so nothing here
/// establishes a name on its own.
///
/// A peer that predates services answers `Unsupported`, which is an empty service list rather than
/// an error worth surfacing — services are additive, and an older peer simply has none to announce.
pub async fn pull_services(
    target: SocketAddr,
    timeout: Duration,
) -> anyhow::Result<Vec<MeshService>> {
    match ask(target, ReqBody::GetServices, timeout).await? {
        RespBody::Services { mut services } => {
            // A peer's list is peer-supplied: bound it before it reaches our maps, and drop the
            // entries we could never resolve rather than the whole reply — one bad label must cost
            // that label, not the peer's other services.
            services.retain(|s| common::service::valid_label(&s.name));
            services.truncate(common::service::MAX_SERVICES_PER_DEVICE);
            Ok(services)
        }
        RespBody::Unsupported => Ok(Vec::new()),
        other => Err(unexpected(other, "service pull")),
    }
}

fn unexpected(body: RespBody, what: &str) -> anyhow::Error {
    match body {
        RespBody::Unsupported => anyhow::anyhow!("peer does not support {what}"),
        // A newer peer answered with something this build has no variant for. Not an error worth
        // escalating — the coordinator path covers it.
        _ => anyhow::anyhow!("peer replied with an unrecognized p2p response type"),
    }
}

/// One request/response over an ephemeral socket, bounded by `timeout` so a silent or older peer
/// falls back quickly.
async fn ask(target: SocketAddr, body: ReqBody, timeout: Duration) -> anyhow::Result<RespBody> {
    let bind: SocketAddr = if target.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await.context("p2p client bind")?;
    let req = P2pRequest {
        proto: common::PROTOCOL_VERSION,
        body,
    };
    sock.send_to(&serde_json::to_vec(&req)?, target)
        .await
        .context("p2p send")?;
    let mut buf = vec![0u8; P2P_MAX_DATAGRAM];
    let (n, _) = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
        .await
        .context("p2p pull timed out")?
        .context("p2p recv")?;
    Ok(serde_json::from_slice::<P2pResponse>(&buf[..n])
        .context("decoding p2p response")?
        .body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ga(blob: &str) -> GuildAttestation {
        GuildAttestation {
            attestation: blob.into(),
            community_name: "c".into(),
            att_schema: common::attestation::ATTESTATION_SCHEMA_V1,
        }
    }

    async fn round_trip(client: &UdpSocket, to: std::net::SocketAddr, req: &[u8]) -> P2pResponse {
        client.send_to(req, to).await.unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("no p2p reply")
            .unwrap();
        serde_json::from_slice(&buf[..n]).unwrap()
    }

    #[tokio::test]
    async fn serves_own_attestations_and_reflects_refreshes() {
        let own = OwnAttestations::default();
        own.set(vec![ga("blobA"), ga("blobB")]);
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(serve(sock, own.clone(), OwnServices::default()));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let req = format!(
            r#"{{"proto":{},"body":{{"type":"GetAttestations"}}}}"#,
            common::PROTOCOL_VERSION
        );
        let req = req.as_bytes();
        match round_trip(&client, addr, req).await.body {
            RespBody::Attestations { attestations: a } => {
                assert_eq!(a.len(), 2);
                assert_eq!(a[0].attestation, "blobA");
            }
            other => panic!("expected attestations, got {other:?}"),
        }

        // A later grant is served on the next request (no restart).
        own.set(vec![ga("blobC")]);
        match round_trip(&client, addr, req).await.body {
            RespBody::Attestations { attestations: a } => assert_eq!(a[0].attestation, "blobC"),
            other => panic!("expected refreshed attestations, got {other:?}"),
        }
    }

    /// Announcements are per-asker: the source address of the request decides what comes back, so
    /// a peer outside a service's scope is told nothing rather than told-and-denied.
    #[tokio::test]
    async fn services_are_announced_per_asker() {
        struct OnlyLoopbackFive;
        impl ServiceSource for OnlyLoopbackFive {
            fn services_for(&self, peer: std::net::Ipv4Addr) -> Vec<MeshService> {
                if peer == std::net::Ipv4Addr::LOCALHOST {
                    vec![MeshService {
                        name: "mc".into(),
                        proto: common::control::Proto::Tcp,
                        port: 25565,
                    }]
                } else {
                    Vec::new()
                }
            }
        }

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(serve(
            sock,
            OwnAttestations::default(),
            OwnServices::new(Arc::new(OnlyLoopbackFive)),
        ));

        let got = pull_services(addr, Duration::from_secs(2)).await.unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].name, "mc");
        assert_eq!(got[0].port, 25565);
    }

    /// A peer's list is peer-supplied data: a label we could never resolve costs that label, not
    /// the rest of the reply, and the count is bounded before it reaches our maps.
    #[tokio::test]
    async fn a_peers_unusable_labels_are_dropped_without_losing_the_rest() {
        struct Hostile;
        impl ServiceSource for Hostile {
            fn services_for(&self, _: std::net::Ipv4Addr) -> Vec<MeshService> {
                let mut out = vec![MeshService {
                    name: "../etc/passwd".into(), // not a label at all
                    proto: common::control::Proto::Tcp,
                    port: 1,
                }];
                out.push(MeshService {
                    name: "good".into(),
                    proto: common::control::Proto::Tcp,
                    port: 2,
                });
                out.extend((0..64).map(|i| MeshService {
                    name: format!("flood{i}"),
                    proto: common::control::Proto::Tcp,
                    port: 3,
                }));
                out
            }
        }

        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(serve(
            sock,
            OwnAttestations::default(),
            OwnServices::new(Arc::new(Hostile)),
        ));

        let got = pull_services(addr, Duration::from_secs(2)).await.unwrap();
        assert!(got.iter().all(|s| common::service::valid_label(&s.name)));
        assert!(
            got.iter().any(|s| s.name == "good"),
            "the usable one survives"
        );
        assert!(got.len() <= common::service::MAX_SERVICES_PER_DEVICE);
    }

    /// A peer that predates services answers `Unsupported`, which is "no services" — not an error
    /// the caller has to special-case, since services are additive.
    #[tokio::test]
    async fn an_older_peer_reports_no_services_rather_than_failing() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        // No `ServiceSource` at all is the early-startup shape; an older peer answers `Unsupported`
        // for the same reason — neither is a failure.
        tokio::spawn(serve(
            sock,
            OwnAttestations::default(),
            OwnServices::default(),
        ));
        assert!(pull_services(addr, Duration::from_secs(2))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn unknown_request_type_gets_unsupported() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(serve(
            sock,
            OwnAttestations::default(),
            OwnServices::default(),
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // A body tag this build doesn't know → #[serde(other)] Unknown → Unsupported.
        let raw = format!(
            r#"{{"proto":{},"body":{{"type":"SomeFutureType"}}}}"#,
            common::PROTOCOL_VERSION
        );
        assert!(matches!(
            round_trip(&client, addr, raw.as_bytes()).await.body,
            RespBody::Unsupported
        ));
    }

    /// The mirror of the above: a *newer* peer's response variant must decode to `Unknown` rather
    /// than failing outright, so the older side of a mixed mesh degrades to the coordinator instead
    /// of erroring. Decode-level, since the wire is what has to tolerate it.
    #[test]
    fn unknown_response_type_decodes_as_unknown() {
        let raw = format!(
            r#"{{"proto":{},"body":{{"type":"SomeFutureReply","data":[1,2,3]}}}}"#,
            common::PROTOCOL_VERSION
        );
        let resp: P2pResponse = serde_json::from_slice(raw.as_bytes()).unwrap();
        assert!(matches!(resp.body, RespBody::Unknown));
    }

    #[tokio::test]
    async fn peer_outside_our_version_window_gets_unsupported() {
        let own = OwnAttestations::default();
        own.set(vec![ga("blobA")]);
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(serve(sock, own, OwnServices::default()));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // A peer far below our floor: answered, but not with attestations it might misread.
        let raw = r#"{"proto":1,"body":{"type":"GetAttestations"}}"#;
        assert!(matches!(
            round_trip(&client, addr, raw.as_bytes()).await.body,
            RespBody::Unsupported
        ));

        // …while a peer inside the window is served normally.
        let ok = format!(
            r#"{{"proto":{},"body":{{"type":"GetAttestations"}}}}"#,
            common::MIN_PROTOCOL_VERSION
        );
        assert!(matches!(
            round_trip(&client, addr, ok.as_bytes()).await.body,
            RespBody::Attestations { .. }
        ));
    }
}
