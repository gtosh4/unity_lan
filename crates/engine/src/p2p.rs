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

/// Answer P2P requests on an already-bound socket until the task is dropped (the daemon binds this
/// device's own mesh `/32` — known only after register — so it controls the address). Malformed
/// datagrams are ignored; a request type we don't recognize is answered `Unsupported`.
pub async fn serve(sock: UdpSocket, own: OwnAttestations) -> anyhow::Result<()> {
    let mut buf = vec![0u8; P2P_MAX_DATAGRAM];
    loop {
        let (n, from) = sock.recv_from(&mut buf).await.context("p2p recv")?;
        let body = match serde_json::from_slice::<P2pRequest>(&buf[..n]) {
            Ok(req) => match req.body {
                ReqBody::GetAttestations => RespBody::Attestations(own.get()),
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
    let bind: SocketAddr = if target.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await.context("p2p client bind")?;
    let req = P2pRequest {
        proto: common::PROTOCOL_VERSION,
        body: ReqBody::GetAttestations,
    };
    sock.send_to(&serde_json::to_vec(&req)?, target)
        .await
        .context("p2p send")?;
    let mut buf = vec![0u8; P2P_MAX_DATAGRAM];
    let (n, _) = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
        .await
        .context("p2p pull timed out")?
        .context("p2p recv")?;
    match serde_json::from_slice::<P2pResponse>(&buf[..n])
        .context("decoding p2p response")?
        .body
    {
        RespBody::Attestations(a) => Ok(a),
        RespBody::Unsupported => anyhow::bail!("peer does not support attestation pull"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn ga(blob: &str) -> GuildAttestation {
        GuildAttestation {
            attestation: blob.into(),
            community_name: "c".into(),
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
        tokio::spawn(serve(sock, own.clone()));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let req = br#"{"proto":3,"body":{"type":"GetAttestations"}}"#;
        match round_trip(&client, addr, req).await.body {
            RespBody::Attestations(a) => {
                assert_eq!(a.len(), 2);
                assert_eq!(a[0].attestation, "blobA");
            }
            other => panic!("expected attestations, got {other:?}"),
        }

        // A later grant is served on the next request (no restart).
        own.set(vec![ga("blobC")]);
        match round_trip(&client, addr, req).await.body {
            RespBody::Attestations(a) => assert_eq!(a[0].attestation, "blobC"),
            other => panic!("expected refreshed attestations, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_request_type_gets_unsupported() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(serve(sock, OwnAttestations::default()));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // A body tag this build doesn't know → #[serde(other)] Unknown → Unsupported.
        let raw = br#"{"proto":3,"body":{"type":"SomeFutureType"}}"#;
        assert!(matches!(
            round_trip(&client, addr, raw).await.body,
            RespBody::Unsupported
        ));
    }
}
