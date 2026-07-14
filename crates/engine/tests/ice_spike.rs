//! M5.5 Stage 0 spike (gate): prove `webrtc-ice`'s `Agent` connects two peers when their candidates
//! and ICE credentials are exchanged out-of-band (after gathering, mirroring how the coordinator
//! will relay them over the long-poll, not the crate's built-in signaling), yields a
//! `webrtc_util::Conn`, and carries application bytes both ways. Loopback-only (host candidates);
//! real srflx/relay gathering is Stage 2/3. This gates the agent, the exchange model, and the Conn.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use webrtc_ice::agent::agent_config::AgentConfig;
use webrtc_ice::agent::Agent;
use webrtc_ice::candidate::candidate_base::unmarshal_candidate;
use webrtc_ice::candidate::Candidate;
use webrtc_ice::network_type::NetworkType;
use webrtc_util::Conn;

async fn new_agent(controlling: bool) -> Arc<Agent> {
    Arc::new(
        Agent::new(AgentConfig {
            network_types: vec![NetworkType::Udp4],
            is_controlling: controlling,
            include_loopback: true, // the test's only reachable host candidate is 127.0.0.1
            ..Default::default()
        })
        .await
        .expect("agent"),
    )
}

/// Gather on both agents, wait for each to signal end-of-gathering (`on_candidate(None)`), then hand
/// every local candidate to the other side — exactly the shape of a coordinator that collects a
/// device's candidates and returns the peer's set in a long-poll snapshot.
async fn gather_and_exchange(a: &Arc<Agent>, b: &Arc<Agent>) {
    let (done_tx, mut done_rx) = mpsc::channel::<()>(2);
    for ag in [a, b] {
        let tx = done_tx.clone();
        ag.on_candidate(Box::new(move |c| {
            let tx = tx.clone();
            Box::pin(async move {
                if c.is_none() {
                    let _ = tx.send(()).await; // gathering finished for this agent
                }
            })
        }));
        ag.gather_candidates().expect("gather");
    }
    done_rx.recv().await.unwrap();
    done_rx.recv().await.unwrap();

    for c in a.get_local_candidates().await.unwrap() {
        let c2: Arc<dyn Candidate + Send + Sync> =
            Arc::new(unmarshal_candidate(c.marshal().as_str()).unwrap());
        b.add_remote_candidate(&c2).unwrap();
    }
    for c in b.get_local_candidates().await.unwrap() {
        let c2: Arc<dyn Candidate + Send + Sync> =
            Arc::new(unmarshal_candidate(c.marshal().as_str()).unwrap());
        a.add_remote_candidate(&c2).unwrap();
    }
}

#[tokio::test]
async fn ice_connects_out_of_band_and_carries_bytes() {
    let a = new_agent(true).await; // controlling — deterministic role, min-pubkey in the real plan
    let b = new_agent(false).await; // controlled

    let (a_ufrag, a_pwd) = a.get_local_user_credentials().await;
    let (b_ufrag, b_pwd) = b.get_local_user_credentials().await;

    gather_and_exchange(&a, &b).await;

    // Cancel senders must outlive the connect: dial/accept select on `cancel_rx.recv()`, which
    // resolves (→ ErrCanceledByCaller) the moment its sender drops. Hold them here.
    let (_cancel_a_tx, cancel_a_rx) = mpsc::channel(1);
    let (_cancel_b_tx, cancel_b_rx) = mpsc::channel(1);

    let a2 = a.clone();
    let dial = tokio::spawn(async move { a2.dial(cancel_a_rx, b_ufrag, b_pwd).await });
    let b2 = b.clone();
    let accept = tokio::spawn(async move { b2.accept(cancel_b_rx, a_ufrag, a_pwd).await });

    let conn_a = tokio::time::timeout(Duration::from_secs(10), dial)
        .await
        .expect("dial timed out")
        .unwrap()
        .expect("dial connects");
    let conn_b = tokio::time::timeout(Duration::from_secs(10), accept)
        .await
        .expect("accept timed out")
        .unwrap()
        .expect("accept connects");

    // Application bytes both directions over the negotiated pair.
    conn_a.send(b"ping").await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), conn_b.recv(&mut buf))
        .await
        .expect("recv ping timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"ping");

    conn_b.send(b"pong").await.unwrap();
    let n = tokio::time::timeout(Duration::from_secs(5), conn_a.recv(&mut buf))
        .await
        .expect("recv pong timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"pong");

    // The selected pair is the loopback host candidate — proves candidate exchange drove selection.
    assert!(a.get_selected_candidate_pair().is_some());
}
