//! Side-socket ICE agent (design.md §7.2, M5.5).
//!
//! For a peer whose hole punch structurally can't complete (restricted-cone, or a lone/all-NAT'd
//! mesh with no observer to bootstrap the punch), we run a real ICE agent (`webrtc-ice`) on a socket
//! *beside* boringtun. It gathers host + server-reflexive (STUN) + relay (TURN, = the M5.4 relay)
//! candidates, exchanges them with the peer over the coordinator long-poll (never a separate Signal
//! server — see [`common::api::IceParams`]), runs connectivity checks, and on success bridges the
//! peer's WireGuard traffic boringtun↔ICE `Conn` through a `127.0.0.1:<shim>` socket — the same
//! loopback-shim shape as the M5.4 relay ([`crate::relay::RelayManager`]), but the `Conn` here picks
//! the *best* validated path (a direct srflx pair when one works, the relay only as a last resort).
//!
//! Userspace-only: it owns its own UDP socket, so it applies to the boringtun backend; kernel
//! backends keep the M5.2 punch + M5.4 relay.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use common::api::{IceEndpoint, IceParams, RelayInfo};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use webrtc_ice::agent::agent_config::AgentConfig;
use webrtc_ice::agent::Agent;
use webrtc_ice::candidate::candidate_base::unmarshal_candidate;
use webrtc_ice::candidate::Candidate;
use webrtc_ice::network_type::NetworkType;
use webrtc_ice::url::{ProtoType, SchemeType, Url};
use webrtc_util::Conn;

/// Per-peer ICE configuration the daemon assembles each refresh.
pub struct IcePeerConfig {
    /// True if we are the **controlling** agent. Deterministic (our pubkey < the peer's), so both
    /// sides compute the same and exactly one dials while the other accepts.
    pub controlling: bool,
    /// STUN servers to gather server-reflexive candidates from, in preference order (relay-first: a
    /// dialable relay co-member's address, then the coordinator-host fallback).
    pub stun: Vec<SocketAddr>,
    /// The peer's TURN relay reservation (from `Seed.relay`), used to gather a relay candidate —
    /// the same embedded relay as M5.4. `None` when no relay was matched for this pair.
    pub turn: Option<RelayInfo>,
    /// The peer's ICE params (ufrag/pwd + candidates), relayed by the coordinator. `None` until the
    /// peer has offered ICE for us.
    pub remote: Option<IceParams>,
}

/// Tracks one ICE agent per peer we're reaching via ICE, mirroring [`crate::relay::RelayManager`].
#[derive(Default)]
pub struct IceManager {
    sessions: HashMap<[u8; 32], IceSession>,
}

struct IceSession {
    /// Our ICE credentials (fixed for the agent's life) — reported to the coordinator as our offer.
    ufrag: String,
    pwd: String,
    /// Our gathered candidates (marshaled), growing as gathering completes; reported each refresh.
    local_candidates: Arc<Mutex<Vec<String>>>,
    /// Pushes the latest remote params to the connect + candidate-adder tasks.
    remote_tx: watch::Sender<Option<IceParams>>,
    /// `127.0.0.1:<port>` boringtun sends to once connected (set as the peer's WG endpoint); `None`
    /// until the ICE agent has selected a working candidate pair.
    shim: Arc<Mutex<Option<SocketAddr>>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for IceSession {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort(); // stop the agent + pump when the session is pruned (frees the side socket)
        }
    }
}

impl IceManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensure an ICE session exists for `peer` (starting the agent + gathering on first sight) and
    /// push the peer's latest params to it. Returns the local shim address to use as the peer's WG
    /// endpoint once ICE has connected, else `None` (still gathering / checking — retried next
    /// refresh).
    #[allow(clippy::map_entry)] // the branch does async agent startup the entry API can't express
    pub async fn ensure(&mut self, peer: [u8; 32], cfg: IcePeerConfig) -> Option<SocketAddr> {
        if !self.sessions.contains_key(&peer) {
            match IceSession::start(&cfg).await {
                Ok(s) => {
                    tracing::info!(peer = %hex8(&peer), controlling = cfg.controlling, "ice: agent started");
                    self.sessions.insert(peer, s);
                }
                Err(e) => {
                    tracing::warn!(peer = %hex8(&peer), "ice: start failed ({e:#})");
                    return None;
                }
            }
        }
        let s = &self.sessions[&peer];
        let _ = s.remote_tx.send(cfg.remote); // ignore: a closed receiver means the task died
        *s.shim.lock().unwrap()
    }

    /// Drop sessions for peers no longer being reached via ICE (now directly/punch reachable, or
    /// pruned), aborting their agents and freeing the side sockets.
    pub fn retain(&mut self, keep: &HashSet<[u8; 32]>) {
        self.sessions.retain(|pk, _| keep.contains(pk));
    }

    /// Whether we already hold a session for `peer` (connected or still negotiating). Used to keep a
    /// live session alive across a long-poll cycle even when the (stale) stuck-set momentarily drops
    /// the peer — otherwise a mid-negotiation session is torn down and restarted every cycle.
    pub fn has_session(&self, peer: &[u8; 32]) -> bool {
        self.sessions.contains_key(peer)
    }

    /// True once ICE has selected a working pair for `peer` (its WG endpoint should point at the
    /// shim). Used to keep the peer in the ICE set and mark it `Ice` in status.
    pub fn is_connected(&self, peer: &[u8; 32]) -> bool {
        self.sessions
            .get(peer)
            .is_some_and(|s| s.shim.lock().unwrap().is_some())
    }

    /// Our ICE offers to report to the coordinator (the candidate-exchange half). Candidates grow as
    /// gathering completes, so successive refreshes carry a fuller set until it converges.
    pub fn offers(&self) -> Vec<IceEndpoint> {
        self.sessions
            .iter()
            .map(|(pk, s)| IceEndpoint {
                peer: *pk,
                params: IceParams {
                    ufrag: s.ufrag.clone(),
                    pwd: s.pwd.clone(),
                    candidates: s.local_candidates.lock().unwrap().clone(),
                },
            })
            .collect()
    }
}

/// Build the ICE server URL list: each STUN server (in preference order) then the TURN relay (with
/// its minted long-term credential), so the agent gathers srflx + relay candidates.
fn build_urls(stun: &[SocketAddr], turn: Option<&RelayInfo>) -> Vec<Url> {
    let mut urls: Vec<Url> = stun
        .iter()
        .map(|s| Url {
            scheme: SchemeType::Stun,
            host: s.ip().to_string(),
            port: s.port(),
            proto: ProtoType::Udp,
            ..Default::default()
        })
        .collect();
    if let Some(t) = turn {
        urls.push(Url {
            scheme: SchemeType::Turn,
            host: t.turn_addr.ip().to_string(),
            port: t.turn_addr.port(),
            username: t.username.clone(),
            password: t.credential.clone(),
            proto: ProtoType::Udp,
        });
    }
    urls
}

impl IceSession {
    async fn start(cfg: &IcePeerConfig) -> anyhow::Result<Self> {
        let agent = Arc::new(
            Agent::new(AgentConfig {
                urls: build_urls(&cfg.stun, cfg.turn.as_ref()),
                network_types: vec![NetworkType::Udp4],
                is_controlling: cfg.controlling,
                ..Default::default()
            })
            .await
            .context("creating ICE agent")?,
        );

        // Collect our gathered candidates as they arrive (reported to the coordinator via `offers`).
        let local_candidates = Arc::new(Mutex::new(Vec::new()));
        {
            let lc = local_candidates.clone();
            agent.on_candidate(Box::new(move |c| {
                let lc = lc.clone();
                Box::pin(async move {
                    if let Some(c) = c {
                        lc.lock().unwrap().push(c.marshal());
                    }
                })
            }));
        }
        let (ufrag, pwd) = agent.get_local_user_credentials().await;
        agent
            .gather_candidates()
            .context("gathering ICE candidates")?;

        let (remote_tx, remote_rx) = watch::channel(cfg.remote.clone());
        let shim = Arc::new(Mutex::new(None));

        // Candidate-adder: feed the peer's candidates into the agent as they trickle in over refreshes.
        let adder = {
            let agent = agent.clone();
            let mut rx = remote_rx.clone();
            tokio::spawn(async move {
                let mut added: HashSet<String> = HashSet::new();
                loop {
                    let cands = rx
                        .borrow_and_update()
                        .as_ref()
                        .map(|p| p.candidates.clone())
                        .unwrap_or_default();
                    for c in cands {
                        if added.insert(c.clone()) {
                            if let Ok(cand) = unmarshal_candidate(&c) {
                                let arc: Arc<dyn Candidate + Send + Sync> = Arc::new(cand);
                                let _ = agent.add_remote_candidate(&arc);
                            }
                        }
                    }
                    if rx.changed().await.is_err() {
                        break; // session dropped
                    }
                }
            })
        };

        // Connect + pump: wait for the peer's credentials, run checks, then bridge boringtun↔Conn.
        let connect = {
            let agent = agent.clone();
            let shim_slot = shim.clone();
            let mut rx = remote_rx;
            let controlling = cfg.controlling;
            tokio::spawn(async move {
                let (rufrag, rpwd) = loop {
                    if let Some(p) = rx.borrow_and_update().as_ref() {
                        if !p.ufrag.is_empty() {
                            break (p.ufrag.clone(), p.pwd.clone());
                        }
                    }
                    if rx.changed().await.is_err() {
                        return;
                    }
                };
                // The cancel sender must outlive dial/accept: they select on `cancel_rx.recv()`, which
                // resolves (→ cancel) the instant its sender drops. Held for the pump's lifetime.
                let (_cancel_tx, cancel_rx) = mpsc::channel(1);
                let conn: Arc<dyn Conn + Send + Sync> = if controlling {
                    match agent.dial(cancel_rx, rufrag, rpwd).await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("ice: dial failed ({e})");
                            return;
                        }
                    }
                } else {
                    match agent.accept(cancel_rx, rufrag, rpwd).await {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!("ice: accept failed ({e})");
                            return;
                        }
                    }
                };

                let shim = match UdpSocket::bind("127.0.0.1:0").await {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        tracing::warn!("ice: shim bind failed ({e})");
                        return;
                    }
                };
                let Ok(shim_addr) = shim.local_addr() else {
                    return;
                };
                *shim_slot.lock().unwrap() = Some(shim_addr);
                tracing::info!(%shim_addr, "ice: connected — routing peer via ICE");

                let mut bt: Option<SocketAddr> = None; // boringtun's source, learned on first packet
                let mut egress = vec![0u8; 1600]; // boringtun → peer
                let mut ingress = vec![0u8; 1600]; // peer → boringtun
                loop {
                    tokio::select! {
                        r = shim.recv_from(&mut egress) => {
                            let Ok((n, from)) = r else { break };
                            bt = Some(from);
                            let _ = conn.send(&egress[..n]).await;
                        }
                        r = conn.recv(&mut ingress) => {
                            let Ok(n) = r else { break };
                            if let Some(dst) = bt {
                                let _ = shim.send_to(&ingress[..n], dst).await;
                            }
                        }
                    }
                }
            })
        };

        Ok(Self {
            ufrag,
            pwd,
            local_candidates,
            remote_tx,
            shim,
            tasks: vec![adder, connect],
        })
    }
}

/// Short pubkey prefix for logs.
fn hex8(pk: &[u8; 32]) -> String {
    pk[..4].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay_info(addr: &str) -> RelayInfo {
        RelayInfo {
            turn_addr: addr.parse().unwrap(),
            username: "1700000000".into(),
            credential: "cred".into(),
            realm: "unitylan".into(),
            peer_relayed: None,
        }
    }

    #[test]
    fn urls_put_stun_first_then_turn_with_creds() {
        let stun = vec![
            "203.0.113.9:3478".parse().unwrap(),
            "198.51.100.1:19302".parse().unwrap(),
        ];
        let turn = relay_info("203.0.113.9:3478");
        let urls = build_urls(&stun, Some(&turn));

        assert_eq!(urls.len(), 3);
        // Relay-first STUN ordering preserved.
        assert_eq!(urls[0].scheme, SchemeType::Stun);
        assert_eq!(urls[0].host, "203.0.113.9");
        assert_eq!(urls[0].port, 3478);
        assert_eq!(urls[1].scheme, SchemeType::Stun);
        assert_eq!(urls[1].port, 19302);
        // TURN last, carrying the minted long-term credential.
        assert_eq!(urls[2].scheme, SchemeType::Turn);
        assert_eq!(urls[2].username, "1700000000");
        assert_eq!(urls[2].password, "cred");
    }

    #[test]
    fn urls_omit_turn_when_no_relay() {
        let stun = vec!["203.0.113.9:3478".parse().unwrap()];
        let urls = build_urls(&stun, None);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].scheme, SchemeType::Stun);
    }
}
