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
use std::time::Duration;

use anyhow::Context;
use common::api::{IceEndpoint, IceParams, RelayInfo};

use crate::util::hex8;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use webrtc_ice::agent::agent_config::AgentConfig;
use webrtc_ice::agent::Agent;
use webrtc_ice::candidate::candidate_base::unmarshal_candidate;
use webrtc_ice::candidate::Candidate;
use webrtc_ice::network_type::NetworkType;
use webrtc_ice::state::ConnectionState;
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

/// Restart backoff after a failed agent: doubles from [`RESTART_BACKOFF_MIN`] to the cap. A peer that
/// can't be reached is often one that is *gone* — a device that died without a clean shutdown stays
/// in the coordinator's presence map (and so in our snapshot, with its last endpoint) until the
/// presence TTL reaps it, ~31 minutes. Retrying it flat-out would re-gather STUN candidates against
/// the coordinator every minute for that whole window, for a peer that cannot answer.
const RESTART_BACKOFF_MIN: Duration = Duration::from_secs(60);
const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(600);

/// Tracks one ICE agent per peer we're reaching via ICE, mirroring [`crate::relay::RelayManager`].
#[derive(Default)]
pub struct IceManager {
    sessions: HashMap<[u8; 32], IceSession>,
    /// Consecutive failures per peer, and when the last one landed — drives the restart backoff.
    /// Outlives the session it describes (the session is dropped on failure) and is cleared on a
    /// successful connect or when the peer leaves the ICE set.
    failures: HashMap<[u8; 32], (u32, std::time::Instant)>,
}

/// One ICE agent's lifecycle. Replaces the former `failed: AtomicBool` + `shim: Option<SocketAddr>`
/// flag pair, which between them encoded exactly these three states. Reading the two in the wrong
/// order (shim before failed) would treat a just-failed agent as connected, so `ensure` had to check
/// `failed` first; folding them into one enum makes `Failed` win by construction instead — it is
/// terminal and sticky (a connect can't overwrite it), so the transition order no longer matters.
enum IceState {
    /// Gathering / running checks — no validated candidate pair yet.
    Negotiating,
    /// A pair validated; `127.0.0.1:<port>` is boringtun's shim, set as the peer's WG endpoint.
    Connected(SocketAddr),
    /// Terminal: negotiation failed, timed out, or the peer never offered. The session is dead —
    /// `ensure` drops it so the next refresh starts a fresh agent with fresh credentials, which is
    /// what an ICE restart is.
    Failed,
}

struct IceSession {
    /// Our ICE credentials (fixed for the agent's life) — reported to the coordinator as our offer.
    ufrag: String,
    pwd: String,
    /// Our gathered candidates (marshaled), growing as gathering completes; reported each refresh.
    local_candidates: Arc<Mutex<Vec<String>>>,
    /// Pushes the latest remote params to the connect + candidate-adder tasks.
    remote_tx: watch::Sender<Option<IceParams>>,
    /// The agent's lifecycle, written by the state-change callback and the connect task, read by
    /// `ensure`/`is_connected`.
    state: Arc<Mutex<IceState>>,
    tasks: Vec<JoinHandle<()>>,
}

impl IceSession {
    /// Whether this agent hit a terminal state and should be replaced.
    fn is_failed(&self) -> bool {
        matches!(*self.state.lock().unwrap(), IceState::Failed)
    }
}

/// How long to wait before restarting an agent that has failed `n` times in a row.
fn backoff(n: u32) -> Duration {
    RESTART_BACKOFF_MIN
        .saturating_mul(1u32.checked_shl(n.saturating_sub(1)).unwrap_or(u32::MAX))
        .min(RESTART_BACKOFF_MAX)
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
        // A session that reached a terminal state is dead weight — drop it so the branch below starts
        // a fresh agent (new credentials = an ICE restart) instead of holding a corpse forever.
        if self.sessions.get(&peer).is_some_and(|s| s.is_failed()) {
            self.sessions.remove(&peer);
            let e = self
                .failures
                .entry(peer)
                .or_insert((0, std::time::Instant::now()));
            e.0 = e.0.saturating_add(1);
            e.1 = std::time::Instant::now();
        }
        // Hold off restarting until this peer's backoff has elapsed.
        if !self.sessions.contains_key(&peer) {
            if let Some((n, at)) = self.failures.get(&peer) {
                let wait = backoff(*n);
                if at.elapsed() < wait {
                    return None;
                }
                tracing::info!(
                    peer = %hex8(&peer), attempt = n + 1,
                    "ice: restarting agent after {}s backoff", wait.as_secs()
                );
            }
        }
        if !self.sessions.contains_key(&peer) {
            match IceSession::start(peer, &cfg).await {
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
        let shim = match *s.state.lock().unwrap() {
            IceState::Connected(addr) => Some(addr),
            _ => None,
        };
        if shim.is_some() {
            self.failures.remove(&peer); // connected: the next failure starts from the shortest wait
        }
        shim
    }

    /// Drop sessions for peers no longer being reached via ICE (now directly/punch reachable, or
    /// pruned), aborting their agents and freeing the side sockets.
    pub fn retain(&mut self, keep: &HashSet<[u8; 32]>) {
        self.sessions.retain(|pk, _| keep.contains(pk));
        self.failures.retain(|pk, _| keep.contains(pk));
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
            .is_some_and(|s| matches!(*s.state.lock().unwrap(), IceState::Connected(_)))
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

/// Backstops for the two previously-unbounded waits: a peer that never offers (kernel backend,
/// `ice = false`, or whose own stuck-set never included us) parked the connect task forever, and
/// `dial`/`accept` never resolve when ICE reaches `Failed`.
///
/// Both are deliberately generous, because neither is the primary failure detector — the real
/// signal for a failed negotiation is the `Failed` state transition, which cancels the dial
/// directly (see `start`). Candidates trickle in over the coordinator long-poll, so a *healthy*
/// negotiation can legitimately spend minutes in `Checking` waiting for the peer's candidates;
/// a tight timer here aborts agents that would have connected.
const OFFER_WAIT: Duration = Duration::from_secs(300);
const NEGOTIATE_TIMEOUT: Duration = Duration::from_secs(300);

impl IceSession {
    async fn start(peer: [u8; 32], cfg: &IcePeerConfig) -> anyhow::Result<Self> {
        let peer_hex = hex8(&peer);
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

        let state = Arc::new(Mutex::new(IceState::Negotiating));

        // The cancel sender must outlive dial/accept: they select on `cancel_rx.recv()`, which
        // resolves (→ cancel) the instant its sender drops. Parked here so the state-change handler
        // below can drop it on demand.
        let (cancel_tx, cancel_rx) = mpsc::channel(1);
        let cancel_tx = Arc::new(Mutex::new(Some(cancel_tx)));

        // Surface ICE state transitions — without this, Checking → Failed is invisible and a stalled
        // agent is indistinguishable in the log from one still gathering. `Failed` is also the only
        // precise signal that a negotiation is dead: neither `dial` nor `accept` resolves on it, so
        // dropping the cancel sender here is what actually unblocks the connect task.
        {
            let peer_hex = peer_hex.clone();
            let state = state.clone();
            let cancel_tx = cancel_tx.clone();
            agent.on_connection_state_change(Box::new(move |st| {
                tracing::debug!(peer = %peer_hex, state = %st, "ice: connection state");
                if st == ConnectionState::Failed {
                    tracing::warn!(peer = %peer_hex, "ice: negotiation failed — no usable candidate pair");
                    *state.lock().unwrap() = IceState::Failed; // unconditional: Failed always wins
                    cancel_tx.lock().unwrap().take(); // dropped → dial/accept returns
                }
                Box::pin(async {})
            }));
        }

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
            let state = state.clone();
            let mut rx = remote_rx;
            let controlling = cfg.controlling;
            let peer_hex = peer_hex.clone();
            tokio::spawn(async move {
                // Mark the session dead on every early return, so `ensure` restarts it rather than
                // leaving a session that looks alive but will never connect.
                let creds = tokio::time::timeout(OFFER_WAIT, async {
                    loop {
                        if let Some(p) = rx.borrow_and_update().as_ref() {
                            if !p.ufrag.is_empty() {
                                return Some((p.ufrag.clone(), p.pwd.clone()));
                            }
                        }
                        if rx.changed().await.is_err() {
                            return None;
                        }
                    }
                })
                .await;
                let (rufrag, rpwd) = match creds {
                    Ok(Some(c)) => c,
                    Ok(None) => {
                        *state.lock().unwrap() = IceState::Failed;
                        return; // session dropped
                    }
                    Err(_) => {
                        tracing::warn!(
                            peer = %peer_hex,
                            "ice: peer never offered credentials within {}s — it may be on a kernel \
                             WireGuard backend, have ice disabled, or not consider us stuck",
                            OFFER_WAIT.as_secs()
                        );
                        *state.lock().unwrap() = IceState::Failed;
                        return;
                    }
                };
                // Backstop only — the `Failed` handler above is what normally ends a dead negotiation.
                // One async block, so `cancel_rx` moves once and both arms coerce to the same trait
                // object (`dial` and `accept` return distinct opaque `impl Conn` types).
                let negotiated = tokio::time::timeout(NEGOTIATE_TIMEOUT, async {
                    if controlling {
                        agent
                            .dial(cancel_rx, rufrag, rpwd)
                            .await
                            .map(|c| c as Arc<dyn Conn + Send + Sync>)
                    } else {
                        agent
                            .accept(cancel_rx, rufrag, rpwd)
                            .await
                            .map(|c| c as Arc<dyn Conn + Send + Sync>)
                    }
                })
                .await;
                let conn: Arc<dyn Conn + Send + Sync> = match negotiated {
                    Ok(Ok(c)) => c,
                    Ok(Err(e)) => {
                        tracing::warn!(peer = %peer_hex, controlling, "ice: negotiation failed ({e})");
                        *state.lock().unwrap() = IceState::Failed;
                        return;
                    }
                    Err(_) => {
                        tracing::warn!(
                            peer = %peer_hex, controlling,
                            "ice: no candidate pair validated within {}s — giving up on this agent",
                            NEGOTIATE_TIMEOUT.as_secs()
                        );
                        *state.lock().unwrap() = IceState::Failed;
                        return;
                    }
                };

                let shim = match UdpSocket::bind("127.0.0.1:0").await {
                    Ok(s) => Arc::new(s),
                    Err(e) => {
                        tracing::warn!(peer = %peer_hex, "ice: shim bind failed ({e})");
                        *state.lock().unwrap() = IceState::Failed;
                        return;
                    }
                };
                let Ok(shim_addr) = shim.local_addr() else {
                    *state.lock().unwrap() = IceState::Failed;
                    return;
                };
                {
                    // Publish the connected shim — but only if a concurrent `Failed` (the state-change
                    // callback firing as the pair dies) hasn't already won: Failed is terminal, so we
                    // don't resurrect it, and there's no point pumping a session `ensure` will drop.
                    let mut st = state.lock().unwrap();
                    if matches!(*st, IceState::Failed) {
                        return;
                    }
                    *st = IceState::Connected(shim_addr);
                }
                tracing::info!(peer = %peer_hex, %shim_addr, "ice: connected — routing peer via ICE");

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
            state,
            tasks: vec![adder, connect],
        })
    }
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

    /// A peer that died without a clean shutdown lingers in our snapshot for the presence TTL
    /// (~31 min). Flat retries would re-gather STUN against the coordinator every minute of it, so
    /// the wait has to grow — and stay capped, so a genuinely stuck peer still gets retried.
    #[test]
    fn restart_backoff_grows_then_caps() {
        assert_eq!(backoff(1), RESTART_BACKOFF_MIN);
        assert_eq!(backoff(2), RESTART_BACKOFF_MIN * 2);
        assert_eq!(backoff(4), RESTART_BACKOFF_MIN * 8);
        // Capped, and no overflow panic at absurd failure counts.
        assert_eq!(backoff(20), RESTART_BACKOFF_MAX);
        assert_eq!(backoff(u32::MAX), RESTART_BACKOFF_MAX);
    }

    #[test]
    fn urls_omit_turn_when_no_relay() {
        let stun = vec!["203.0.113.9:3478".parse().unwrap()];
        let urls = build_urls(&stun, None);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].scheme, SchemeType::Stun);
    }
}
