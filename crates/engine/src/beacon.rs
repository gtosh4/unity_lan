//! LAN peer-discovery beacon.
//!
//! Two same-LAN peers behind one NAT otherwise reach each other only through the router's public
//! IP (a *hairpin*) — their reflexive endpoints, since neither advertises its private address (a
//! privacy choice: LAN addresses would leak internal topology to the coordinator and every peer,
//! and RFC1918 ranges collide, so a remote peer on `192.168.4.0/24` would look "same subnet" as
//! ours). Hairpin translation is flaky on consumer routers → intermittent handshake loss → the
//! peer flaps.
//!
//! This module closes that gap without advertising anything private. Each engine periodically UDP-
//! **broadcasts** a tiny beacon on the local segment carrying only its WireGuard pubkey + listen
//! port. A beacon can only be *received* by a host physically on the same L2 segment, so its source
//! address is a genuine LAN path to the sender — proof by receipt, not by address guessing. On
//! receiving one from a known mesh peer we record `src_ip : advertised_port` as a candidate direct
//! endpoint and (if it proves out) point WireGuard at it, replacing the hairpin.
//!
//! **No beacon crypto.** The WireGuard handshake is the authenticator: a beacon only says "try
//! endpoint X for pubkey P", and P's pubkey is already public among mesh members. Adopting an
//! endpoint is guarded by a health check ([`Beacon::select`]) — we switch, then require the peer to
//! stay reachable (ping) across a short grace; if not we revert to the reflexive path and suppress
//! that address for a cooldown. So a forged/spoofed beacon (from an on-LAN attacker who sniffed the
//! cleartext pubkey) can cost at most one bounded ~grace-length blip before we fall back, never a
//! key compromise.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

/// Beacon wire tag + version. Bump `VERSION` on any payload layout change.
const MAGIC: [u8; 4] = *b"ULB1";
const VERSION: u8 = 1;
/// `MAGIC(4) + VERSION(1) + wg_pubkey(32) + listen_port(2, LE)`.
const PAYLOAD_LEN: usize = 4 + 1 + 32 + 2;

/// Default UDP port beacons are broadcast on/received at (distinct from the WG listen port).
pub const DEFAULT_PORT: u16 = 51821;

/// Steady-state broadcast interval. One ~39-byte packet at this cadence is ~1.3 B/s — quieter than
/// the mDNS/SSDP traffic already on a typical LAN. A short startup burst (see [`Beacon::spawn`])
/// makes a freshly-joined peer discoverable in seconds rather than up to one interval.
const SEND_INTERVAL: Duration = Duration::from_secs(30);
/// Drop a learned candidate this long after its last beacon (3 missed → revert to reflexive).
const CAND_TTL: Duration = Duration::from_secs(90);
/// After switching a peer to its LAN endpoint, ignore health this long so the next ping cycle
/// measures the *new* path rather than the pre-switch one.
const SETTLE: Duration = Duration::from_secs(3);
/// If a just-switched LAN endpoint isn't reachable within this window, revert to reflexive.
const VERIFY_GRACE: Duration = Duration::from_secs(8);
/// Demote an established LAN endpoint back to reflexive after this long unreachable (peer left the
/// LAN, or the direct path died).
const STALE_GRACE: Duration = Duration::from_secs(20);
/// After a LAN endpoint fails verification, suppress *that address* this long so a repeatedly-forged
/// or dead endpoint can't thrash the peer. A different candidate address retries immediately.
const FAIL_COOLDOWN: Duration = Duration::from_secs(300);

/// A LAN endpoint learned from a received beacon.
#[derive(Clone, Copy)]
struct Candidate {
    /// `src_ip` of the beacon combined with the sender's advertised WG listen port.
    addr: SocketAddr,
    seen: Instant,
}

/// Per-peer adoption state for its current LAN candidate.
#[derive(Clone)]
enum LanState {
    /// Switched to `addr`, waiting for the health check to confirm reachability.
    Trying { addr: SocketAddr, since: Instant },
    /// `addr` confirmed reachable; `last_ok` tracks the most recent reachable observation.
    Active { addr: SocketAddr, last_ok: Instant },
    /// `addr` failed verification (or went stale); suppressed until `until`.
    Failed { addr: SocketAddr, until: Instant },
}

/// Handle to the beacon subsystem: shared learned-candidate map (written by the recv task) plus the
/// per-peer adoption state machine ([`select`](Beacon::select), driven by the mesh loop).
pub struct Beacon {
    candidates: Arc<Mutex<HashMap<[u8; 32], Candidate>>>,
    states: HashMap<[u8; 32], LanState>,
    /// Send + receive task handles, aborted on drop so re-enrollment frees the bound socket.
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Beacon {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Encode a beacon datagram advertising `pubkey` reachable at `port`.
fn encode(pubkey: &[u8; 32], port: u16) -> [u8; PAYLOAD_LEN] {
    let mut buf = [0u8; PAYLOAD_LEN];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION;
    buf[5..37].copy_from_slice(pubkey);
    buf[37..39].copy_from_slice(&port.to_le_bytes());
    buf
}

/// Parse a beacon datagram, returning `(pubkey, advertised_port)` if it's well-formed and a version
/// we understand. Anything else (wrong magic/version/length) is ignored.
fn decode(buf: &[u8]) -> Option<([u8; 32], u16)> {
    if buf.len() != PAYLOAD_LEN || buf[0..4] != MAGIC || buf[4] != VERSION {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&buf[5..37]);
    let port = u16::from_le_bytes([buf[37], buf[38]]);
    Some((pk, port))
}

impl Beacon {
    /// Spawn the send + receive tasks on `sock` (bound to `0.0.0.0:<port>`, broadcast-enabled) and
    /// return the handle the mesh loop drives. `my_pubkey`/`my_wg_port` are what we advertise; our
    /// own looped-back broadcasts are ignored on receipt.
    pub fn spawn(
        sock: UdpSocket,
        my_pubkey: [u8; 32],
        my_wg_port: u16,
        beacon_port: u16,
    ) -> Beacon {
        let candidates: Arc<Mutex<HashMap<[u8; 32], Candidate>>> = Arc::default();
        let sock = Arc::new(sock);
        let mut tasks = Vec::with_capacity(2);
        // Receiver: record each known-shaped beacon as a candidate (src_ip : advertised_port).
        {
            let sock = sock.clone();
            let candidates = candidates.clone();
            tasks.push(tokio::spawn(async move {
                let mut buf = [0u8; 512];
                loop {
                    let (n, from) = match sock.recv_from(&mut buf).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("beacon recv ended: {e}");
                            return;
                        }
                    };
                    let Some((pk, port)) = decode(&buf[..n]) else {
                        continue;
                    };
                    if pk == my_pubkey {
                        continue; // our own broadcast, looped back
                    }
                    let addr = SocketAddr::new(from.ip(), port);
                    candidates.lock().unwrap().insert(
                        pk,
                        Candidate {
                            addr,
                            seen: Instant::now(),
                        },
                    );
                }
            }));
        }
        // Sender: startup burst (0s, +1s, +2s) then steady interval.
        {
            let payload = encode(&my_pubkey, my_wg_port);
            let dst = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, beacon_port));
            tasks.push(tokio::spawn(async move {
                let burst = [
                    Duration::ZERO,
                    Duration::from_secs(1),
                    Duration::from_secs(2),
                ];
                for (i, gap) in burst.iter().enumerate() {
                    tokio::time::sleep(*gap).await;
                    if let Err(e) = sock.send_to(&payload, dst).await {
                        // A send failure early (no route / broadcast disallowed) is non-fatal: log
                        // once and keep the steady loop trying — an interface may come up later.
                        if i == 0 {
                            tracing::warn!(
                                "beacon send failed ({e}); LAN discovery may be limited"
                            );
                        }
                    }
                }
                loop {
                    tokio::time::sleep(SEND_INTERVAL).await;
                    let _ = sock.send_to(&payload, dst).await;
                }
            }));
        }
        Beacon {
            candidates,
            states: HashMap::new(),
            tasks,
        }
    }

    /// Decide, for this mesh-loop iteration, which peers to route through a LAN endpoint.
    ///
    /// `reachable` maps every currently-known peer pubkey to whether it answered this iteration's
    /// ping (the health signal). Peers absent from it are no longer in the mesh and are dropped from
    /// the state machine. Returns `pubkey -> lan_endpoint` for peers whose LAN candidate is being
    /// tried or is confirmed active; the mesh loop gives these top endpoint precedence.
    ///
    /// Time is injected (`now`) so the transition logic is unit-testable without a real clock.
    pub fn select(
        &mut self,
        now: Instant,
        reachable: &HashMap<[u8; 32], bool>,
    ) -> HashMap<[u8; 32], SocketAddr> {
        // Snapshot live (non-expired) candidates, then drop stale ones so the map can't grow with
        // beacons from hosts that stopped broadcasting (or never were peers).
        let mut cands = self.candidates.lock().unwrap();
        cands.retain(|_, c| now.duration_since(c.seen) < CAND_TTL);
        let live: HashMap<[u8; 32], SocketAddr> =
            cands.iter().map(|(pk, c)| (*pk, c.addr)).collect();
        drop(cands);

        // Forget state for peers that left the mesh.
        self.states.retain(|pk, _| reachable.contains_key(pk));

        let mut out = HashMap::new();
        for (&pk, &ok) in reachable {
            let Some(&addr) = live.get(&pk) else {
                // No live beacon for this peer → not on our LAN; ensure no stale adoption lingers.
                self.states.remove(&pk);
                continue;
            };
            let next = self.step(pk, addr, ok, now);
            match &next {
                LanState::Trying { addr, .. } | LanState::Active { addr, .. } => {
                    out.insert(pk, *addr);
                }
                LanState::Failed { .. } => {} // suppressed → fall back to reflexive
            }
            self.states.insert(pk, next);
        }
        out
    }

    /// Advance one peer's LAN-adoption state given its current live candidate `addr` and whether it
    /// is `ok` (reachable) this iteration.
    fn step(&self, pk: [u8; 32], addr: SocketAddr, ok: bool, now: Instant) -> LanState {
        match self.states.get(&pk) {
            // A different candidate address than whatever we were doing → (re)start verification.
            Some(LanState::Trying { addr: a, .. })
            | Some(LanState::Active { addr: a, .. })
            | Some(LanState::Failed { addr: a, .. })
                if *a != addr =>
            {
                LanState::Trying { addr, since: now }
            }
            None => LanState::Trying { addr, since: now },
            Some(LanState::Trying { since, .. }) => {
                let waited = now.duration_since(*since);
                if waited < SETTLE {
                    LanState::Trying {
                        addr,
                        since: *since,
                    } // let the path settle before judging
                } else if ok {
                    LanState::Active { addr, last_ok: now }
                } else if waited >= VERIFY_GRACE {
                    LanState::Failed {
                        addr,
                        until: now + FAIL_COOLDOWN,
                    }
                } else {
                    LanState::Trying {
                        addr,
                        since: *since,
                    }
                }
            }
            Some(LanState::Active { last_ok, .. }) => {
                if ok {
                    LanState::Active { addr, last_ok: now }
                } else if now.duration_since(*last_ok) >= STALE_GRACE {
                    LanState::Failed {
                        addr,
                        until: now + FAIL_COOLDOWN,
                    }
                } else {
                    LanState::Active {
                        addr,
                        last_ok: *last_ok,
                    }
                }
            }
            Some(LanState::Failed { until, .. }) => {
                if now < *until {
                    LanState::Failed {
                        addr,
                        until: *until,
                    } // same address still suppressed
                } else {
                    LanState::Trying { addr, since: now } // cooldown elapsed → retry
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(last: u8, port: u16) -> SocketAddr {
        SocketAddr::from(([192, 168, 4, last], port))
    }

    #[test]
    fn codec_roundtrips() {
        let pk = [7u8; 32];
        let (got_pk, got_port) = decode(&encode(&pk, 51820)).unwrap();
        assert_eq!(got_pk, pk);
        assert_eq!(got_port, 51820);
    }

    #[test]
    fn codec_rejects_junk() {
        assert!(decode(b"nope").is_none()); // wrong length
        let mut bad = encode(&[1u8; 32], 1);
        bad[4] = 9; // unknown version
        assert!(decode(&bad).is_none());
    }

    /// Build a Beacon with a directly-seeded candidate map (no sockets), for state-machine tests.
    fn with_candidate(pk: [u8; 32], addr: SocketAddr, seen: Instant) -> Beacon {
        let candidates: Arc<Mutex<HashMap<[u8; 32], Candidate>>> = Arc::default();
        candidates
            .lock()
            .unwrap()
            .insert(pk, Candidate { addr, seen });
        Beacon {
            candidates,
            states: HashMap::new(),
            tasks: Vec::new(),
        }
    }

    #[test]
    fn adopts_reachable_lan_endpoint_after_settle() {
        let pk = [1u8; 32];
        let addr = ep(118, 51820);
        let t0 = Instant::now();
        let mut b = with_candidate(pk, addr, t0);
        let known = HashMap::from([(pk, true)]);

        // First pass: within SETTLE, still Trying but already routed to the LAN endpoint.
        assert_eq!(b.select(t0, &known).get(&pk), Some(&addr));
        // After SETTLE, reachable → confirmed Active, still routed.
        let out = b.select(t0 + SETTLE + Duration::from_millis(1), &known);
        assert_eq!(out.get(&pk), Some(&addr));
        assert!(matches!(b.states.get(&pk), Some(LanState::Active { .. })));
    }

    #[test]
    fn reverts_unreachable_endpoint_and_suppresses_it() {
        let pk = [2u8; 32];
        let addr = ep(200, 51820); // a forged / dead endpoint
        let t0 = Instant::now();
        let mut b = with_candidate(pk, addr, t0);
        let unreachable = HashMap::from([(pk, false)]);

        // Routed while trying...
        assert_eq!(b.select(t0, &unreachable).get(&pk), Some(&addr));
        // ...but still dark past the grace → reverts (not in output) and is now suppressed.
        let out = b.select(t0 + VERIFY_GRACE + Duration::from_millis(1), &unreachable);
        assert!(!out.contains_key(&pk));
        assert!(matches!(b.states.get(&pk), Some(LanState::Failed { .. })));

        // A fresh beacon for the SAME bad address during cooldown stays suppressed.
        b.candidates
            .lock()
            .unwrap()
            .insert(pk, Candidate { addr, seen: t0 });
        let out = b.select(t0 + VERIFY_GRACE + Duration::from_secs(1), &unreachable);
        assert!(!out.contains_key(&pk));
    }

    #[test]
    fn expired_candidate_drops_adoption() {
        let pk = [3u8; 32];
        let addr = ep(118, 51820);
        let t0 = Instant::now();
        let mut b = with_candidate(pk, addr, t0);
        let known = HashMap::from([(pk, true)]);
        b.select(t0, &known);
        // No fresh beacon: past the TTL the candidate is gone → no LAN route, state cleared.
        let out = b.select(t0 + CAND_TTL + Duration::from_secs(1), &known);
        assert!(!out.contains_key(&pk));
        assert!(!b.states.contains_key(&pk));
    }

    #[test]
    fn peer_leaving_mesh_clears_state() {
        let pk = [4u8; 32];
        let t0 = Instant::now();
        let mut b = with_candidate(pk, ep(118, 51820), t0);
        b.select(t0, &HashMap::from([(pk, true)]));
        // Peer absent from `reachable` (left the mesh) → state forgotten.
        b.select(t0 + Duration::from_millis(1), &HashMap::new());
        assert!(!b.states.contains_key(&pk));
    }
}
