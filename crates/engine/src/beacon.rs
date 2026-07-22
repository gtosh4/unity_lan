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
//! endpoint X for pubkey P", and P's pubkey is already public among mesh members. Adoption is
//! doubly guarded ([`Beacon::select`]) so a forged/spoofed beacon (from an on-LAN attacker who
//! sniffed the cleartext pubkey) can't churn a peer: we only *start* adopting a LAN candidate for a
//! peer whose current path is unhealthy (a working endpoint is never replaced), and once we switch
//! we require the peer to stay reachable (ping) across a short grace or we revert and suppress that
//! *peer* — not just that address — for a cooldown. A rotating-source flood therefore costs at most
//! one bounded ~grace-length blip per cooldown, never continuous WireGuard teardown, and never a key
//! compromise. Candidates are only recorded for pubkeys already in the authenticated peer set, so a
//! flood of forged pubkeys can't grow the candidate map past the mesh size.

use std::collections::{HashMap, HashSet};
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
/// After a LAN endpoint fails verification, suppress the *peer* (any candidate address) this long so
/// a repeatedly-forged or rotating-source endpoint can't thrash it — a fresh address does not retry
/// early, which is what bounds a rotating-source flood to one blip per cooldown.
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
    /// Authenticated peer pubkeys, refreshed each [`select`](Beacon::select). The recv task reads it
    /// to drop beacons for pubkeys not in the mesh, bounding the candidate map to the mesh size.
    members: Arc<Mutex<HashSet<[u8; 32]>>>,
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
        let members: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::default();
        let sock = Arc::new(sock);
        let mut tasks = Vec::with_capacity(2);
        // Receiver: record each known-shaped beacon from a current mesh peer as a candidate
        // (src_ip : advertised_port). Beacons for pubkeys not in the authenticated peer set are
        // dropped, so an on-LAN flood of forged random pubkeys can't grow the map past the mesh size.
        {
            let sock = sock.clone();
            let candidates = candidates.clone();
            let members = members.clone();
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
                    if !members.lock().unwrap().contains(&pk) {
                        continue; // not a current mesh peer — never routes, so never stored
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
            members,
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
        // Publish the current authenticated peer set for the recv task's membership gate.
        {
            let mut m = self.members.lock().unwrap();
            m.clear();
            m.extend(reachable.keys().copied());
        }

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
            match self.step(pk, addr, ok, now) {
                // Trying/Active → route to the LAN endpoint; Failed → hold the state (enforces the
                // per-peer cooldown) but fall back to reflexive (not routed this iteration).
                Some(next) => {
                    if let LanState::Trying { addr, .. } | LanState::Active { addr, .. } = next {
                        out.insert(pk, addr);
                    }
                    self.states.insert(pk, next);
                }
                // Not adopting (healthy path, or cooldown elapsed while still healthy): hold no state
                // and route via the coordinator/reflexive endpoint.
                None => {
                    self.states.remove(&pk);
                }
            }
        }
        out
    }

    /// Advance one peer's LAN-adoption state given its current live candidate `addr` and whether it
    /// is `ok` (reachable) this iteration. `None` = not adopting (route via the reflexive endpoint).
    ///
    /// Two anti-churn guards defend against forged/flooded beacons:
    /// - **Adopt only an unhealthy path.** We enter `Trying` for a peer only when its current path is
    ///   *not* carrying traffic (`!ok`); a working endpoint is never yanked onto a LAN candidate. A
    ///   forged beacon therefore can't disturb a healthy peer at all.
    /// - **Throttle per peer, not per address.** Once we commit to a candidate we stick with it,
    ///   ignoring a changed candidate address until the attempt resolves; a failure suppresses the
    ///   peer for [`FAIL_COOLDOWN`] regardless of address. A rotating-source flood thus can't reset
    ///   the attempt every iteration — it costs one bounded blip per cooldown.
    fn step(&self, pk: [u8; 32], addr: SocketAddr, ok: bool, now: Instant) -> Option<LanState> {
        match self.states.get(&pk) {
            // Not currently adopting: start only if the peer's existing path is unhealthy. Committing
            // to whatever candidate is live now; a later address change is ignored until this resolves.
            None => (!ok).then_some(LanState::Trying { addr, since: now }),
            // Stick with the address we're verifying (`a`), ignoring any newer candidate `addr`.
            Some(LanState::Trying { addr: a, since }) => {
                let a = *a;
                let waited = now.duration_since(*since);
                Some(if waited < SETTLE {
                    LanState::Trying {
                        addr: a,
                        since: *since,
                    } // let the path settle before judging
                } else if ok {
                    LanState::Active {
                        addr: a,
                        last_ok: now,
                    }
                } else if waited >= VERIFY_GRACE {
                    LanState::Failed {
                        addr: a,
                        until: now + FAIL_COOLDOWN,
                    }
                } else {
                    LanState::Trying {
                        addr: a,
                        since: *since,
                    }
                })
            }
            // Stay on the confirmed address until it goes stale; a different candidate is ignored.
            Some(LanState::Active { addr: a, last_ok }) => {
                let a = *a;
                Some(if ok {
                    LanState::Active {
                        addr: a,
                        last_ok: now,
                    }
                } else if now.duration_since(*last_ok) >= STALE_GRACE {
                    LanState::Failed {
                        addr: a,
                        until: now + FAIL_COOLDOWN,
                    }
                } else {
                    LanState::Active {
                        addr: a,
                        last_ok: *last_ok,
                    }
                })
            }
            // Suppressed peer: hold the cooldown regardless of which address beacons now arrive. When
            // it elapses, retry only if the path is still unhealthy.
            Some(LanState::Failed { addr: a, until }) => {
                if now < *until {
                    Some(LanState::Failed {
                        addr: *a,
                        until: *until,
                    })
                } else {
                    (!ok).then_some(LanState::Trying { addr, since: now })
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
            members: Arc::default(),
            states: HashMap::new(),
            tasks: Vec::new(),
        }
    }

    #[test]
    fn adopts_lan_endpoint_for_unhealthy_peer_then_confirms() {
        let pk = [1u8; 32];
        let addr = ep(118, 51820);
        let t0 = Instant::now();
        let mut b = with_candidate(pk, addr, t0);

        // Current path down (ok=false) → start adopting; within SETTLE, routed to the LAN endpoint.
        let down = HashMap::from([(pk, false)]);
        assert_eq!(b.select(t0, &down).get(&pk), Some(&addr));
        // The LAN path now answers → after SETTLE, confirmed Active, still routed.
        let up = HashMap::from([(pk, true)]);
        let out = b.select(t0 + SETTLE + Duration::from_millis(1), &up);
        assert_eq!(out.get(&pk), Some(&addr));
        assert!(matches!(b.states.get(&pk), Some(LanState::Active { .. })));
    }

    #[test]
    fn does_not_adopt_a_healthy_peer() {
        // The core forged-beacon defense: a peer whose current path works is never yanked onto a LAN
        // candidate, so a spoofed beacon can't disturb it.
        let pk = [9u8; 32];
        let addr = ep(200, 51820); // attacker-advertised endpoint
        let t0 = Instant::now();
        let mut b = with_candidate(pk, addr, t0);
        let healthy = HashMap::from([(pk, true)]);
        let out = b.select(t0, &healthy);
        assert!(!out.contains_key(&pk));
        assert!(!b.states.contains_key(&pk));
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
    fn rotating_source_stays_suppressed_per_peer() {
        // A forged-beacon flood that changes source address every iteration must not keep restarting
        // adoption: once one attempt fails, the peer is suppressed regardless of address.
        let pk = [5u8; 32];
        let a1 = ep(200, 51820);
        let t0 = Instant::now();
        let mut b = with_candidate(pk, a1, t0);
        let down = HashMap::from([(pk, false)]);

        // a1 tried and fails past the grace → Failed (peer suppressed).
        b.select(t0, &down);
        let t1 = t0 + VERIFY_GRACE + Duration::from_millis(1);
        assert!(!b.select(t1, &down).contains_key(&pk));
        assert!(matches!(b.states.get(&pk), Some(LanState::Failed { .. })));

        // Attacker rotates to a different address during the cooldown → still ignored, not routed,
        // and no new Trying attempt starts.
        let a2 = ep(201, 51820);
        b.candidates
            .lock()
            .unwrap()
            .insert(pk, Candidate { addr: a2, seen: t1 });
        let out = b.select(t1 + Duration::from_secs(2), &down);
        assert!(!out.contains_key(&pk));
        assert!(matches!(b.states.get(&pk), Some(LanState::Failed { .. })));
    }

    #[test]
    fn trying_sticks_to_its_address_ignoring_rotation() {
        // While verifying one candidate, a changed candidate address (a rotating flood) must not
        // hijack the in-flight attempt.
        let pk = [6u8; 32];
        let a1 = ep(118, 51820); // the real LAN endpoint we committed to
        let t0 = Instant::now();
        let mut b = with_candidate(pk, a1, t0);
        let down = HashMap::from([(pk, false)]);
        assert_eq!(b.select(t0, &down).get(&pk), Some(&a1));

        // Attacker overwrites the candidate mid-verification, still within SETTLE.
        let a2 = ep(202, 51820);
        b.candidates
            .lock()
            .unwrap()
            .insert(pk, Candidate { addr: a2, seen: t0 });
        let out = b.select(t0 + Duration::from_secs(1), &down);
        assert_eq!(out.get(&pk), Some(&a1)); // still a1, not the injected a2
    }

    #[test]
    fn expired_candidate_drops_adoption() {
        let pk = [3u8; 32];
        let addr = ep(118, 51820);
        let t0 = Instant::now();
        let mut b = with_candidate(pk, addr, t0);
        let down = HashMap::from([(pk, false)]);
        b.select(t0, &down); // unhealthy → adopts (Trying)
                             // No fresh beacon: past the TTL the candidate is gone → no LAN route, state cleared.
        let out = b.select(t0 + CAND_TTL + Duration::from_secs(1), &down);
        assert!(!out.contains_key(&pk));
        assert!(!b.states.contains_key(&pk));
    }

    #[test]
    fn peer_leaving_mesh_clears_state() {
        let pk = [4u8; 32];
        let t0 = Instant::now();
        let mut b = with_candidate(pk, ep(118, 51820), t0);
        b.select(t0, &HashMap::from([(pk, false)])); // unhealthy → adopts, holds state
        assert!(b.states.contains_key(&pk));
        // Peer absent from `reachable` (left the mesh) → state forgotten.
        b.select(t0 + Duration::from_millis(1), &HashMap::new());
        assert!(!b.states.contains_key(&pk));
    }

    #[test]
    fn select_publishes_member_set_for_ingestion_gate() {
        // `select` must expose the authenticated peer set so the recv task can drop beacons for
        // non-members (the candidate-map growth bound).
        let pk = [7u8; 32];
        let other = [8u8; 32];
        let t0 = Instant::now();
        let mut b = with_candidate(pk, ep(118, 51820), t0);
        b.select(t0, &HashMap::from([(pk, false), (other, true)]));
        let m = b.members.lock().unwrap();
        assert!(m.contains(&pk) && m.contains(&other));
    }
}
