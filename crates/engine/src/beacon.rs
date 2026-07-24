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
//! endpoint and — once the candidate proves itself (below) — point WireGuard at it, replacing the
//! hairpin. A LAN path is *preferred*, not merely a fallback: the hairpin it replaces is exactly the
//! path that works *intermittently*, so waiting for the current path to go fully dark would leave a
//! flaky hairpin in place indefinitely. We therefore switch a *working* peer onto its LAN endpoint
//! too, and once a LAN endpoint has carried traffic we stay on it through transient loss
//! ([`STALE_GRACE`]) and return to it quickly after a blip ([`RETRY_COOLDOWN`]).
//!
//! **Adoption is gated on an authenticated liveness probe, so a forged beacon can't churn a peer.**
//! The broadcast announcement is an unauthenticated *hint* (a broadcast has no pairwise recipient to
//! MAC to, and the WG pubkey it carries is already public among members). Before pointing WireGuard
//! at a candidate we unicast a **probe** to it and require a valid **ack** ([`Beacon::step`],
//! `Probing` state). The probe/ack are MAC'd with the X25519 shared secret of the two peers'
//! WireGuard keys (`common::crypto::beacon_probe_mac`/`beacon_ack_mac`) — the same secret both sides
//! already hold, needing no new key and no distribution — so **only a holder of the peer's WG
//! private key can answer**. A party that merely sniffed the cleartext pubkey off the wire cannot,
//! and a replayed ack is rejected: each probe carries a fresh nonce the ack must echo. Until a valid
//! ack arrives the candidate is never routed, so a forged or dead candidate can neither displace a
//! working tunnel nor churn a dark one — it costs at most one unanswered probe, then a backoff. A
//! switched-to endpoint that then fails to carry WG traffic within a grace reverts and the peer is
//! held off for a short cooldown. Candidates are only recorded for pubkeys already in the
//! authenticated peer set, so a flood of forged pubkeys can't grow the candidate map past the mesh
//! size.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use common::crypto::{beacon_ack_mac, gen_beacon_nonce, verify_beacon_ack, verify_beacon_probe};

/// Beacon wire tag + version. Bump `VERSION` on any payload layout change.
const MAGIC: [u8; 4] = *b"ULB1";
const VERSION: u8 = 1;
/// `MAGIC(4) + VERSION(1) + wg_pubkey(32) + listen_port(2, LE)` — the broadcast announcement, the
/// only shape older engines understand.
const ANNOUNCE_LEN: usize = 4 + 1 + 32 + 2;
const NONCE_LEN: usize = 16;
const MAC_LEN: usize = 16;
/// An announcement plus `kind(1) + nonce(16) + mac(16)`: the unicast probe/ack exchange. An engine
/// predating this rejects the extra bytes as malformed and simply never answers, so a mixed-version
/// LAN degrades to no LAN adoption for that peer rather than misbehaving.
const KINDED_LEN: usize = ANNOUNCE_LEN + 1 + NONCE_LEN + MAC_LEN;
const KIND_PROBE: u8 = 1;
const KIND_ACK: u8 = 2;

/// Default UDP port beacons are broadcast on/received at (distinct from the WG listen port).
pub const DEFAULT_PORT: u16 = 51821;

/// Steady-state broadcast interval. One ~39-byte packet at this cadence is ~1.3 B/s — quieter than
/// the mDNS/SSDP traffic already on a typical LAN. A short startup burst (see [`Beacon::spawn`])
/// makes a freshly-joined peer discoverable in seconds rather than up to one interval.
const SEND_INTERVAL: Duration = Duration::from_secs(30);
/// Drop a learned candidate this long after its last beacon (3 missed → revert to reflexive).
const CAND_TTL: Duration = Duration::from_secs(90);
/// How long to wait for a valid ack before giving up on a candidate.
const PROBE_GRACE: Duration = Duration::from_secs(6);
/// A probe ack (and the nonce that solicited it) counts as evidence for this long.
const PROBE_ACK_TTL: Duration = Duration::from_secs(10);
/// After a probe goes unanswered, don't probe that peer again for this long — a peer whose current
/// path works loses nothing by waiting, and this bounds probe traffic under a beacon flood.
const PROBE_BACKOFF: Duration = Duration::from_secs(60);
/// After switching a peer to its LAN endpoint, ignore health this long so the next ping cycle
/// measures the *new* path rather than the pre-switch one.
const SETTLE: Duration = Duration::from_secs(3);
/// If a just-switched LAN endpoint isn't reachable within this window, revert to reflexive.
const VERIFY_GRACE: Duration = Duration::from_secs(8);
/// Demote an established LAN endpoint back to reflexive after this long unreachable (peer left the
/// LAN, or the direct path died). Generous on purpose: a LAN path that has carried traffic is the
/// best path we know of, so brief loss shouldn't hand the peer back to a flaky hairpin.
const STALE_GRACE: Duration = Duration::from_secs(60);
/// Hold a peer off the LAN endpoint this long after it reverts. Short because reverting no longer
/// implies an attack: only the real peer can answer the probe, so a `Trying`/`Active` failure is a
/// genuine path that broke (odd firewall, peer left the segment), worth retrying soon.
const RETRY_COOLDOWN: Duration = Duration::from_secs(30);

/// Probe answers recorded by the recv task, keyed by peer pubkey: `(address that answered, when)`.
type Acks = Arc<Mutex<HashMap<[u8; 32], (SocketAddr, Instant)>>>;
/// Outstanding probes, keyed by peer pubkey: `(nonce we issued, address probed, when)`. Written by
/// the prober, read by the recv task to bind an ack to the probe that solicited it.
type Pending = Arc<Mutex<HashMap<[u8; 32], ([u8; NONCE_LEN], SocketAddr, Instant)>>>;

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
    /// Probing `addr` over the LAN, awaiting a valid ack before pointing WireGuard at it. Not routed.
    Probing { addr: SocketAddr, since: Instant },
    /// Switched to `addr`, waiting for the health check to confirm WG traffic flows.
    Trying { addr: SocketAddr, since: Instant },
    /// `addr` confirmed reachable; `last_ok` tracks the most recent reachable observation.
    Active { addr: SocketAddr, last_ok: Instant },
    /// `addr` reverted (failed verification or went stale); held off until `until`.
    Failed { addr: SocketAddr, until: Instant },
}

/// Handle to the beacon subsystem: shared learned-candidate map (written by the recv task) plus the
/// per-peer adoption state machine ([`select`](Beacon::select), driven by the mesh loop).
pub struct Beacon {
    candidates: Arc<Mutex<HashMap<[u8; 32], Candidate>>>,
    /// Authenticated peer pubkeys, refreshed each [`select`](Beacon::select). The recv task reads it
    /// to drop beacons for pubkeys not in the mesh, bounding the candidate map to the mesh size.
    members: Arc<Mutex<HashSet<[u8; 32]>>>,
    /// Validated probe acks recorded by the recv task.
    acks: Acks,
    /// Probes we've sent and are awaiting an ack for.
    pending: Pending,
    /// Outbound probe targets `(peer pubkey, address)`, drained by the prober task. Bounded: a full
    /// queue drops the probe, which simply retries next iteration.
    probes: Option<mpsc::Sender<([u8; 32], SocketAddr)>>,
    /// Peers whose probe went unanswered, not probed again until this instant.
    probe_backoff: HashMap<[u8; 32], Instant>,
    states: HashMap<[u8; 32], LanState>,
    /// Send + receive + prober task handles, aborted on drop so re-enrollment frees the socket.
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Beacon {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Encode the broadcast announcement advertising `pubkey` reachable at `port`.
fn encode(pubkey: &[u8; 32], port: u16) -> [u8; ANNOUNCE_LEN] {
    let mut buf = [0u8; ANNOUNCE_LEN];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = VERSION;
    buf[5..37].copy_from_slice(pubkey);
    buf[37..39].copy_from_slice(&port.to_le_bytes());
    buf
}

/// Encode a unicast probe (`KIND_PROBE`) or its answer (`KIND_ACK`), carrying the nonce + MAC.
fn encode_kinded(
    pubkey: &[u8; 32],
    port: u16,
    kind: u8,
    nonce: &[u8; NONCE_LEN],
    mac: &[u8; MAC_LEN],
) -> [u8; KINDED_LEN] {
    let mut buf = [0u8; KINDED_LEN];
    buf[..ANNOUNCE_LEN].copy_from_slice(&encode(pubkey, port));
    buf[ANNOUNCE_LEN] = kind;
    buf[ANNOUNCE_LEN + 1..ANNOUNCE_LEN + 1 + NONCE_LEN].copy_from_slice(nonce);
    buf[ANNOUNCE_LEN + 1 + NONCE_LEN..].copy_from_slice(mac);
    buf
}

/// The kind + authenticator carried by a unicast probe/ack.
struct Kinded {
    kind: u8,
    nonce: [u8; NONCE_LEN],
    mac: [u8; MAC_LEN],
}

/// A parsed beacon datagram: sender pubkey + advertised WG port, and — for a unicast probe/ack —
/// its kind, nonce and MAC. `kinded` is `None` for a plain broadcast announcement.
struct Msg {
    pk: [u8; 32],
    port: u16,
    kinded: Option<Kinded>,
}

/// Parse a beacon datagram if it's well-formed and a version we understand. Anything else (wrong
/// magic/version/length/kind) is ignored.
fn decode(buf: &[u8]) -> Option<Msg> {
    if buf.len() < ANNOUNCE_LEN || buf[0..4] != MAGIC || buf[4] != VERSION {
        return None;
    }
    let kinded = match buf.len() {
        ANNOUNCE_LEN => None,
        KINDED_LEN if matches!(buf[ANNOUNCE_LEN], KIND_PROBE | KIND_ACK) => {
            let mut nonce = [0u8; NONCE_LEN];
            let mut mac = [0u8; MAC_LEN];
            nonce.copy_from_slice(&buf[ANNOUNCE_LEN + 1..ANNOUNCE_LEN + 1 + NONCE_LEN]);
            mac.copy_from_slice(&buf[ANNOUNCE_LEN + 1 + NONCE_LEN..]);
            Some(Kinded {
                kind: buf[ANNOUNCE_LEN],
                nonce,
                mac,
            })
        }
        _ => return None,
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&buf[5..37]);
    let port = u16::from_le_bytes([buf[37], buf[38]]);
    Some(Msg { pk, port, kinded })
}

impl Beacon {
    /// Spawn the send + receive + prober tasks on `sock` (bound to `0.0.0.0:<port>`,
    /// broadcast-enabled) and return the handle the mesh loop drives. `my_pubkey`/`my_wg_port` are
    /// what we advertise; `my_wg_private` keys the probe/ack MACs. Our own looped-back broadcasts are
    /// ignored on receipt.
    pub fn spawn(
        sock: UdpSocket,
        my_pubkey: [u8; 32],
        my_wg_private: [u8; 32],
        my_wg_port: u16,
        beacon_port: u16,
    ) -> Beacon {
        let candidates: Arc<Mutex<HashMap<[u8; 32], Candidate>>> = Arc::default();
        let members: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::default();
        let acks: Acks = Arc::default();
        let pending: Pending = Arc::default();
        let (probe_tx, mut probe_rx) = mpsc::channel::<([u8; 32], SocketAddr)>(64);
        let sock = Arc::new(sock);
        let mut tasks = Vec::with_capacity(3);
        // Receiver: record each known-shaped beacon from a current mesh peer as a candidate
        // (src_ip : advertised_port). Beacons for pubkeys not in the authenticated peer set are
        // dropped, so an on-LAN flood of forged random pubkeys can't grow the map past the mesh
        // size. A peer's *authenticated* probe is answered in place; a valid ack (matching a probe
        // we issued) is recorded as liveness proof.
        {
            let sock = sock.clone();
            let candidates = candidates.clone();
            let members = members.clone();
            let acks = acks.clone();
            let pending = pending.clone();
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
                    let Some(msg) = decode(&buf[..n]) else {
                        continue;
                    };
                    if msg.pk == my_pubkey {
                        continue; // our own broadcast, looped back
                    }
                    if !members.lock().unwrap().contains(&msg.pk) {
                        continue; // not a current mesh peer — never routes, so never stored
                    }
                    let addr = SocketAddr::new(from.ip(), msg.port);
                    let now = Instant::now();
                    // Any beacon is proof of an L2 path from `from`; record it as the candidate.
                    candidates
                        .lock()
                        .unwrap()
                        .insert(msg.pk, Candidate { addr, seen: now });
                    let Some(k) = msg.kinded else { continue };
                    match k.kind {
                        KIND_PROBE => {
                            // Only answer a probe that proves the sender holds the peer's WG key —
                            // otherwise we'd reflect acks to spoofers. Answer to the socket the probe
                            // came from, echoing the nonce so our ack is bound to this probe.
                            if !verify_beacon_probe(&my_wg_private, &msg.pk, &k.nonce, &k.mac) {
                                continue;
                            }
                            if let Some(mac) = beacon_ack_mac(&my_wg_private, &msg.pk, &k.nonce) {
                                let reply =
                                    encode_kinded(&my_pubkey, my_wg_port, KIND_ACK, &k.nonce, &mac);
                                let _ = sock.send_to(&reply, from).await;
                            }
                        }
                        KIND_ACK => {
                            // Accept only an ack that (a) matches a fresh probe we issued for this
                            // peer and (b) verifies under the shared secret. Both together defeat a
                            // replayed or forged ack.
                            let ok = pending.lock().unwrap().get(&msg.pk).is_some_and(
                                |(nonce, _, sent)| {
                                    *nonce == k.nonce && now.duration_since(*sent) < PROBE_ACK_TTL
                                },
                            );
                            if ok && verify_beacon_ack(&my_wg_private, &msg.pk, &k.nonce, &k.mac) {
                                acks.lock().unwrap().insert(msg.pk, (addr, now));
                            }
                        }
                        _ => {}
                    }
                }
            }));
        }
        // Prober: unicast an authenticated probe to each address the state machine asks about.
        {
            let sock = sock.clone();
            let pending = pending.clone();
            tasks.push(tokio::spawn(async move {
                while let Some((pk, addr)) = probe_rx.recv().await {
                    let nonce = gen_beacon_nonce();
                    let Some(mac) = common::crypto::beacon_probe_mac(&my_wg_private, &pk, &nonce)
                    else {
                        continue; // low-order peer key — never a real WG key
                    };
                    pending
                        .lock()
                        .unwrap()
                        .insert(pk, (nonce, addr, Instant::now()));
                    let payload = encode_kinded(&my_pubkey, my_wg_port, KIND_PROBE, &nonce, &mac);
                    let dst = SocketAddr::new(addr.ip(), beacon_port);
                    let _ = sock.send_to(&payload, dst).await;
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
            acks,
            pending,
            probes: Some(probe_tx),
            probe_backoff: HashMap::new(),
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
        let live: HashMap<[u8; 32], Candidate> = {
            let mut cands = self.candidates.lock().unwrap();
            cands.retain(|_, c| now.duration_since(c.seen) < CAND_TTL);
            cands.iter().map(|(pk, c)| (*pk, *c)).collect()
        };
        self.acks
            .lock()
            .unwrap()
            .retain(|_, (_, t)| now.duration_since(*t) < PROBE_ACK_TTL);
        self.pending.lock().unwrap().retain(|pk, (_, _, t)| {
            reachable.contains_key(pk) && now.duration_since(*t) < CAND_TTL
        });

        // Forget state for peers that left the mesh.
        self.states.retain(|pk, _| reachable.contains_key(pk));
        self.probe_backoff
            .retain(|pk, _| reachable.contains_key(pk));

        let mut out = HashMap::new();
        for (&pk, &ok) in reachable {
            let Some(&cand) = live.get(&pk) else {
                // No live beacon for this peer → not on our LAN; ensure no stale adoption lingers.
                self.states.remove(&pk);
                continue;
            };
            match self.step(pk, &cand, ok, now) {
                // Trying/Active → route to the LAN endpoint; Probing (candidate not yet proven) and
                // Failed (cooldown held) stay on the reflexive endpoint this iteration.
                Some(next) => {
                    if let LanState::Trying { addr, .. } | LanState::Active { addr, .. } = next {
                        out.insert(pk, addr);
                    }
                    self.states.insert(pk, next);
                }
                // Not adopting: hold no state and route via the coordinator/reflexive endpoint.
                None => {
                    self.states.remove(&pk);
                }
            }
        }
        out
    }

    /// Whether `addr` answered a probe for `pk` recently enough to act on.
    fn ack_fresh(&self, pk: [u8; 32], addr: SocketAddr, now: Instant) -> bool {
        self.acks
            .lock()
            .unwrap()
            .get(&pk)
            .is_some_and(|(a, t)| *a == addr && now.duration_since(*t) < PROBE_ACK_TTL)
    }

    /// Queue an authenticated probe to `pk` at `addr` (dropped if the queue is full — it retries
    /// next iteration).
    fn send_probe(&self, pk: [u8; 32], addr: SocketAddr) {
        if let Some(tx) = &self.probes {
            let _ = tx.try_send((pk, addr));
        }
    }

    /// Begin adoption for a peer we hold no state for (or whose cooldown just expired): start probing
    /// its candidate, unless it's within a probe backoff. Never routes until the probe is answered,
    /// so this is safe whether or not the peer's current path works.
    fn begin(&mut self, pk: [u8; 32], cand: &Candidate, now: Instant) -> Option<LanState> {
        if self.ack_fresh(pk, cand.addr, now) {
            return Some(LanState::Trying {
                addr: cand.addr,
                since: now,
            });
        }
        if self
            .probe_backoff
            .get(&pk)
            .is_some_and(|until| now < *until)
        {
            return None;
        }
        self.send_probe(pk, cand.addr);
        Some(LanState::Probing {
            addr: cand.addr,
            since: now,
        })
    }

    /// Advance one peer's LAN-adoption state given its current live candidate and whether it is `ok`
    /// (reachable) this iteration. `None` = not adopting (route via the reflexive endpoint).
    ///
    /// Anti-churn guards against forged/flooded beacons:
    /// - **Nothing is routed without an authenticated ack.** `Probing` never points WireGuard at a
    ///   candidate, so a forged or dead candidate disturbs neither a working nor a dark tunnel; only
    ///   a holder of the peer's WG private key can produce the ack that advances to `Trying`.
    /// - **Stick to the address in flight.** Once probing/verifying a candidate we ignore any newer
    ///   candidate address until the attempt resolves, so a rotating-source flood can't reset it.
    fn step(&mut self, pk: [u8; 32], cand: &Candidate, ok: bool, now: Instant) -> Option<LanState> {
        match self.states.get(&pk).cloned() {
            None => self.begin(pk, cand, now),
            // Awaiting a valid ack: switch when it arrives, give up (and back off) if it doesn't.
            Some(LanState::Probing { addr, since }) => {
                if self.ack_fresh(pk, addr, now) {
                    return Some(LanState::Trying { addr, since: now });
                }
                if now.duration_since(since) >= PROBE_GRACE {
                    self.probe_backoff.insert(pk, now + PROBE_BACKOFF);
                    return None;
                }
                // Re-send while waiting: a single lost probe shouldn't cost the whole backoff.
                self.send_probe(pk, addr);
                Some(LanState::Probing { addr, since })
            }
            // Stick with the address we're verifying, ignoring any newer candidate.
            Some(LanState::Trying { addr, since }) => {
                let waited = now.duration_since(since);
                Some(if waited < SETTLE {
                    LanState::Trying { addr, since } // let the path settle before judging
                } else if ok {
                    LanState::Active { addr, last_ok: now }
                } else if waited >= VERIFY_GRACE {
                    LanState::Failed {
                        addr,
                        until: now + RETRY_COOLDOWN,
                    }
                } else {
                    LanState::Trying { addr, since }
                })
            }
            // Stay on the confirmed address until it goes stale; a different candidate is ignored.
            Some(LanState::Active { addr, last_ok }) => Some(if ok {
                LanState::Active { addr, last_ok: now }
            } else if now.duration_since(last_ok) >= STALE_GRACE {
                LanState::Failed {
                    addr,
                    until: now + RETRY_COOLDOWN,
                }
            } else {
                LanState::Active { addr, last_ok }
            }),
            // Held off after a revert: wait out the cooldown, then re-enter the adoption decision.
            Some(LanState::Failed { addr, until }) => {
                if now < until {
                    Some(LanState::Failed { addr, until })
                } else {
                    self.begin(pk, cand, now)
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

    const NONCE: [u8; NONCE_LEN] = [3u8; NONCE_LEN];
    const MAC: [u8; MAC_LEN] = [4u8; MAC_LEN];

    #[test]
    fn codec_roundtrips() {
        let pk = [7u8; 32];
        let m = decode(&encode(&pk, 51820)).unwrap();
        assert_eq!(m.pk, pk);
        assert_eq!(m.port, 51820);
        assert!(m.kinded.is_none());

        let probe = decode(&encode_kinded(&pk, 51820, KIND_PROBE, &NONCE, &MAC)).unwrap();
        let k = probe.kinded.unwrap();
        assert_eq!(k.kind, KIND_PROBE);
        assert_eq!(k.nonce, NONCE);
        assert_eq!(k.mac, MAC);
        assert_eq!(
            decode(&encode_kinded(&pk, 1, KIND_ACK, &NONCE, &MAC))
                .unwrap()
                .kinded
                .unwrap()
                .kind,
            KIND_ACK
        );
    }

    #[test]
    fn codec_rejects_junk() {
        assert!(decode(b"nope").is_none()); // wrong length
        let mut bad = encode(&[1u8; 32], 1);
        bad[4] = 9; // unknown version
        assert!(decode(&bad).is_none());
        let mut bad_kind = encode_kinded(&[1u8; 32], 1, KIND_PROBE, &NONCE, &MAC);
        bad_kind[ANNOUNCE_LEN] = 9; // unknown kind
        assert!(decode(&bad_kind).is_none());
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
            acks: Arc::default(),
            pending: Arc::default(),
            probes: None,
            probe_backoff: HashMap::new(),
            states: HashMap::new(),
            tasks: Vec::new(),
        }
    }

    /// Overwrite a peer's candidate (a rotating-source flood, or a refreshed beacon).
    fn set_candidate(b: &Beacon, pk: [u8; 32], addr: SocketAddr, seen: Instant) {
        b.candidates
            .lock()
            .unwrap()
            .insert(pk, Candidate { addr, seen });
    }

    /// Pretend a probe for `pk` was answered by `addr` at `at` (what the recv task records on a
    /// valid ack).
    fn seed_ack(b: &Beacon, pk: [u8; 32], addr: SocketAddr, at: Instant) {
        b.acks.lock().unwrap().insert(pk, (addr, at));
    }

    #[test]
    fn adopts_lan_endpoint_once_the_probe_is_answered() {
        // The core flow: a candidate is not routed until a valid ack arrives, then confirms.
        let pk = [1u8; 32];
        let addr = ep(118, 51820);
        let t0 = Instant::now();
        let mut b = with_candidate(pk, addr, t0);

        // First pass: unproven → Probing, not routed (works the same whether the peer is up or down).
        let up = HashMap::from([(pk, true)]);
        assert!(!b.select(t0, &up).contains_key(&pk));
        assert!(matches!(b.states.get(&pk), Some(LanState::Probing { .. })));

        // The peer answers the probe → switch, then confirm Active after SETTLE.
        seed_ack(&b, pk, addr, t0);
        let t1 = t0 + Duration::from_secs(1);
        assert_eq!(b.select(t1, &up).get(&pk), Some(&addr));
        let out = b.select(t1 + SETTLE + Duration::from_millis(1), &up);
        assert_eq!(out.get(&pk), Some(&addr));
        assert!(matches!(b.states.get(&pk), Some(LanState::Active { .. })));
    }

    #[test]
    fn unanswered_probe_never_routes_and_backs_off() {
        // A forged or dead candidate can't be answered (no WG key), so it never routes — neither a
        // working tunnel (ok=true) nor a dark one (ok=false) is ever disturbed.
        for ok in [true, false] {
            let pk = [9u8; 32];
            let addr = ep(200, 51820); // attacker-advertised / dead endpoint
            let t0 = Instant::now();
            let mut b = with_candidate(pk, addr, t0);
            let health = HashMap::from([(pk, ok)]);

            assert!(!b.select(t0, &health).contains_key(&pk)); // Probing, not routed
            let t1 = t0 + PROBE_GRACE + Duration::from_millis(1);
            assert!(!b.select(t1, &health).contains_key(&pk)); // gave up
            assert!(!b.states.contains_key(&pk));
            // ...and doesn't re-probe until the backoff elapses.
            assert!(!b
                .select(t1 + Duration::from_secs(1), &health)
                .contains_key(&pk));
            assert!(!b.states.contains_key(&pk));
            // After the backoff, it tries again.
            let t2 = t1 + PROBE_BACKOFF + Duration::from_secs(1);
            set_candidate(&b, pk, addr, t2);
            assert!(!b.select(t2, &health).contains_key(&pk));
            assert!(matches!(b.states.get(&pk), Some(LanState::Probing { .. })));
        }
    }

    #[test]
    fn reverts_endpoint_that_answers_but_carries_no_traffic() {
        // The peer answered the probe (so the candidate is genuine), but WG traffic never flows —
        // revert after the grace and hold off for the short cooldown.
        let pk = [2u8; 32];
        let addr = ep(118, 51820);
        let t0 = Instant::now();
        let mut b = with_candidate(pk, addr, t0);
        let down = HashMap::from([(pk, false)]);
        seed_ack(&b, pk, addr, t0);

        // Ack present → switch and route while verifying...
        assert_eq!(b.select(t0, &down).get(&pk), Some(&addr));
        // ...but still no traffic past the grace → reverts and holds off.
        let out = b.select(t0 + VERIFY_GRACE + Duration::from_millis(1), &down);
        assert!(!out.contains_key(&pk));
        let Some(LanState::Failed { until, .. }) = b.states.get(&pk) else {
            panic!("expected Failed");
        };
        assert_eq!(
            *until,
            t0 + VERIFY_GRACE + Duration::from_millis(1) + RETRY_COOLDOWN
        );
    }

    #[test]
    fn proven_endpoint_survives_a_blip_and_returns_quickly() {
        // Stickiness: a LAN path that carried traffic isn't demoted on brief loss, and when it does
        // go it returns after the short cooldown.
        let pk = [3u8; 32];
        let addr = ep(118, 51820);
        let t0 = Instant::now();
        let mut b = with_candidate(pk, addr, t0);
        let up = HashMap::from([(pk, true)]);
        let down = HashMap::from([(pk, false)]);
        seed_ack(&b, pk, addr, t0);

        // Probe answered → Trying → Active.
        b.select(t0, &up);
        b.select(t0 + SETTLE + Duration::from_millis(1), &up);
        assert!(matches!(b.states.get(&pk), Some(LanState::Active { .. })));

        // A blip well inside STALE_GRACE keeps the LAN endpoint routed.
        let t1 = t0 + SETTLE + Duration::from_secs(10);
        assert_eq!(b.select(t1, &down).get(&pk), Some(&addr));

        // Sustained loss past STALE_GRACE demotes it — with the short cooldown.
        let t2 = t0 + SETTLE + STALE_GRACE + Duration::from_secs(1);
        assert!(!b.select(t2, &down).contains_key(&pk));
        let Some(LanState::Failed { until, .. }) = b.states.get(&pk) else {
            panic!("expected Failed");
        };
        assert_eq!(*until, t2 + RETRY_COOLDOWN);

        // Once the short cooldown elapses and the probe still answers, it re-adopts.
        let t3 = t2 + RETRY_COOLDOWN + Duration::from_secs(1);
        set_candidate(&b, pk, addr, t3);
        seed_ack(&b, pk, addr, t3);
        assert_eq!(b.select(t3, &down).get(&pk), Some(&addr));
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
        seed_ack(&b, pk, a1, t0);
        assert_eq!(b.select(t0, &down).get(&pk), Some(&a1));

        // Attacker overwrites the candidate mid-verification, still within SETTLE.
        set_candidate(&b, pk, ep(202, 51820), t0);
        let out = b.select(t0 + Duration::from_secs(1), &down);
        assert_eq!(out.get(&pk), Some(&a1)); // still a1, not the injected address
    }

    #[test]
    fn expired_candidate_drops_adoption() {
        let pk = [3u8; 32];
        let addr = ep(118, 51820);
        let t0 = Instant::now();
        let mut b = with_candidate(pk, addr, t0);
        let up = HashMap::from([(pk, true)]);
        seed_ack(&b, pk, addr, t0);
        b.select(t0, &up); // ack present → Trying
                           // No fresh beacon: past the TTL the candidate is gone → no LAN route, state cleared.
        let out = b.select(t0 + CAND_TTL + Duration::from_secs(1), &up);
        assert!(!out.contains_key(&pk));
        assert!(!b.states.contains_key(&pk));
    }

    #[test]
    fn peer_leaving_mesh_clears_state() {
        let pk = [4u8; 32];
        let t0 = Instant::now();
        let mut b = with_candidate(pk, ep(118, 51820), t0);
        seed_ack(&b, pk, ep(118, 51820), t0);
        b.select(t0, &HashMap::from([(pk, true)])); // ack → Trying, holds state
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

    /// Real sockets end-to-end: a genuine peer (holding its WG key) probes us and we answer with a
    /// valid ack; then it acks a probe we issued and we record it. Exercises the recv + prober wire
    /// paths and the MAC verification the state-machine tests stub out.
    #[tokio::test]
    async fn authenticated_probe_and_ack_over_real_sockets() {
        use common::crypto::{
            beacon_probe_mac, gen_beacon_nonce, gen_wg_keypair, verify_beacon_ack,
        };

        let (my_priv, my_pub) = gen_wg_keypair();
        let (peer_priv, peer_pub) = gen_wg_keypair();
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let beacon_addr = sock.local_addr().unwrap();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let mut b = Beacon::spawn(sock, my_pub, my_priv, 51820, beacon_addr.port());
        // Only current mesh peers are listened to, so publish the peer set first.
        b.select(Instant::now(), &HashMap::from([(peer_pub, true)]));

        // The peer probes us with a MAC only its WG key can produce → we must answer with a valid ack.
        let nonce = gen_beacon_nonce();
        let pmac = beacon_probe_mac(&peer_priv, &my_pub, &nonce).unwrap();
        peer.send_to(
            &encode_kinded(&peer_pub, 51830, KIND_PROBE, &nonce, &pmac),
            beacon_addr,
        )
        .await
        .unwrap();
        let mut buf = [0u8; 128];
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
            .await
            .expect("no ack within timeout")
            .unwrap();
        assert_eq!(from, beacon_addr);
        let ack = decode(&buf[..n]).unwrap();
        let k = ack.kinded.expect("ack is a kinded message");
        assert_eq!(k.kind, KIND_ACK);
        assert_eq!(k.nonce, nonce); // our ack echoes the probe nonce
        assert_eq!(ack.pk, my_pub);
        // The ack verifies under the shared secret — the peer (holding peer_priv) can trust it.
        assert!(verify_beacon_ack(&peer_priv, &my_pub, &k.nonce, &k.mac));

        // A probe carrying a bogus MAC is ignored — no ack comes back.
        peer.send_to(
            &encode_kinded(&peer_pub, 51830, KIND_PROBE, &nonce, &[0u8; MAC_LEN]),
            beacon_addr,
        )
        .await
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), peer.recv_from(&mut buf))
                .await
                .is_err(),
            "a forged probe must not be answered"
        );
    }
}
