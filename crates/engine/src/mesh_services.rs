//! What peers announce they serve, and which claim on a name wins.
//!
//! (Named `mesh_services` rather than `services` because `service` is already the OS
//! service-integration module — Windows SCM, config bootstrap — and the two are unrelated. Not a
//! doc link: that module is Windows-only, so it does not exist to link to on other platforms.)
//!
//! Services are learned peer-direct ([`crate::p2p::pull_services`]), so this is the client half of a
//! feature the coordinator holds no state for. Two jobs live here: remembering what each peer last
//! announced, and turning the whole set of claims into names — a decision every device must make
//! identically, or `mc.alice.unity.internal` would resolve differently depending on who asked.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::service::MeshService;

use crate::coord::{SeedPeer, SelfDevice};

/// How long a peer's announced list is trusted before we ask again.
///
/// There is no push: a device that names a new service cannot tell its peers, so this interval *is*
/// how long "I added it, why can't you see it?" lasts. That argues for short. Against it: one small
/// datagram per peer per interval, forever. Thirty seconds costs less than the WireGuard keepalive
/// already running to each of those peers and keeps the delay inside what reads as "a moment", which
/// is the trade worth making — this is a name people are waiting to use, not a background cache.
pub const REFRESH: Duration = Duration::from_secs(30);

/// What each peer last told us, keyed by public key — the identity that survives a peer renaming a
/// device or changing address, and the one the tiebreak orders on.
#[derive(Clone, Default)]
pub struct ServiceBook(Arc<Mutex<HashMap<[u8; 32], Entry>>>);

#[derive(Clone)]
struct Entry {
    services: Vec<MeshService>,
    polled_at: Instant,
}

impl ServiceBook {
    /// Record a peer's announcement, as of `now`. Returns whether it differs from what we held.
    ///
    /// The clock is the caller's rather than read here, so "polled at" and the [`Self::is_due`] that
    /// decides the next poll are measured against the same instant.
    pub fn set(&self, pubkey: [u8; 32], services: Vec<MeshService>, now: Instant) -> bool {
        let mut map = self.0.lock().unwrap();
        let changed = map.get(&pubkey).is_none_or(|e| e.services != services);
        map.insert(
            pubkey,
            Entry {
                services,
                polled_at: now,
            },
        );
        changed
    }

    /// Whether this peer is due a poll: never asked, or asked longer ago than [`REFRESH`].
    pub fn is_due(&self, pubkey: &[u8; 32], now: Instant) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(pubkey)
            .is_none_or(|e| now.duration_since(e.polled_at) >= REFRESH)
    }

    fn get(&self, pubkey: &[u8; 32]) -> Vec<MeshService> {
        self.0
            .lock()
            .unwrap()
            .get(pubkey)
            .map(|e| e.services.clone())
            .unwrap_or_default()
    }

    /// Forget peers no longer in the mesh, so a departed device's names stop resolving and the map
    /// cannot grow without bound across a long uptime.
    pub fn retain_peers(&self, present: &HashSet<[u8; 32]>) {
        self.0.lock().unwrap().retain(|k, _| present.contains(k));
    }
}

/// One device's claim on one label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub pubkey: [u8; 32],
    pub ip: Ipv4Addr,
    /// The label the device announced.
    pub name: String,
    /// The name it resolves as, composed by *us* from the claimant's verified user label — never
    /// taken from the claimant, which is what keeps a peer inside its owner's namespace.
    pub hostname: String,
    pub proto: common::control::Proto,
    pub port: u16,
    pub kind: common::service::ServiceKind,
}

/// The outcome of resolving every claim.
pub struct Resolved {
    /// Name → address, for the resolver.
    pub names: HashMap<String, Ipv4Addr>,
    /// The claims that lost, by (claimant, label) — shown rather than hidden, because a service
    /// that is running but unreachable by its name is precisely what its owner needs told.
    pub shadowed: HashSet<([u8; 32], String)>,
}

/// Decide which claim owns each name.
///
/// Two rules, in order:
///
/// 1. **A device name always wins.** Device names are allocated by the coordinator and are what
///    attestations are signed over; a service label is self-asserted. Letting one shadow the other
///    would let a device make a *sibling* unreachable by name.
/// 2. **Otherwise the lowest public key wins.** Two of an owner's devices claiming `mc` is a real
///    conflict, and no observer can arbitrate it remotely — so every observer must reach the same
///    answer. Lowest key is arbitrary but total, computed identically everywhere, and stable as
///    peers come and go.
pub fn resolve(claims: Vec<Claim>, device_names: &HashSet<String>) -> Resolved {
    let mut best: HashMap<String, Claim> = HashMap::new();
    let mut shadowed = HashSet::new();
    for claim in claims {
        if device_names.contains(&claim.hostname) {
            shadowed.insert((claim.pubkey, claim.name));
            continue;
        }
        match best.get(&claim.hostname) {
            Some(held) if held.pubkey <= claim.pubkey => {
                shadowed.insert((claim.pubkey, claim.name));
            }
            Some(held) => {
                shadowed.insert((held.pubkey, held.name.clone()));
                best.insert(claim.hostname.clone(), claim);
            }
            None => {
                best.insert(claim.hostname.clone(), claim);
            }
        }
    }
    Resolved {
        names: best.into_iter().map(|(name, c)| (name, c.ip)).collect(),
        shadowed,
    }
}

fn claim(pubkey: [u8; 32], user: &str, ip: Ipv4Addr, s: &MeshService) -> Claim {
    Claim {
        pubkey,
        ip,
        name: s.name.clone(),
        hostname: format!("{}.{}.{}", s.name, user, common::DNS_SUFFIX).to_ascii_lowercase(),
        proto: s.proto,
        port: s.port,
        kind: s.kind,
    }
}

/// This device's own claims.
pub fn own_claims(me: &SelfDevice, my_pubkey: [u8; 32], own: &[MeshService]) -> Vec<Claim> {
    own.iter()
        .map(|s| claim(my_pubkey, &me.username, me.wg_ip, s))
        .collect()
}

/// What each peer last announced, composed under *that peer's* verified user label.
pub fn peer_claims(seeds: &[SeedPeer], book: &ServiceBook) -> Vec<Claim> {
    seeds
        .iter()
        .flat_map(|seed| {
            book.get(&seed.pubkey)
                .into_iter()
                .map(move |s| claim(seed.pubkey, &seed.username, seed.ip, &s))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(pubkey: u8, name: &str, user: &str, last: u8) -> Claim {
        Claim {
            pubkey: [pubkey; 32],
            ip: Ipv4Addr::new(100, 64, 0, last),
            name: name.into(),
            hostname: format!("{name}.{user}.{}", common::DNS_SUFFIX),
            proto: common::control::Proto::Tcp,
            port: 25565,
            kind: common::service::ServiceKind::Port,
        }
    }

    /// The tiebreak must not depend on the order claims happened to arrive in — two devices seeing
    /// the same conflict have no way to compare notes, so the rule has to be a pure function.
    #[test]
    fn a_label_two_of_an_owners_devices_claim_resolves_to_the_lowest_key_either_way() {
        let a = claim(1, "mc", "alice", 5);
        let b = claim(2, "mc", "alice", 9);
        for order in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
            let r = resolve(order, &HashSet::new());
            assert_eq!(
                r.names[&format!("mc.alice.{}", common::DNS_SUFFIX)],
                Ipv4Addr::new(100, 64, 0, 5)
            );
            assert_eq!(r.shadowed, HashSet::from([([2u8; 32], "mc".to_string())]));
        }
    }

    /// A service label can never take a device's name away: the device name is coordinator-allocated
    /// and attested, the service label is self-asserted, so the attested one wins.
    #[test]
    fn a_device_name_is_never_shadowed_by_a_service() {
        let taken = format!("mc.alice.{}", common::DNS_SUFFIX);
        let r = resolve(
            vec![claim(1, "mc", "alice", 5)],
            &HashSet::from([taken.clone()]),
        );
        assert!(r.names.is_empty(), "the device keeps its own name");
        assert_eq!(r.shadowed, HashSet::from([([1u8; 32], "mc".to_string())]));
    }

    /// Same label, different owners, is not a conflict at all — the names differ.
    #[test]
    fn the_same_label_under_two_owners_is_two_names() {
        let r = resolve(
            vec![claim(1, "mc", "alice", 5), claim(2, "mc", "bob", 9)],
            &HashSet::new(),
        );
        assert_eq!(r.names.len(), 2);
        assert!(r.shadowed.is_empty());
    }

    /// The kind has to survive from the announcement into the claim: it is what tells the frontend
    /// a name is reached over https under the certificate domain rather than dialled on the port
    /// below it. Dropped here, every web service is displayed as its loopback backend.
    #[test]
    fn a_web_services_kind_reaches_the_claim() {
        let me = SelfDevice {
            community_name: "c".into(),
            user_id: 1,
            username: "alice".into(),
            networks: Vec::new(),
            wg_ip: Ipv4Addr::new(100, 64, 0, 1),
            wg_net: "100.64.0.0/10".parse().unwrap(),
            hostname: "laptop.alice.unity.internal".into(),
            is_primary: true,
            grant_expires_at: 0,
            primary_alias: None,
            networks_status: Vec::new(),
            dns_domain: Some("mesh.example.com".into()),
        };
        let own = [
            MeshService {
                name: "wiki".into(),
                proto: common::control::Proto::Tcp,
                port: 8080,
                kind: common::service::ServiceKind::Web,
            },
            MeshService {
                name: "mc".into(),
                proto: common::control::Proto::Tcp,
                port: 25565,
                kind: common::service::ServiceKind::Port,
            },
        ];
        let claims = own_claims(&me, [1u8; 32], &own);
        assert_eq!(claims[0].kind, common::service::ServiceKind::Web);
        assert_eq!(claims[1].kind, common::service::ServiceKind::Port);
    }

    #[test]
    fn a_peer_is_polled_again_only_once_its_entry_is_stale() {
        let book = ServiceBook::default();
        let key = [7u8; 32];
        let now = Instant::now();
        assert!(book.is_due(&key, now), "never polled");
        book.set(key, vec![], now);
        assert!(!book.is_due(&key, now));
        assert!(book.is_due(&key, now + REFRESH));
    }

    #[test]
    fn re_announcing_the_same_list_is_not_a_change() {
        let book = ServiceBook::default();
        let now = Instant::now();
        let svc = MeshService {
            name: "mc".into(),
            proto: common::control::Proto::Tcp,
            port: 25565,
            kind: Default::default(),
        };
        assert!(book.set([1u8; 32], vec![svc.clone()], now), "first sight");
        assert!(!book.set([1u8; 32], vec![svc.clone()], now), "identical");
        assert!(book.set([1u8; 32], vec![], now), "withdrawn");
    }

    #[test]
    fn a_departed_peers_services_are_forgotten() {
        let book = ServiceBook::default();
        let now = Instant::now();
        book.set([1u8; 32], vec![], now);
        book.set([2u8; 32], vec![], now);
        book.retain_peers(&HashSet::from([[1u8; 32]]));
        assert!(!book.is_due(&[1u8; 32], now), "still held");
        assert!(book.is_due(&[2u8; 32], now), "forgotten");
    }
}
