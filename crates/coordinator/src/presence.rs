//! In-memory presence: which **devices** are currently registered in each network, with their
//! pubkey/ip/owner and last-reported endpoint. Rebuilt as members register/refresh; lost on
//! restart (by design — seeds repopulate). Used to hand new joiners their co-members (§5).
//!
//! Keyed by (guild, role, device pubkey) so a user's multiple devices don't collide.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;

use crate::versions::Scope;

#[derive(Clone, PartialEq)]
pub struct MemberPresence {
    pub pubkey: [u8; 32],
    pub ip: Ipv4Addr,
    pub user_id: u64,
    pub username: String,
    pub device_name: String,
    pub is_primary: bool,
    pub endpoint: Option<SocketAddr>,
}

/// A presence entry: the device's live info plus when we last heard from it. `last_seen` and
/// `client_version` are both kept out of `MemberPresence`'s `PartialEq` (they live here, not there)
/// so a steady-state re-record — including a client that just auto-updated to a new version — still
/// compares equal and doesn't spuriously bump the membership version and wake the herd. The version
/// is peering-irrelevant; it's tracked only for the operator's fleet view (`stats`).
struct Entry {
    p: MemberPresence,
    last_seen: u64,
    /// The device's reported release version (`RegisterReq::client_version`), `""` from a
    /// pre-versioning client. Refreshed on every record so it tracks a device across an update.
    client_version: String,
}

#[derive(Default)]
pub struct Presence {
    // (guild_id, role_id, device_pubkey) -> entry
    // The composite key is the domain model; a type alias would hide it.
    #[allow(clippy::type_complexity)]
    map: Mutex<HashMap<(u64, u64, [u8; 32]), Entry>>,
    // (user_id, device_pubkey) -> entry: every online device, keyed by owner independent of any
    // network — the source for **own-device peering**, so a user's devices can seed each other even
    // when they share no network. Recorded only when the device opts in (`peer_own_devices`) and is
    // live; reaped/evicted on the same paths as `map`.
    self_map: Mutex<HashMap<(u64, [u8; 32]), Entry>>,
}

impl Presence {
    /// Record a device's presence in a network (stamping `now` as its last-seen time). Returns
    /// `true` if this changed the map (a new device or altered fields) — the caller bumps the
    /// membership version so parked long-polls wake. An identical re-record (steady-state refresh)
    /// returns `false` → no wake, but still refreshes `last_seen` so the reaper leaves it alone.
    pub fn record(
        &self,
        guild_id: u64,
        role_id: u64,
        p: MemberPresence,
        client_version: String,
        now: u64,
    ) -> bool {
        let key = (guild_id, role_id, p.pubkey);
        let mut map = self.map.lock().unwrap();
        let changed = map.get(&key).map(|e| &e.p) != Some(&p);
        map.insert(
            key,
            Entry {
                p,
                last_seen: now,
                client_version,
            },
        );
        changed
    }

    /// Every device pubkey currently present — in any network (`map`) or as an own-device peer
    /// (`self_map`). Used by the presence reaper to prune per-device NAT side-tables (reflexive /
    /// source-IP / relay / ICE) of entries whose device has gone offline, so those maps track live
    /// membership instead of accumulating every pubkey ever seen.
    pub fn present_pubkeys(&self) -> std::collections::HashSet<[u8; 32]> {
        let mut set = std::collections::HashSet::new();
        set.extend(self.map.lock().unwrap().keys().map(|(_, _, pk)| *pk));
        set.extend(self.self_map.lock().unwrap().keys().map(|(_, pk)| *pk));
        set
    }

    /// Record a device in the per-user online set (own-device peering). Semantics mirror [`record`]:
    /// returns `true` if it changed the map (new device / altered fields) so the caller bumps the
    /// version; an identical re-record refreshes `last_seen` only.
    pub fn record_self(
        &self,
        user_id: u64,
        p: MemberPresence,
        client_version: String,
        now: u64,
    ) -> bool {
        let key = (user_id, p.pubkey);
        let mut map = self.self_map.lock().unwrap();
        let changed = map.get(&key).map(|e| &e.p) != Some(&p);
        map.insert(
            key,
            Entry {
                p,
                last_seen: now,
                client_version,
            },
        );
        changed
    }

    /// Drop a device from the per-user online set (own-device peering) — on opt-out, pause, role
    /// loss, or a re-key retiring the old pubkey. Returns `true` if an entry was removed.
    pub fn evict_self(&self, user_id: u64, pubkey: &[u8; 32]) -> bool {
        self.self_map
            .lock()
            .unwrap()
            .remove(&(user_id, *pubkey))
            .is_some()
    }

    /// The user's other online devices (own-device peering), excluding the caller (`exclude_pubkey`).
    /// Queried only for the caller's own `user_id`, so it never exposes another user's devices.
    pub fn others_of_user(&self, user_id: u64, exclude_pubkey: &[u8; 32]) -> Vec<MemberPresence> {
        self.self_map
            .lock()
            .unwrap()
            .iter()
            .filter(|((uid, pk), _)| *uid == user_id && pk != exclude_pubkey)
            .map(|(_, e)| e.p.clone())
            .collect()
    }

    /// Evict every entry not refreshed within `max_age` seconds, across **both** the per-network and
    /// per-user (own-device) sets. Catches devices that vanished without a clean drop: a crashed
    /// client, or one that **re-keyed** and abandoned this pubkey (its owner now refreshes under a
    /// new key, so this entry is never self-evicted). Returns the [`Scope`]s it removed something
    /// from → the caller bumps exactly those, so co-members prune the dead peer without waking
    /// clients of guilds the reap never touched.
    pub fn reap(&self, now: u64, max_age: u64) -> BTreeSet<Scope> {
        let fresh = |e: &Entry| now.saturating_sub(e.last_seen) <= max_age;
        let mut changed = BTreeSet::new();
        {
            let mut map = self.map.lock().unwrap();
            map.retain(|(g, _, _), e| {
                fresh(e) || {
                    changed.insert(Scope::Guild(*g));
                    false
                }
            });
        }
        {
            let mut sm = self.self_map.lock().unwrap();
            sm.retain(|(uid, _), e| {
                fresh(e) || {
                    changed.insert(Scope::User(*uid));
                    false
                }
            });
        }
        changed
    }

    /// The networks a device is currently recorded in. Used to detect networks the caller has
    /// dropped since last refresh (role revoked) so its stale presence there can be evicted.
    pub fn networks_of(&self, pubkey: &[u8; 32]) -> Vec<(u64, u64)> {
        self.map
            .lock()
            .unwrap()
            .keys()
            .filter(|(_, _, pk)| pk == pubkey)
            .map(|(g, r, _)| (*g, *r))
            .collect()
    }

    /// Drop a device's presence in one network. Returns `true` if an entry was removed — the
    /// caller bumps the membership version so peers parked in long-poll wake and prune it.
    pub fn evict(&self, guild_id: u64, role_id: u64, pubkey: &[u8; 32]) -> bool {
        self.map
            .lock()
            .unwrap()
            .remove(&(guild_id, role_id, *pubkey))
            .is_some()
    }

    /// Drop every device a user has in one network (role revoked at the source). Returns `true` if
    /// anything was removed. Used by the live gateway when a member loses a role.
    pub fn evict_user(&self, guild_id: u64, role_id: u64, user_id: u64) -> bool {
        let mut map = self.map.lock().unwrap();
        let before = map.len();
        map.retain(|(g, r, _), e| !(*g == guild_id && *r == role_id && e.p.user_id == user_id));
        map.len() != before
    }

    /// Other devices present in a network, excluding the caller's own device (`exclude_pubkey`).
    pub fn others_in(
        &self,
        guild_id: u64,
        role_id: u64,
        exclude_pubkey: &[u8; 32],
    ) -> Vec<MemberPresence> {
        self.map
            .lock()
            .unwrap()
            .iter()
            .filter(|((g, r, pk), _)| *g == guild_id && *r == role_id && pk != exclude_pubkey)
            .map(|(_, e)| e.p.clone())
            .collect()
    }

    /// A point-in-time count of live presence for the admin dashboard, taken under one lock:
    /// online device *and* distinct-user counts per `(guild_id, role_id)`, plus deployment-wide
    /// distinct totals. A device present in N networks contributes to N per-network counts but is
    /// one `online_device` and its owner one `online_user`; a user with several devices in the
    /// same network counts once in that network's user count.
    pub fn stats(&self) -> PresenceStats {
        // Both locks, in the same order the reaper takes them (map then self_map) so the two paths
        // can't deadlock against each other.
        let map = self.map.lock().unwrap();
        let self_map = self.self_map.lock().unwrap();
        let mut online_per_network: HashMap<(u64, u64), usize> = HashMap::new();
        let mut users_by_network: HashMap<(u64, u64), std::collections::HashSet<u64>> =
            HashMap::new();
        let mut devices = std::collections::HashSet::new();
        let mut users = std::collections::HashSet::new();
        // Each device reports one version; it appears in one map row per network, so collapse to
        // pubkey first, then tally — otherwise a device in N networks would count N times.
        let mut device_version: HashMap<[u8; 32], String> = HashMap::new();
        // Pubkeys recorded in ≥1 network, so the own-device pass below can tell which of its devices
        // are *only* reachable as own-devices (on no network) — the off-network bucket.
        let mut network_pubkeys = std::collections::HashSet::new();
        for ((g, r, pk), e) in map.iter() {
            *online_per_network.entry((*g, *r)).or_default() += 1;
            users_by_network
                .entry((*g, *r))
                .or_default()
                .insert(e.p.user_id);
            devices.insert(*pk);
            users.insert(e.p.user_id);
            network_pubkeys.insert(*pk);
            device_version
                .entry(*pk)
                .or_insert_with(|| e.client_version.clone());
        }
        // Fold in own-device presence: a device on no *enabled* network still long-polls and stays
        // reachable to its owner's other devices, so it's genuinely online — it must count toward the
        // deployment totals and the version fleet, or a mesh living entirely on own-device peering
        // reads as empty. A pubkey already seen in a network is deduped by the sets; one seen only
        // here is an off-network device.
        let mut off_network = std::collections::HashSet::new();
        for ((uid, pk), e) in self_map.iter() {
            devices.insert(*pk);
            users.insert(*uid);
            device_version
                .entry(*pk)
                .or_insert_with(|| e.client_version.clone());
            if !network_pubkeys.contains(pk) {
                off_network.insert(*pk);
            }
        }
        // Tally distinct devices per version. An empty string (a pre-versioning client) buckets as
        // "unknown" so both the JSON feed and the Prometheus label carry a clean value.
        let mut client_versions: BTreeMap<String, usize> = BTreeMap::new();
        for v in device_version.into_values() {
            let label = if v.is_empty() {
                "unknown".to_string()
            } else {
                v
            };
            *client_versions.entry(label).or_default() += 1;
        }
        PresenceStats {
            online_per_network,
            users_per_network: users_by_network
                .into_iter()
                .map(|(k, v)| (k, v.len()))
                .collect(),
            online_devices: devices.len(),
            online_users: users.len(),
            off_network_devices: off_network.len(),
            client_versions,
        }
    }

    /// Distinct `(guild_id, role_id, user_id)` membership edges for the admin network graph —
    /// one per user per network they're currently online in, collapsing a user's several devices
    /// in the same network to a single edge. Sorted, so the graph (and its DOT export) is stable
    /// across renders. Off the hot path: taken under one lock on a rare operator request.
    pub fn membership(&self) -> Vec<(u64, u64, u64)> {
        let map = self.map.lock().unwrap();
        let edges: BTreeSet<(u64, u64, u64)> = map
            .iter()
            .map(|((g, r, _), e)| (*g, *r, e.p.user_id))
            .collect();
        edges.into_iter().collect()
    }
}

/// A snapshot of live presence counts for the admin dashboard (see [`Presence::stats`]).
pub struct PresenceStats {
    /// Online device count keyed by `(guild_id, role_id)`.
    pub online_per_network: HashMap<(u64, u64), usize>,
    /// Distinct online *users* keyed by `(guild_id, role_id)` — a user's several devices in one
    /// network collapse to one.
    pub users_per_network: HashMap<(u64, u64), usize>,
    /// Distinct devices currently online across the deployment — on a network *or* reachable only
    /// as an own-device (on no enabled network). A device that has opted out of own-device peering
    /// *and* holds no enabled network peers with nobody, so it isn't in presence at all and isn't
    /// counted here.
    pub online_devices: usize,
    /// Distinct users currently online across the deployment (same union as `online_devices`).
    pub online_users: usize,
    /// Distinct online devices present *only* via own-device peering — on no network. Counted in
    /// `online_devices`; broken out so the dashboard's per-network breakdown plus this reconciles to
    /// the total, and so version tracking accounts for a fleet that lives on own-device peering.
    pub off_network_devices: usize,
    /// Distinct online devices per reported client version (`""` bucketed as `"unknown"`), sorted
    /// by version. The operator's fleet view — how many of each release are live, so a phased wire
    /// change (e.g. retiring an attestation layout) can be gated on "no old client remains".
    pub client_versions: BTreeMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mp(pubkey: [u8; 32], user_id: u64) -> MemberPresence {
        MemberPresence {
            pubkey,
            ip: Ipv4Addr::new(100, 64, 0, 1),
            user_id,
            username: "u".into(),
            device_name: "d".into(),
            is_primary: false,
            endpoint: None,
        }
    }

    #[test]
    fn evict_removes_and_reports_change() {
        let p = Presence::default();
        p.record(1, 2, mp([9; 32], 42), "".into(), 0);
        assert_eq!(p.networks_of(&[9; 32]), vec![(1, 2)]);
        assert!(p.evict(1, 2, &[9; 32]));
        assert!(p.networks_of(&[9; 32]).is_empty());
        assert!(!p.evict(1, 2, &[9; 32])); // second evict is a no-op
    }

    #[test]
    fn evict_user_drops_all_their_devices_in_network() {
        let p = Presence::default();
        p.record(1, 2, mp([1; 32], 42), "".into(), 0); // user 42, device A
        p.record(1, 2, mp([2; 32], 42), "".into(), 0); // user 42, device B
        p.record(1, 2, mp([3; 32], 99), "".into(), 0); // other user
        assert!(p.evict_user(1, 2, 42));
        // both of 42's devices gone; the other user's stays.
        assert_eq!(p.others_in(1, 2, &[0; 32]).len(), 1);
        assert!(!p.evict_user(1, 2, 42));
    }

    #[test]
    fn present_pubkeys_unions_network_and_own_device_entries() {
        let p = Presence::default();
        p.record(1, 2, mp([1; 32], 42), "".into(), 0); // network presence
        p.record_self(42, mp([2; 32], 42), "".into(), 0); // own-device-only presence
        let present = p.present_pubkeys();
        assert_eq!(present.len(), 2);
        assert!(present.contains(&[1; 32]));
        assert!(present.contains(&[2; 32]));
        // A device that was reaped no longer counts as present.
        p.reap(u64::MAX, 0);
        assert!(p.present_pubkeys().is_empty());
    }

    #[test]
    fn reap_evicts_only_stale_entries() {
        let p = Presence::default();
        p.record(1, 2, mp([1; 32], 42), "".into(), 100); // last seen t=100
        p.record(1, 2, mp([2; 32], 99), "".into(), 150); // last seen t=150
                                                         // At t=200 with max_age 60: entry A (age 100) is stale, B (age 50) is fresh.
                                                         // Only guild 1's scope is reported — no other guild's clients are woken.
        assert_eq!(p.reap(200, 60), [Scope::Guild(1)].into_iter().collect());
        assert!(p.networks_of(&[1; 32]).is_empty());
        assert_eq!(p.networks_of(&[2; 32]), vec![(1, 2)]);
        // Nothing left to reap → no scopes reported (no spurious version bump).
        assert!(p.reap(200, 60).is_empty());
    }

    #[test]
    fn stats_counts_per_network_and_distinct_totals() {
        let p = Presence::default();
        // user 42 device A in two networks; user 42 device B in one; user 99 device C in one.
        // A runs 0.3.0 and is recorded in two networks — it must still count once for its version.
        // B also 0.3.0; C is a pre-versioning client ("" → "unknown").
        p.record(1, 2, mp([1; 32], 42), "0.3.0".into(), 0);
        p.record(1, 3, mp([1; 32], 42), "0.3.0".into(), 0);
        p.record(1, 2, mp([2; 32], 42), "0.3.0".into(), 0);
        p.record(1, 2, mp([3; 32], 99), "".into(), 0);
        // A is also in the own-device set (as a real device on a network would be) — it must not
        // double-count nor read as off-network. Device D (user 77, version 0.4.0) is own-device
        // *only*: on no network, yet online and reachable to its owner's siblings.
        p.record_self(42, mp([1; 32], 42), "0.3.0".into(), 0);
        p.record_self(77, mp([4; 32], 77), "0.4.0".into(), 0);
        let s = p.stats();
        assert_eq!(s.online_per_network[&(1, 2)], 3); // A, B, C
        assert_eq!(s.online_per_network[&(1, 3)], 1); // A only
        assert_eq!(s.users_per_network[&(1, 2)], 2); // 42 (A+B collapse), 99
        assert_eq!(s.users_per_network[&(1, 3)], 1); // 42 only
        assert_eq!(s.online_devices, 4); // A, B, C, D — D folds in from own-device presence
        assert_eq!(s.online_users, 3); // 42, 99, 77
        assert_eq!(s.off_network_devices, 1); // D only (A is on a network, so not off-network)
                                              // A (in two networks + own-device) counts once; D's version joins the fleet view.
        assert_eq!(s.client_versions[&"0.3.0".to_string()], 2); // A, B
        assert_eq!(s.client_versions[&"unknown".to_string()], 1); // C
        assert_eq!(s.client_versions[&"0.4.0".to_string()], 1); // D
    }

    #[test]
    fn membership_dedupes_devices_per_user_and_sorts() {
        let p = Presence::default();
        // user 42 has two devices in network (1,2) — one edge; also in (1,3). user 99 in (1,2).
        p.record(1, 2, mp([1; 32], 42), "".into(), 0);
        p.record(1, 2, mp([2; 32], 42), "".into(), 0);
        p.record(1, 3, mp([1; 32], 42), "".into(), 0);
        p.record(1, 2, mp([3; 32], 99), "".into(), 0);
        assert_eq!(
            p.membership(),
            vec![(1, 2, 42), (1, 2, 99), (1, 3, 42)],
            "one edge per user per network, sorted"
        );
    }

    #[test]
    fn self_presence_scopes_to_owner_and_reaps() {
        let p = Presence::default();
        // user 42 devices A & B; user 99 device C.
        assert!(p.record_self(42, mp([1; 32], 42), "".into(), 100));
        assert!(p.record_self(42, mp([2; 32], 42), "".into(), 100));
        assert!(p.record_self(99, mp([3; 32], 99), "".into(), 100));
        // A sees only its sibling B, never user 99's C.
        let others: Vec<_> = p
            .others_of_user(42, &[1; 32])
            .iter()
            .map(|m| m.pubkey)
            .collect();
        assert_eq!(others, vec![[2; 32]]);
        // Identical re-record doesn't report a change (no spurious version bump).
        assert!(!p.record_self(42, mp([2; 32], 42), "".into(), 200));
        // Explicit evict removes B; a second evict is a no-op.
        assert!(p.evict_self(42, &[2; 32]));
        assert!(!p.evict_self(42, &[2; 32]));
        assert!(p.others_of_user(42, &[1; 32]).is_empty());
        // Reap ages out the per-user set too: at t=400, max_age 60, A (last seen 100) is stale —
        // and it reports the *user* scope, since own-device peering crosses guilds.
        assert_eq!(
            p.reap(400, 60),
            [Scope::User(42), Scope::User(99)].into_iter().collect()
        );
        assert!(p.others_of_user(99, &[0; 32]).is_empty());
    }

    #[test]
    fn record_refreshes_last_seen_without_reporting_change() {
        let p = Presence::default();
        assert!(p.record(1, 2, mp([1; 32], 42), "".into(), 100)); // new → changed
        assert!(!p.record(1, 2, mp([1; 32], 42), "".into(), 300)); // identical → no wake, but re-stamped
                                                                   // The re-stamp at t=300 keeps it alive: at t=340, age 40 ≤ 60, survives.
        assert!(p.reap(340, 60).is_empty());
        assert_eq!(p.networks_of(&[1; 32]), vec![(1, 2)]);
    }
}
