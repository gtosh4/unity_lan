//! In-memory presence: which **devices** are currently registered in each network, with their
//! pubkey/ip/owner and last-reported endpoint. Rebuilt as members register/refresh; lost on
//! restart (by design — seeds repopulate). Used to hand new joiners their co-members (§5).
//!
//! Keyed by (guild, role, device pubkey) so a user's multiple devices don't collide.

use std::collections::{BTreeSet, HashMap};
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

/// A presence entry: the device's live info plus when we last heard from it. `last_seen` is kept
/// out of `MemberPresence`'s `PartialEq` (it lives here, not there) so a steady-state re-record
/// still compares equal and doesn't spuriously bump the version every refresh.
struct Entry {
    p: MemberPresence,
    last_seen: u64,
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
    pub fn record(&self, guild_id: u64, role_id: u64, p: MemberPresence, now: u64) -> bool {
        let key = (guild_id, role_id, p.pubkey);
        let mut map = self.map.lock().unwrap();
        let changed = map.get(&key).map(|e| &e.p) != Some(&p);
        map.insert(key, Entry { p, last_seen: now });
        changed
    }

    /// Record a device in the per-user online set (own-device peering). Semantics mirror [`record`]:
    /// returns `true` if it changed the map (new device / altered fields) so the caller bumps the
    /// version; an identical re-record refreshes `last_seen` only.
    pub fn record_self(&self, user_id: u64, p: MemberPresence, now: u64) -> bool {
        let key = (user_id, p.pubkey);
        let mut map = self.self_map.lock().unwrap();
        let changed = map.get(&key).map(|e| &e.p) != Some(&p);
        map.insert(key, Entry { p, last_seen: now });
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
    /// online-device count per `(guild_id, role_id)` plus deployment-wide distinct totals. A device
    /// present in N networks contributes to N per-network counts but is one `online_device` and its
    /// owner one `online_user`.
    pub fn stats(&self) -> PresenceStats {
        let map = self.map.lock().unwrap();
        let mut online_per_network: HashMap<(u64, u64), usize> = HashMap::new();
        let mut devices = std::collections::HashSet::new();
        let mut users = std::collections::HashSet::new();
        for ((g, r, pk), e) in map.iter() {
            *online_per_network.entry((*g, *r)).or_default() += 1;
            devices.insert(*pk);
            users.insert(e.p.user_id);
        }
        PresenceStats {
            online_per_network,
            online_devices: devices.len(),
            online_users: users.len(),
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
    /// Distinct devices currently online across the deployment.
    pub online_devices: usize,
    /// Distinct users currently online across the deployment.
    pub online_users: usize,
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
        p.record(1, 2, mp([9; 32], 42), 0);
        assert_eq!(p.networks_of(&[9; 32]), vec![(1, 2)]);
        assert!(p.evict(1, 2, &[9; 32]));
        assert!(p.networks_of(&[9; 32]).is_empty());
        assert!(!p.evict(1, 2, &[9; 32])); // second evict is a no-op
    }

    #[test]
    fn evict_user_drops_all_their_devices_in_network() {
        let p = Presence::default();
        p.record(1, 2, mp([1; 32], 42), 0); // user 42, device A
        p.record(1, 2, mp([2; 32], 42), 0); // user 42, device B
        p.record(1, 2, mp([3; 32], 99), 0); // other user
        assert!(p.evict_user(1, 2, 42));
        // both of 42's devices gone; the other user's stays.
        assert_eq!(p.others_in(1, 2, &[0; 32]).len(), 1);
        assert!(!p.evict_user(1, 2, 42));
    }

    #[test]
    fn reap_evicts_only_stale_entries() {
        let p = Presence::default();
        p.record(1, 2, mp([1; 32], 42), 100); // last seen t=100
        p.record(1, 2, mp([2; 32], 99), 150); // last seen t=150
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
        p.record(1, 2, mp([1; 32], 42), 0);
        p.record(1, 3, mp([1; 32], 42), 0);
        p.record(1, 2, mp([2; 32], 42), 0);
        p.record(1, 2, mp([3; 32], 99), 0);
        let s = p.stats();
        assert_eq!(s.online_per_network[&(1, 2)], 3); // A, B, C
        assert_eq!(s.online_per_network[&(1, 3)], 1); // A only
        assert_eq!(s.online_devices, 3); // A, B, C distinct
        assert_eq!(s.online_users, 2); // 42, 99
    }

    #[test]
    fn membership_dedupes_devices_per_user_and_sorts() {
        let p = Presence::default();
        // user 42 has two devices in network (1,2) — one edge; also in (1,3). user 99 in (1,2).
        p.record(1, 2, mp([1; 32], 42), 0);
        p.record(1, 2, mp([2; 32], 42), 0);
        p.record(1, 3, mp([1; 32], 42), 0);
        p.record(1, 2, mp([3; 32], 99), 0);
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
        assert!(p.record_self(42, mp([1; 32], 42), 100));
        assert!(p.record_self(42, mp([2; 32], 42), 100));
        assert!(p.record_self(99, mp([3; 32], 99), 100));
        // A sees only its sibling B, never user 99's C.
        let others: Vec<_> = p
            .others_of_user(42, &[1; 32])
            .iter()
            .map(|m| m.pubkey)
            .collect();
        assert_eq!(others, vec![[2; 32]]);
        // Identical re-record doesn't report a change (no spurious version bump).
        assert!(!p.record_self(42, mp([2; 32], 42), 200));
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
        assert!(p.record(1, 2, mp([1; 32], 42), 100)); // new → changed
        assert!(!p.record(1, 2, mp([1; 32], 42), 300)); // identical → no wake, but re-stamped
                                                        // The re-stamp at t=300 keeps it alive: at t=340, age 40 ≤ 60, survives.
        assert!(p.reap(340, 60).is_empty());
        assert_eq!(p.networks_of(&[1; 32]), vec![(1, 2)]);
    }
}
