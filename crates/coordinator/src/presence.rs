//! In-memory presence: which **devices** are currently registered in each network, with their
//! pubkey/ip/owner and last-reported endpoint. Rebuilt as members register/refresh; lost on
//! restart (by design — seeds repopulate). Used to hand new joiners their co-members (§5).
//!
//! Keyed by (guild, role, device pubkey) so a user's multiple devices don't collide.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;

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

#[derive(Default)]
pub struct Presence {
    // (guild_id, role_id, device_pubkey) -> presence
    map: Mutex<HashMap<(u64, u64, [u8; 32]), MemberPresence>>,
}

impl Presence {
    /// Record a device's presence in a network. Returns `true` if this changed the map (a new
    /// device or altered fields) — the caller bumps the membership version so parked long-polls
    /// wake. An identical re-record (steady-state refresh) returns `false` → no wake.
    pub fn record(&self, guild_id: u64, role_id: u64, p: MemberPresence) -> bool {
        let key = (guild_id, role_id, p.pubkey);
        let mut map = self.map.lock().unwrap();
        let changed = map.get(&key) != Some(&p);
        map.insert(key, p);
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
        map.retain(|(g, r, _), p| !(*g == guild_id && *r == role_id && p.user_id == user_id));
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
            .map(|(_, p)| p.clone())
            .collect()
    }
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
        p.record(1, 2, mp([9; 32], 42));
        assert_eq!(p.networks_of(&[9; 32]), vec![(1, 2)]);
        assert!(p.evict(1, 2, &[9; 32]));
        assert!(p.networks_of(&[9; 32]).is_empty());
        assert!(!p.evict(1, 2, &[9; 32])); // second evict is a no-op
    }

    #[test]
    fn evict_user_drops_all_their_devices_in_network() {
        let p = Presence::default();
        p.record(1, 2, mp([1; 32], 42)); // user 42, device A
        p.record(1, 2, mp([2; 32], 42)); // user 42, device B
        p.record(1, 2, mp([3; 32], 99)); // other user
        assert!(p.evict_user(1, 2, 42));
        // both of 42's devices gone; the other user's stays.
        assert_eq!(p.others_in(1, 2, &[0; 32]).len(), 1);
        assert!(!p.evict_user(1, 2, 42));
    }
}
