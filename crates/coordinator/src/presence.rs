//! In-memory presence: who is currently registered in each network, with their pubkey/ip and
//! last-reported endpoint. Rebuilt as members register/refresh; lost on restart (by design —
//! seeds repopulate). Used to hand new joiners their co-members (design.md §5).

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;

#[derive(Clone)]
pub struct MemberPresence {
    pub pubkey: [u8; 32],
    pub ip: Ipv4Addr,
    pub nick: String,
    pub endpoint: Option<SocketAddr>,
}

#[derive(Default)]
pub struct Presence {
    // (guild_id, role_id, user_id) -> presence
    map: Mutex<HashMap<(u64, u64, u64), MemberPresence>>,
}

impl Presence {
    pub fn record(&self, guild_id: u64, role_id: u64, user_id: u64, p: MemberPresence) {
        self.map
            .lock()
            .unwrap()
            .insert((guild_id, role_id, user_id), p);
    }

    /// Other members present in a network, excluding `exclude_user`.
    pub fn others_in(
        &self,
        guild_id: u64,
        role_id: u64,
        exclude_user: u64,
    ) -> Vec<(u64, MemberPresence)> {
        self.map
            .lock()
            .unwrap()
            .iter()
            .filter(|((g, r, u), _)| *g == guild_id && *r == role_id && *u != exclude_user)
            .map(|((_, _, u), p)| (*u, p.clone()))
            .collect()
    }
}
