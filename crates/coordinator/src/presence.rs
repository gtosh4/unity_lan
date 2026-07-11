//! In-memory presence: which **devices** are currently registered in each network, with their
//! pubkey/ip/owner and last-reported endpoint. Rebuilt as members register/refresh; lost on
//! restart (by design — seeds repopulate). Used to hand new joiners their co-members (§5).
//!
//! Keyed by (guild, role, device pubkey) so a user's multiple devices don't collide.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;

#[derive(Clone)]
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
    pub fn record(&self, guild_id: u64, role_id: u64, p: MemberPresence) {
        self.map
            .lock()
            .unwrap()
            .insert((guild_id, role_id, p.pubkey), p);
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
