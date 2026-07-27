//! "This user holds no network role anywhere" — remembered, briefly.
//!
//! Answering that question costs one Discord member lookup **per registered guild**, because a user
//! who is in none of them produces no cacheable member row (`discord.rs` caches successful fetches
//! only, deliberately: a miss must not pin a real member as absent). Before personal-scope meshing
//! that cost was paid by nobody — a caller with no role was a rare stray. Now it is paid by every
//! solo user, on every renewal *and* every herd wake, multiplied by the number of guilds the
//! deployment serves. That is the fan-out CLAUDE.md warns about, arriving through the front door.
//!
//! So the answer is memoized per **user**, not per `(guild, user)`: one entry instead of one per
//! guild, and a hit skips the whole walk rather than making it cheaper. The staleness this admits is
//! in the fail-closed direction — a user who *gains* a role waits, they are never wrongly admitted —
//! and the gateway closes even that: a role change fires `MemberUpdate`, which forgets the entry
//! (see `commands::revoke`). The TTL is only the backstop for a dropped event.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long "no roles anywhere" is trusted. Comfortably longer than a long-poll hold, or a solo
/// user's every renewal would re-walk every guild and the memo would buy nothing.
const TTL: Duration = Duration::from_secs(600);

/// Prune expired entries once the map grows past this. Entries are only added for users who hold no
/// role, so the map is bounded by that population — but nothing removes an expired one on its own.
const PRUNE_AT: usize = 4096;

#[derive(Default)]
pub struct RolelessMemo {
    seen: Mutex<HashMap<u64, Instant>>,
}

impl RolelessMemo {
    /// Whether we recently established that this user holds no network role anywhere.
    pub fn fresh(&self, user_id: u64) -> bool {
        let seen = self.seen.lock().unwrap();
        seen.get(&user_id).is_some_and(|t| t.elapsed() < TTL)
    }

    /// Record that a full walk just found no role for this user.
    pub fn remember(&self, user_id: u64) {
        let mut seen = self.seen.lock().unwrap();
        if seen.len() >= PRUNE_AT {
            seen.retain(|_, t| t.elapsed() < TTL);
        }
        seen.insert(user_id, Instant::now());
    }

    /// Drop the memo for a user whose roles may have changed — the gateway's job.
    pub fn forget(&self, user_id: u64) {
        self.seen.lock().unwrap().remove(&user_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_then_forgets() {
        let m = RolelessMemo::default();
        assert!(
            !m.fresh(7),
            "nothing is known about a user we've never walked"
        );
        m.remember(7);
        assert!(m.fresh(7));
        // A role change must take effect at once, not at the end of the window: this is the path a
        // newly-granted role travels.
        m.forget(7);
        assert!(!m.fresh(7));
    }

    #[test]
    fn an_expired_entry_is_not_fresh_and_gets_pruned() {
        let m = RolelessMemo::default();
        {
            let mut seen = m.seen.lock().unwrap();
            seen.insert(7, Instant::now() - TTL - Duration::from_secs(1));
            for u in 100..(100 + PRUNE_AT as u64) {
                seen.insert(u, Instant::now() - TTL - Duration::from_secs(1));
            }
        }
        assert!(!m.fresh(7), "past its TTL");
        // The next write past the threshold sweeps the expired entries rather than growing.
        m.remember(1);
        let seen = m.seen.lock().unwrap();
        assert_eq!(seen.len(), 1, "only the entry just written survives");
    }
}
