//! Scoped membership versions — the long-poll ETag machinery.
//!
//! The `version` a client echoes back as `since` used to be a single deployment-wide counter, so
//! *any* membership change anywhere released *every* parked long-poll: a client in guild A woke,
//! rebuilt its whole snapshot, and learned nothing because the change was in guild B. With `T`
//! devices deployed that costs `T × O(peers)` CPU per membership event — and since a coordinator
//! typically serves many small, mutually disjoint guilds, nearly all of it is waste.
//!
//! So versions are counted per [`Scope`] instead: one counter per guild, plus one per user (for
//! own-device peering, which crosses guilds). A caller's wire `version` is a hash over just the
//! scopes it participates in, so a bump in a scope it isn't in leaves its ETag untouched and it
//! stays parked. The value stays an opaque `u64` on the wire — no protocol change.
//!
//! Scope counters are created on demand and never removed: bounded by (guilds × users) seen since
//! process start, a few hundred bytes each. A restart resets them, which only costs each client one
//! immediate (non-parking) rebuild.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use tokio::sync::watch;

/// What a membership change is scoped to — the unit a client can subscribe to independently.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub enum Scope {
    /// A guild: presence joining/leaving any of its networks. Clients in other guilds don't care.
    Guild(u64),
    /// A user: their own devices coming and going. Own-device peering ignores networks, so a user's
    /// devices must wake each other even when they share no guild.
    User(u64),
}

/// Per-scope membership counters plus a deployment-wide one for the admin surface.
pub struct Versions {
    scopes: Mutex<HashMap<Scope, watch::Sender<u64>>>,
    /// Bumped on every scope bump. Feeds `/admin/stats` + `/metrics`, which are deployment-wide by
    /// definition — one operator tab, so the amplification that matters for clients doesn't apply.
    global: watch::Sender<u64>,
}

impl Default for Versions {
    fn default() -> Self {
        Self {
            scopes: Mutex::new(HashMap::new()),
            global: watch::channel(0u64).0,
        }
    }
}

impl Versions {
    /// The sender for `scope`, created at 0 on first use.
    fn sender(&self, scope: Scope) -> watch::Sender<u64> {
        self.scopes
            .lock()
            .unwrap()
            .entry(scope)
            .or_insert_with(|| watch::channel(0u64).0)
            .clone()
    }

    /// Bump every given scope (waking only the clients subscribed to them) and the global counter
    /// once. A no-op for an empty iterator — nothing changed, so nothing wakes.
    pub fn bump_all(&self, scopes: impl IntoIterator<Item = Scope>) {
        let mut any = false;
        for s in scopes {
            self.sender(s).send_modify(|v| *v += 1);
            any = true;
        }
        if any {
            self.global.send_modify(|v| *v += 1);
        }
    }

    /// Bump a single scope.
    pub fn bump(&self, scope: Scope) {
        self.bump_all([scope]);
    }

    pub fn subscribe(&self, scope: Scope) -> watch::Receiver<u64> {
        self.sender(scope).subscribe()
    }

    /// The caller's long-poll ETag: a hash over its scopes' counters. Changes iff one of *its*
    /// scopes bumped (or its scope set itself changed — scope identity is hashed too). Opaque to
    /// the client, so it need only be stable within one coordinator process.
    pub fn aggregate(&self, scopes: &BTreeSet<Scope>) -> u64 {
        use std::hash::{Hash, Hasher};
        let map = self.scopes.lock().unwrap();
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for s in scopes {
            s.hash(&mut h);
            // A scope with no counter yet has seen no change: 0, same as a freshly created one.
            map.get(s).map_or(0, |tx| *tx.borrow()).hash(&mut h);
        }
        h.finish()
    }

    /// The deployment-wide counter (admin surface only).
    pub fn global(&self) -> u64 {
        *self.global.borrow()
    }

    pub fn subscribe_global(&self) -> watch::Receiver<u64> {
        self.global.subscribe()
    }

    /// Parked long-poll count, for `/admin/stats`. Sums receivers across scopes; a client parked on
    /// its user scope plus `k` guild scopes counts `k+1` times, so this is an activity gauge rather
    /// than a client count.
    pub fn waiters(&self) -> usize {
        self.scopes
            .lock()
            .unwrap()
            .values()
            .map(|tx| tx.receiver_count())
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(scopes: impl IntoIterator<Item = Scope>) -> BTreeSet<Scope> {
        scopes.into_iter().collect()
    }

    #[test]
    fn bump_moves_only_subscribed_scopes() {
        let v = Versions::default();
        let a = set([Scope::Guild(1), Scope::User(7)]);
        let b = set([Scope::Guild(2), Scope::User(8)]);
        let (a0, b0) = (v.aggregate(&a), v.aggregate(&b));

        v.bump(Scope::Guild(1));
        assert_ne!(v.aggregate(&a), a0, "guild 1's members see the change");
        assert_eq!(v.aggregate(&b), b0, "a disjoint guild's members do not");

        v.bump(Scope::User(8));
        assert_ne!(v.aggregate(&b), b0, "own-device scope wakes its owner");
    }

    #[test]
    fn aggregate_tracks_scope_set_changes() {
        let v = Versions::default();
        // Losing a guild changes the ETag even when no counter moved, so a client whose membership
        // shrank never mistakes its old version for the current one and parks on stale state.
        assert_ne!(
            v.aggregate(&set([Scope::Guild(1), Scope::User(7)])),
            v.aggregate(&set([Scope::User(7)]))
        );
    }

    #[test]
    fn global_bumps_once_per_batch() {
        let v = Versions::default();
        let g0 = v.global();
        v.bump_all([Scope::Guild(1), Scope::Guild(2), Scope::User(3)]);
        assert_eq!(v.global(), g0 + 1);
        v.bump_all([]); // nothing changed → no wake
        assert_eq!(v.global(), g0 + 1);
    }
}
