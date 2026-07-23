//! Live Discord role source via a bot token (twilight). Reads guild names + member
//! roles/nick over REST. The bot must be in the guild (single-member REST fetch does not need
//! the privileged members intent).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use twilight_http::Client;
use twilight_model::id::Id;

use crate::roles::{MemberRoles, RoleSource};

/// How long a guild's role-name snapshot is trusted before a re-fetch. Network names track role
/// renames on this cadence; short enough to feel live, long enough that a version-bump herd of
/// clients collapses to one `GET guild roles` per guild per window (Discord rate-limits that route
/// on a per-guild bucket).
const ROLE_NAME_TTL: Duration = Duration::from_secs(300);

/// How long a member's roles/nick are trusted before a re-fetch. Kept short because this snapshot is
/// the *authorization* input (which networks the user's roles grant), so a stale entry lets a poll
/// (not gateway) revocation linger up to this long — well under the attestation TTL, and only ever
/// caches a *successful* fetch (a user who left the guild / a failed lookup is never cached, so those
/// aren't delayed). It collapses a single user's repeated `member()` calls — multiple devices, a
/// reconnect storm, or several back-to-back version bumps within the window — into one REST call,
/// easing the per-guild Discord rate-limit bucket that a herd hammers.
const MEMBER_TTL: Duration = Duration::from_secs(30);

/// How long a guild's own name is trusted before a re-fetch. This is the community label shown when
/// no admin slug is set (the default), resolved once per `build_snapshot` per client — so an uncached
/// fetch turns a version-bump herd into one `GET /guilds/{id}` per client, all landing on the same
/// per-guild Discord bucket. Guild renames are rare, so a long window is fine; it collapses the herd
/// (and a single client's repeated renewals) to one call per guild per window.
const GUILD_NAME_TTL: Duration = Duration::from_secs(300);

/// A guild's roles fetched together, with the instant they were fetched (for TTL expiry).
struct CachedRoles {
    fetched: Instant,
    names: HashMap<u64, String>,
}

/// A guild's name with the instant fetched (for TTL expiry).
struct CachedName {
    fetched: Instant,
    name: String,
}

/// A member's roles/nick with the instant fetched (for TTL expiry).
struct CachedMember {
    fetched: Instant,
    roles: MemberRoles,
}

/// Single-flight coalescing for cache-fill fetches. The TTL caches above collapse *repeated* misses
/// over a window, but not the *simultaneous* cold miss: one membership-version bump wakes a herd of
/// long-pollers at once, and — with an empty or just-expired cache — each would fire the same Discord
/// REST call before any of them populates it, hammering that route's per-guild rate-limit bucket.
/// `Flight` funnels concurrent callers for the same key through one gate: the first runs the fetch,
/// the rest wait and then re-read the now-warm cache instead of duplicating the call.
struct Flight<K> {
    gates: Mutex<HashMap<K, Arc<tokio::sync::Mutex<()>>>>,
}

impl<K: Eq + std::hash::Hash + Clone> Flight<K> {
    fn new() -> Self {
        Self {
            gates: Mutex::new(HashMap::new()),
        }
    }

    /// Run at most one `fetch` at a time per `key`. `cached` returns `Some(answer)` on a cache hit
    /// (including a cached "known-absent" answer) or `None` to fetch. A caller that finds a miss takes
    /// the key's gate, and once past it re-checks `cached` — so a caller that queued behind an
    /// in-flight fetch returns that fetch's freshly-cached result rather than issuing its own. Failed
    /// fetches are not cached, so callers behind a failure retry serially (never a burst) instead of
    /// coalescing onto a bad answer.
    async fn dedup<V, C, F, Fut>(&self, key: K, cached: C, fetch: F) -> V
    where
        C: Fn() -> Option<V>,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = V>,
    {
        if let Some(hit) = cached() {
            return hit;
        }
        // Get-or-create this key's gate under the map lock (so clone/remove never race the count).
        let gate = self
            .gates
            .lock()
            .unwrap()
            .entry(key.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let out = {
            let _held = gate.lock().await;
            // The fetch we queued behind may already have filled the cache.
            match cached() {
                Some(hit) => hit,
                None => fetch().await,
            }
        };
        // Drop the key once no other caller still holds its gate (strong count == our local + the
        // map's own), keeping the map bounded to in-flight keys. Same lock as insertion, so the count
        // is exact at this instant.
        let mut gates = self.gates.lock().unwrap();
        if Arc::strong_count(&gate) == 2 {
            gates.remove(&key);
        }
        out
    }
}

pub struct TwilightRoleSource {
    http: Client,
    /// Per-guild role-name cache. One REST fetch populates every role in the guild, so multiple
    /// networks in the same guild — and a thundering herd of clients — share a single call.
    role_cache: Mutex<HashMap<u64, CachedRoles>>,
    /// Per-`(guild, user)` member cache. Dedups repeated lookups of the *same* user (see
    /// [`MEMBER_TTL`]); only positive results are stored.
    member_cache: Mutex<HashMap<(u64, u64), CachedMember>>,
    /// Per-guild name cache. Collapses the `guild_name` fetch a herd of clients each runs in
    /// `build_snapshot` into one call per guild per [`GUILD_NAME_TTL`]; only positive results stored.
    name_cache: Mutex<HashMap<u64, CachedName>>,
    /// Single-flight gates coalescing simultaneous cold-cache fetches, one per cache. Keyed to match
    /// the fetch's granularity: guild for name/roles (one call fills the guild), `(guild, user)` for
    /// a member.
    name_flight: Flight<u64>,
    role_flight: Flight<u64>,
    member_flight: Flight<(u64, u64)>,
}

impl TwilightRoleSource {
    pub fn new(bot_token: String) -> Self {
        Self {
            http: Client::new(bot_token),
            role_cache: Mutex::new(HashMap::new()),
            member_cache: Mutex::new(HashMap::new()),
            name_cache: Mutex::new(HashMap::new()),
            name_flight: Flight::new(),
            role_flight: Flight::new(),
            member_flight: Flight::new(),
        }
    }

    /// The cached name for `guild_id` if still fresh, else `None` (fetch).
    fn cached_name(&self, guild_id: u64) -> Option<String> {
        let cache = self.name_cache.lock().unwrap();
        let entry = cache.get(&guild_id)?;
        if entry.fetched.elapsed() >= GUILD_NAME_TTL {
            return None; // stale → force a re-fetch
        }
        Some(entry.name.clone())
    }

    /// The cached member roles for `(guild_id, user_id)` if still fresh, else `None` (fetch).
    fn cached_member(&self, guild_id: u64, user_id: u64) -> Option<MemberRoles> {
        let cache = self.member_cache.lock().unwrap();
        let entry = cache.get(&(guild_id, user_id))?;
        if entry.fetched.elapsed() >= MEMBER_TTL {
            return None; // stale → force a re-fetch
        }
        Some(entry.roles.clone())
    }

    /// Look up `role_id`'s name in the cache if the guild's snapshot is still fresh.
    fn cached_role(&self, guild_id: u64, role_id: u64) -> Option<Option<String>> {
        let cache = self.role_cache.lock().unwrap();
        let entry = cache.get(&guild_id)?;
        if entry.fetched.elapsed() >= ROLE_NAME_TTL {
            return None; // stale → force a re-fetch
        }
        // Fresh snapshot: `Some(name)` if the role exists, `Some(None)` if it's known-absent.
        Some(entry.names.get(&role_id).cloned())
    }
}

#[async_trait::async_trait]
impl RoleSource for TwilightRoleSource {
    async fn guild_name(&self, guild_id: u64) -> Option<String> {
        self.name_flight
            .dedup(
                guild_id,
                || self.cached_name(guild_id).map(Some),
                || async move {
                    let guild = self
                        .http
                        .guild(Id::new(guild_id))
                        .await
                        .ok()?
                        .model()
                        .await
                        .ok()?;
                    // Cache only this successful fetch; a miss/failure is never cached, so a
                    // transient error isn't pinned for the whole window.
                    self.name_cache.lock().unwrap().insert(
                        guild_id,
                        CachedName {
                            fetched: Instant::now(),
                            name: guild.name.clone(),
                        },
                    );
                    Some(guild.name)
                },
            )
            .await
    }

    async fn member(&self, guild_id: u64, user_id: u64) -> Option<MemberRoles> {
        self.member_flight
            .dedup(
                (guild_id, user_id),
                || self.cached_member(guild_id, user_id).map(Some),
                || async move {
                    let member = self
                        .http
                        .guild_member(Id::new(guild_id), Id::new(user_id))
                        .await
                        .ok()?
                        .model()
                        .await
                        .ok()?;
                    let nick = member
                        .nick
                        .clone()
                        .unwrap_or_else(|| member.user.name.clone());
                    let roles = MemberRoles {
                        nick,
                        role_ids: member.roles.iter().map(|r| r.get()).collect(),
                    };
                    // Cache only this successful fetch; a miss/failure is never cached, so a departed
                    // or unresolvable member isn't pinned as absent.
                    self.member_cache.lock().unwrap().insert(
                        (guild_id, user_id),
                        CachedMember {
                            fetched: Instant::now(),
                            roles: roles.clone(),
                        },
                    );
                    Some(roles)
                },
            )
            .await
    }

    async fn forget(&self, guild_id: u64, user_id: u64) {
        self.member_cache
            .lock()
            .unwrap()
            .remove(&(guild_id, user_id));
    }

    async fn role_name(&self, guild_id: u64, role_id: u64) -> Option<String> {
        // Key the gate by guild, not role: one fetch fills every role, so two callers wanting
        // different roles of the same guild coalesce onto it and each reads its own role back.
        self.role_flight
            .dedup(
                guild_id,
                || self.cached_role(guild_id, role_id),
                || async move {
                    // Cache miss or stale: fetch the whole guild's roles in one call and repopulate.
                    let roles = self
                        .http
                        .roles(Id::new(guild_id))
                        .await
                        .ok()?
                        .model()
                        .await
                        .ok()?;
                    let names: HashMap<u64, String> =
                        roles.into_iter().map(|r| (r.id.get(), r.name)).collect();
                    let name = names.get(&role_id).cloned();
                    self.role_cache.lock().unwrap().insert(
                        guild_id,
                        CachedRoles {
                            fetched: Instant::now(),
                            names,
                        },
                    );
                    name
                },
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roles::RoleSource;

    #[tokio::test]
    async fn forget_drops_the_cached_membership() {
        let src = TwilightRoleSource::new("test-token".to_string());
        src.member_cache.lock().unwrap().insert(
            (7, 42),
            CachedMember {
                fetched: Instant::now(),
                roles: MemberRoles {
                    nick: "n".into(),
                    role_ids: vec![1],
                },
            },
        );
        // A fresh entry is served from cache; forgetting it forces the next lookup to re-fetch.
        assert!(src.cached_member(7, 42).is_some());
        src.forget(7, 42).await;
        assert!(src.cached_member(7, 42).is_none());
        // Forgetting an absent entry is harmless.
        src.forget(7, 42).await;
    }

    // Multi-threaded on purpose: the coordinator runs on a multi-thread runtime, and a current-thread
    // one would never actually race the gate map or the `Arc::strong_count` cleanup.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dedup_coalesces_a_concurrent_cold_miss() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let flight: Arc<Flight<u64>> = Arc::new(Flight::new());
        let cache: Arc<Mutex<Option<u32>>> = Arc::new(Mutex::new(None));
        let fetches = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(8));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let flight = flight.clone();
            let cache = cache.clone();
            let fetches = fetches.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await; // release all callers into the miss at once
                flight
                    .dedup(
                        7,
                        || *cache.lock().unwrap(),
                        || async {
                            fetches.fetch_add(1, Ordering::SeqCst);
                            tokio::task::yield_now().await; // let the herd pile onto the gate
                            *cache.lock().unwrap() = Some(42);
                            42
                        },
                    )
                    .await
            }));
        }

        for h in handles {
            assert_eq!(h.await.unwrap(), 42);
        }
        // All eight raced the same cold miss, but the gate collapsed them to one real fetch.
        assert_eq!(fetches.load(Ordering::SeqCst), 1);
        // The gate self-cleaned once every caller drained.
        assert!(flight.gates.lock().unwrap().is_empty());
    }
}
