//! Live Discord role source via a bot token (twilight). Reads guild names + member
//! roles/username over REST. The bot must be in the guild (single-member REST fetch does not need
//! the privileged members intent).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use twilight_http::Client;
use twilight_model::id::marker::GuildMarker;
use twilight_model::id::Id;

use crate::roles::{MemberRoles, RoleSource};

/// A guild id as Discord's REST API wants it, or `None` for the reserved personal scope.
///
/// [`PERSONAL_SCOPE`](common::attestation::PERSONAL_SCOPE) is `0`: a coordinator-side scope, not a
/// guild. The deployment holds a signing key under it, so `0` turns up wherever guild ids are
/// enumerated from the key table — `/admin/stats` and `/metrics` both walk it. Discord has no such
/// guild, and twilight's `Id` is a `NonZeroU64`, so building one from `0` *panics* rather than
/// 404ing. Every REST call in this module goes through here, so the personal scope reads as "no such
/// guild" instead of taking down the request that asked about it.
fn guild_of(guild_id: u64) -> Option<Id<GuildMarker>> {
    (guild_id != common::attestation::PERSONAL_SCOPE).then(|| Id::new(guild_id))
}

/// How long a guild's role-name snapshot is trusted before a re-fetch. Network names track role
/// renames on this cadence; short enough to feel live, long enough that a version-bump herd of
/// clients collapses to one `GET guild roles` per guild per window (Discord rate-limits that route
/// on a per-guild bucket).
const ROLE_NAME_TTL: Duration = Duration::from_secs(300);

/// How long a member's roles/username are trusted before a re-fetch. Kept short because this snapshot
/// is the *authorization* input (which networks the user's roles grant), so a stale entry lets a poll
/// (not gateway) revocation linger up to this long — well under the attestation TTL. It collapses a
/// single user's repeated `member()` calls — multiple devices, a reconnect storm, or several
/// back-to-back version bumps within the window — into one REST call, easing the per-guild Discord
/// rate-limit bucket that a herd hammers.
///
/// This governs *present* answers only. A known-absent one is held far longer, and for the opposite
/// reason — see [`MEMBER_ABSENT_TTL`]. A lookup that merely *failed* is still never cached at all.
const MEMBER_TTL: Duration = Duration::from_secs(30);

/// How long a **known-absent** member lookup is trusted — this account is not in that guild.
///
/// This is the deployment's dominant cost. `build_snapshot` walks *every* registered network for
/// every device, and a user is in one or two guilds, so nearly every lookup is a 404 that will still
/// be a 404 an hour later. Without caching those, each device pays one Discord call per guild in the
/// whole deployment on every renewal, and the coordinator's ceiling becomes `devices × guilds`
/// against a 50/s global limit — a shared instance getting slower for everyone each time an unrelated
/// community registers a network.
///
/// A window this long is only safe because a *join* is observable: `Event::MemberAdd` drops the entry
/// (`commands.rs`), so the normal path picks up a real join immediately. The TTL is the fallback for
/// when the gateway missed it, and it fails **closed** — a user whose join went unseen is told they
/// hold no networks, rather than being granted anything they shouldn't have. One renewal period is
/// the natural size: any longer and a gateway gap outlives more than a single snapshot cycle.
const MEMBER_ABSENT_TTL: Duration = Duration::from_secs(common::LONGPOLL_HOLD_SECS);

/// How often the member cache is swept for expired entries. Sweeping is `O(size)` and the map is
/// keyed per `(guild, user)`, so a deployment's worth of absent answers is bounded by
/// `users × guilds` — big enough to be worth pruning, cheap enough to do rarely.
const MEMBER_PRUNE_EVERY: Duration = MEMBER_ABSENT_TTL;

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

/// A member lookup's result with the instant fetched (for TTL expiry). `roles: None` is a
/// *known-absent* answer — this account is not in that guild — cached under [`MEMBER_ABSENT_TTL`]
/// rather than [`MEMBER_TTL`].
struct CachedMember {
    fetched: Instant,
    roles: Option<MemberRoles>,
}

impl CachedMember {
    /// Absent answers are trusted far longer than present ones, so the TTL depends on which this is.
    fn ttl(&self) -> Duration {
        match self.roles {
            Some(_) => MEMBER_TTL,
            None => MEMBER_ABSENT_TTL,
        }
    }

    fn fresh(&self) -> bool {
        self.fetched.elapsed() < self.ttl()
    }
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
    /// Per-`(guild, user)` member cache, holding both present ([`MEMBER_TTL`]) and known-absent
    /// ([`MEMBER_ABSENT_TTL`]) answers.
    member_cache: Mutex<HashMap<(u64, u64), CachedMember>>,
    /// When the member cache was last swept — see [`MEMBER_PRUNE_EVERY`].
    member_pruned: Mutex<Instant>,
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
    /// `api_proxy` redirects REST at a local stand-in for Discord (`examples/mock_discord.rs`) for
    /// the scaling probe. `Config` refuses it outside a debug build and off loopback — see
    /// `config::validate_api_proxy`.
    pub fn new(bot_token: String, api_proxy: Option<String>) -> Self {
        let http = match api_proxy {
            Some(url) => {
                // twilight wants a bare `host:port`, not a URL — it builds `http://{proxy}/api/v10/…`
                // itself. Handing it the `http://` prefix makes a hostname of the scheme, which
                // resolves nowhere and costs a DNS timeout per call instead of failing outright.
                // The config field stays a URL because that is what an operator would write.
                let host = url
                    .strip_prefix("http://")
                    .unwrap_or(&url)
                    .trim_end_matches('/')
                    .to_string();
                // `true` = talk plaintext HTTP to it, which is the only thing the mock serves.
                Client::builder().token(bot_token).proxy(host, true).build()
            }
            None => Client::new(bot_token),
        };
        Self {
            http,
            role_cache: Mutex::new(HashMap::new()),
            member_cache: Mutex::new(HashMap::new()),
            member_pruned: Mutex::new(Instant::now()),
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

    /// The cached answer for `(guild_id, user_id)` if still fresh, else `None` (fetch). The two
    /// levels of `Option` differ: the outer is cache hit/miss, the inner is member/not-a-member.
    fn cached_member(&self, guild_id: u64, user_id: u64) -> Option<Option<MemberRoles>> {
        let cache = self.member_cache.lock().unwrap();
        let entry = cache.get(&(guild_id, user_id))?;
        if !entry.fresh() {
            return None; // stale → force a re-fetch
        }
        Some(entry.roles.clone())
    }

    /// Record a lookup's outcome, sweeping expired entries at most once per [`MEMBER_PRUNE_EVERY`].
    fn store_member(&self, guild_id: u64, user_id: u64, roles: Option<MemberRoles>) {
        let mut cache = self.member_cache.lock().unwrap();
        cache.insert(
            (guild_id, user_id),
            CachedMember {
                fetched: Instant::now(),
                roles,
            },
        );
        let mut last = self.member_pruned.lock().unwrap();
        if last.elapsed() >= MEMBER_PRUNE_EVERY {
            cache.retain(|_, entry| entry.fresh());
            *last = Instant::now();
        }
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
        let id = guild_of(guild_id)?;
        self.name_flight
            .dedup(
                guild_id,
                || self.cached_name(guild_id).map(Some),
                || async move {
                    let guild = self.http.guild(id).await.ok()?.model().await.ok()?;
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
        let id = guild_of(guild_id)?;
        self.member_flight
            .dedup(
                (guild_id, user_id),
                || self.cached_member(guild_id, user_id),
                || async move {
                    let response = match self.http.guild_member(id, Id::new(user_id)).await {
                        Ok(r) => r,
                        Err(e) => {
                            // Only Discord *saying* the member does not exist is an absence worth
                            // remembering. A timeout, a 5xx or a revoked token says nothing about
                            // membership, and caching one as "not a member" would lock the user out
                            // of their networks for the whole absent-TTL over a transient blip.
                            if matches!(
                                e.kind(),
                                twilight_http::error::ErrorType::Response { status, .. }
                                    if status.get() == 404
                            ) {
                                self.store_member(guild_id, user_id, None);
                            } else {
                                tracing::debug!(
                                    guild = guild_id,
                                    user = user_id,
                                    "member lookup failed, not cached: {e}"
                                );
                            }
                            return None;
                        }
                    };
                    let member = response.model().await.ok()?;
                    // The *username*, deliberately not `member.nick`. A guild nickname is arbitrary
                    // Unicode and not unique within a guild, so two members could set the same one
                    // and contend for a hostname; a username is globally unique and stable across
                    // guilds, so a member's mesh name doesn't change with which server you meet them
                    // in. It only seeds the label — `Store::user_label` allocates the real one.
                    let username = member.user.name.clone();
                    let roles = MemberRoles {
                        username,
                        role_ids: member.roles.iter().map(|r| r.get()).collect(),
                    };
                    self.store_member(guild_id, user_id, Some(roles.clone()));
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
        let id = guild_of(guild_id)?;
        // Key the gate by guild, not role: one fetch fills every role, so two callers wanting
        // different roles of the same guild coalesce onto it and each reads its own role back.
        self.role_flight
            .dedup(
                guild_id,
                || self.cached_role(guild_id, role_id),
                || async move {
                    // Cache miss or stale: fetch the whole guild's roles in one call and repopulate.
                    let roles = self.http.roles(id).await.ok()?.model().await.ok()?;
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
        let src = TwilightRoleSource::new("test-token".to_string(), None);
        src.member_cache.lock().unwrap().insert(
            (7, 42),
            CachedMember {
                fetched: Instant::now(),
                roles: Some(MemberRoles {
                    username: "n".into(),
                    role_ids: vec![1],
                }),
            },
        );
        // A fresh entry is served from cache; forgetting it forces the next lookup to re-fetch.
        assert!(src.cached_member(7, 42).is_some());
        src.forget(7, 42).await;
        assert!(src.cached_member(7, 42).is_none());
        // Forgetting an absent entry is harmless.
        src.forget(7, 42).await;
    }

    /// The personal scope (`guild_id = 0`) is not a Discord guild, and asking about it must be an
    /// empty answer rather than a panic: it has a signing key, so it appears in `guild_ids()`, and
    /// `/admin/stats` and `/metrics` both look up a name for every id they find there. Building a
    /// twilight `Id` from `0` panics, which took the whole request down as a 502 with the dashboard
    /// dead for as long as anyone in the deployment held no role. No token or network is needed
    /// here — a lookup that reached REST at all would already have failed the test's point.
    #[tokio::test]
    async fn the_personal_scope_is_no_guild_rather_than_a_panic() {
        let src = TwilightRoleSource::new("test-token".to_string(), None);
        let scope = common::attestation::PERSONAL_SCOPE;
        assert!(src.guild_name(scope).await.is_none());
        assert!(src.member(scope, 42).await.is_none());
        assert!(src.role_name(scope, 7).await.is_none());
        // Refused before any REST call, so nothing about the scope is cached either.
        assert!(src.cached_member(scope, 42).is_none());
    }

    #[tokio::test]
    async fn a_known_absence_is_cached_and_a_join_drops_it() {
        let src = TwilightRoleSource::new("test-token".to_string(), None);
        src.store_member(7, 42, None);
        // Cache hit (outer `Some`) carrying "not a member" (inner `None`) — the answer the walk
        // spends nearly all its Discord calls re-learning.
        assert!(matches!(src.cached_member(7, 42), Some(None)));
        // `Event::MemberAdd` routes here, so a real join is visible without waiting out the TTL.
        src.forget(7, 42).await;
        assert!(src.cached_member(7, 42).is_none());
    }

    #[tokio::test]
    async fn an_absence_is_trusted_longer_than_a_membership() {
        // The asymmetry is the point: a stale *present* answer keeps a revoked member on the mesh,
        // while a stale *absent* one only makes a new member wait.
        let present = CachedMember {
            fetched: Instant::now(),
            roles: Some(MemberRoles {
                username: "n".into(),
                role_ids: vec![1],
            }),
        };
        let absent = CachedMember {
            fetched: Instant::now(),
            roles: None,
        };
        assert_eq!(present.ttl(), MEMBER_TTL);
        assert_eq!(absent.ttl(), MEMBER_ABSENT_TTL);
        assert!(absent.ttl() > present.ttl());
    }

    #[tokio::test]
    async fn an_expired_absence_is_a_miss_not_an_answer() {
        let src = TwilightRoleSource::new("test-token".to_string(), None);
        src.member_cache.lock().unwrap().insert(
            (7, 42),
            CachedMember {
                // Older than the absent window, so it must re-fetch rather than keep denying.
                fetched: Instant::now() - MEMBER_ABSENT_TTL - Duration::from_secs(1),
                roles: None,
            },
        );
        assert!(src.cached_member(7, 42).is_none());
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
