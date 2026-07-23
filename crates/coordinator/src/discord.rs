//! Live Discord role source via a bot token (twilight). Reads guild names + member
//! roles/nick over REST. The bot must be in the guild (single-member REST fetch does not need
//! the privileged members intent).

use std::collections::HashMap;
use std::sync::Mutex;
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
}

impl TwilightRoleSource {
    pub fn new(bot_token: String) -> Self {
        Self {
            http: Client::new(bot_token),
            role_cache: Mutex::new(HashMap::new()),
            member_cache: Mutex::new(HashMap::new()),
            name_cache: Mutex::new(HashMap::new()),
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
        if let Some(hit) = self.cached_name(guild_id) {
            return Some(hit);
        }
        let guild = self
            .http
            .guild(Id::new(guild_id))
            .await
            .ok()?
            .model()
            .await
            .ok()?;
        // Cache only this successful fetch; a miss/failure is never cached, so a transient error
        // isn't pinned for the whole window.
        self.name_cache.lock().unwrap().insert(
            guild_id,
            CachedName {
                fetched: Instant::now(),
                name: guild.name.clone(),
            },
        );
        Some(guild.name)
    }

    async fn member(&self, guild_id: u64, user_id: u64) -> Option<MemberRoles> {
        if let Some(hit) = self.cached_member(guild_id, user_id) {
            return Some(hit);
        }
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
        // Cache only this successful fetch; a miss/failure is never cached, so a departed or
        // unresolvable member isn't pinned as absent.
        self.member_cache.lock().unwrap().insert(
            (guild_id, user_id),
            CachedMember {
                fetched: Instant::now(),
                roles: roles.clone(),
            },
        );
        Some(roles)
    }

    async fn forget(&self, guild_id: u64, user_id: u64) {
        self.member_cache
            .lock()
            .unwrap()
            .remove(&(guild_id, user_id));
    }

    async fn role_name(&self, guild_id: u64, role_id: u64) -> Option<String> {
        if let Some(hit) = self.cached_role(guild_id, role_id) {
            return hit;
        }
        // Cache miss or stale: fetch the whole guild's roles in one call and repopulate.
        let roles = self
            .http
            .roles(Id::new(guild_id))
            .await
            .ok()?
            .model()
            .await
            .ok()?;
        let names: HashMap<u64, String> = roles.into_iter().map(|r| (r.id.get(), r.name)).collect();
        let name = names.get(&role_id).cloned();
        self.role_cache.lock().unwrap().insert(
            guild_id,
            CachedRoles {
                fetched: Instant::now(),
                names,
            },
        );
        name
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
}
