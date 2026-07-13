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

/// A guild's roles fetched together, with the instant they were fetched (for TTL expiry).
struct CachedRoles {
    fetched: Instant,
    names: HashMap<u64, String>,
}

pub struct TwilightRoleSource {
    http: Client,
    /// Per-guild role-name cache. One REST fetch populates every role in the guild, so multiple
    /// networks in the same guild — and a thundering herd of clients — share a single call.
    role_cache: Mutex<HashMap<u64, CachedRoles>>,
}

impl TwilightRoleSource {
    pub fn new(bot_token: String) -> Self {
        Self {
            http: Client::new(bot_token),
            role_cache: Mutex::new(HashMap::new()),
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
        let guild = self
            .http
            .guild(Id::new(guild_id))
            .await
            .ok()?
            .model()
            .await
            .ok()?;
        Some(guild.name)
    }

    async fn member(&self, guild_id: u64, user_id: u64) -> Option<MemberRoles> {
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
        Some(MemberRoles {
            nick,
            role_ids: member.roles.iter().map(|r| r.get()).collect(),
        })
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
