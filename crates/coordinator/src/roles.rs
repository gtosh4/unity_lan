//! Role source: the authority for guild identity + "who holds which role", across the
//! (possibly multiple) guilds a coordinator serves.
//!
//! Two impls behind the trait: [`FakeRoleSource`] (config-seeded, offline dev/tests) and the live
//! twilight bot-token source ([`TwilightRoleSource`] in `discord.rs`).

use std::collections::HashMap;

use crate::config::FakeConfig;

#[derive(Clone)]
pub struct MemberRoles {
    pub nick: String,
    pub role_ids: Vec<u64>,
}

/// Reads guild names + a member's roles/nick. The only party that may do this authoritatively.
/// Async because the live source hits the Discord REST API.
#[async_trait::async_trait]
pub trait RoleSource: Send + Sync {
    /// Display name of a guild the bot serves, if known.
    async fn guild_name(&self, guild_id: u64) -> Option<String>;
    /// A member's roles + nick in a specific guild; `None` if not a member.
    async fn member(&self, guild_id: u64, user_id: u64) -> Option<MemberRoles>;
    /// Drop any cached membership for `(guild, user)` so the next `member` call re-fetches. Called on
    /// a role-change/leave event: without it a revoked member would keep being served from a stale
    /// positive cache for its TTL, re-admitting on a register that lands inside the window. Default
    /// no-op for sources that don't cache.
    async fn forget(&self, _guild_id: u64, _user_id: u64) {}
    /// Current Discord display name of a role, so a network's name tracks role renames without any
    /// stored copy to propagate. `None` if unknown (caller falls back to the registered snapshot).
    async fn role_name(&self, guild_id: u64, role_id: u64) -> Option<String>;
}

pub struct FakeRoleSource {
    guilds: HashMap<u64, FakeGuildData>,
}

struct FakeGuildData {
    name: String,
    members: HashMap<u64, MemberRoles>,
}

impl FakeRoleSource {
    pub fn new(cfg: FakeConfig) -> Self {
        let guilds = cfg
            .guilds
            .into_iter()
            .map(|g| {
                let members = g
                    .members
                    .into_iter()
                    .map(|m| {
                        (
                            m.user_id,
                            MemberRoles {
                                nick: m.nick,
                                role_ids: m.role_ids,
                            },
                        )
                    })
                    .collect();
                (
                    g.id,
                    FakeGuildData {
                        name: g.name,
                        members,
                    },
                )
            })
            .collect();
        Self { guilds }
    }
}

#[async_trait::async_trait]
impl RoleSource for FakeRoleSource {
    async fn guild_name(&self, guild_id: u64) -> Option<String> {
        self.guilds.get(&guild_id).map(|g| g.name.clone())
    }

    async fn member(&self, guild_id: u64, user_id: u64) -> Option<MemberRoles> {
        self.guilds.get(&guild_id)?.members.get(&user_id).cloned()
    }

    /// The fake source doesn't model role names; callers fall back to the seeded network name.
    async fn role_name(&self, _guild_id: u64, _role_id: u64) -> Option<String> {
        None
    }
}
