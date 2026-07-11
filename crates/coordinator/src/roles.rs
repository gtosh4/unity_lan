//! Role source: the authority for guild identity + "who holds which role", across the
//! (possibly multiple) guilds a coordinator serves.
//!
//! M1 ships a [`FakeRoleSource`] from config. The live twilight bot-token source lands later
//! behind the same trait.

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
                (g.id, FakeGuildData { name: g.name, members })
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
}
