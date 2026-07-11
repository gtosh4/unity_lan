//! Live Discord role source via a bot token (twilight). Reads guild names + member
//! roles/nick over REST. The bot must be in the guild (single-member REST fetch does not need
//! the privileged members intent).

use twilight_http::Client;
use twilight_model::id::Id;

use crate::roles::{MemberRoles, RoleSource};

pub struct TwilightRoleSource {
    http: Client,
}

impl TwilightRoleSource {
    pub fn new(bot_token: String) -> Self {
        Self {
            http: Client::new(bot_token),
        }
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
}
