//! Discord OAuth2 for interactive login. The engine is a **public** client — it runs the
//! authorization-code + PKCE flow itself (loopback redirect, `code_verifier` in place of a secret)
//! and hands the coordinator only the resulting access token. The coordinator's job is to *verify*
//! that token against Discord (`GET /users/@me`) and bind the identity to the device pubkey; it
//! holds no client secret. It exposes its `client_id` (public) so the engine can build the
//! authorize URL and do the exchange.
//!
//! A [`FakeOauth`] provider (treats the access token as `user:<id>`) backs offline tests, mirroring
//! the fake role source.

use anyhow::{anyhow, Context};

/// Verifies a Discord access token into the authenticated user id, and exposes the public
/// `client_id` the engine needs to run the PKCE flow.
#[async_trait::async_trait]
pub trait OauthProvider: Send + Sync {
    fn client_id(&self) -> &str;
    /// Offline mode: the engine skips the real Discord round-trip and passes the callback `code`
    /// through as the "access token" (`user:<id>`).
    fn is_fake(&self) -> bool {
        false
    }
    async fn verify(&self, access_token: &str) -> anyhow::Result<u64>;
}

/// Live Discord OAuth2 public client (verify-only; no secret).
pub struct DiscordOauth {
    client_id: String,
    http: reqwest::Client,
}

impl DiscordOauth {
    pub fn new(client_id: String) -> Self {
        Self {
            client_id,
            http: reqwest::Client::new(),
        }
    }
}

#[derive(serde::Deserialize)]
struct DiscordUser {
    id: String,
}

#[async_trait::async_trait]
impl OauthProvider for DiscordOauth {
    fn client_id(&self) -> &str {
        &self.client_id
    }

    async fn verify(&self, access_token: &str) -> anyhow::Result<u64> {
        let user: DiscordUser = self
            .http
            .get("https://discord.com/api/users/@me")
            .bearer_auth(access_token)
            .send()
            .await
            .context("fetching identify")?
            .error_for_status()
            .context("identify request failed")?
            .json()
            .await
            .context("decoding identify response")?;

        user.id.parse().context("Discord user id was not numeric")
    }
}

/// Offline OAuth for tests: the "access token" is `user:<id>` — no Discord round-trip. Enabled when
/// the coordinator runs a fake role source.
pub struct FakeOauth;

#[async_trait::async_trait]
impl OauthProvider for FakeOauth {
    fn client_id(&self) -> &str {
        "fake"
    }

    fn is_fake(&self) -> bool {
        true
    }

    async fn verify(&self, access_token: &str) -> anyhow::Result<u64> {
        access_token
            .strip_prefix("user:")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("fake oauth expects token 'user:<id>', got '{access_token}'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_oauth_parses_user_id() {
        let o = FakeOauth;
        assert_eq!(o.verify("user:42").await.unwrap(), 42);
        assert!(o.verify("nope").await.is_err());
        assert_eq!(o.client_id(), "fake");
        assert!(o.is_fake());
    }
}
