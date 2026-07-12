//! Discord OAuth2 (authorization-code) for interactive login. The coordinator is a *confidential*
//! client — it holds the client secret and performs the token exchange server-side — so a client
//! only opens the authorize URL and polls register; the secret never leaves the coordinator.
//! (PKCE is unnecessary for a confidential server-mediated flow; it can be added if the exchange
//! ever moves client-side.)
//!
//! A [`FakeOauth`] provider (parses `user:<id>` from the callback code) backs offline tests,
//! mirroring the fake role source.

use anyhow::{anyhow, Context};

/// Turns an authorization `code` into the authenticated Discord user id. Also builds the authorize
/// URL the client opens.
#[async_trait::async_trait]
pub trait OauthProvider: Send + Sync {
    fn authorize_url(&self, state: &str) -> String;
    async fn exchange(&self, code: &str) -> anyhow::Result<u64>;
}

/// Live Discord OAuth2 confidential client.
pub struct DiscordOauth {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http: reqwest::Client,
}

impl DiscordOauth {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
            http: reqwest::Client::new(),
        }
    }
}

#[derive(serde::Deserialize)]
struct TokenResp {
    access_token: String,
}

#[derive(serde::Deserialize)]
struct DiscordUser {
    id: String,
}

#[async_trait::async_trait]
impl OauthProvider for DiscordOauth {
    fn authorize_url(&self, state: &str) -> String {
        reqwest::Url::parse_with_params(
            "https://discord.com/oauth2/authorize",
            &[
                ("client_id", self.client_id.as_str()),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("response_type", "code"),
                ("scope", "identify"),
                ("state", state),
            ],
        )
        .expect("valid authorize url")
        .to_string()
    }

    async fn exchange(&self, code: &str) -> anyhow::Result<u64> {
        let token: TokenResp = self
            .http
            .post("https://discord.com/api/oauth2/token")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.redirect_uri.as_str()),
            ])
            .send()
            .await
            .context("exchanging oauth code")?
            .error_for_status()
            .context("oauth token endpoint rejected the code")?
            .json()
            .await
            .context("decoding token response")?;

        let user: DiscordUser = self
            .http
            .get("https://discord.com/api/users/@me")
            .bearer_auth(&token.access_token)
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

/// Offline OAuth for tests: the "authorize URL" points straight at the callback, and the code is
/// `user:<id>` — no Discord round-trip. Enabled when the coordinator runs a fake role source.
pub struct FakeOauth {
    redirect_uri: String,
}

impl FakeOauth {
    pub fn new(redirect_uri: String) -> Self {
        Self { redirect_uri }
    }
}

#[async_trait::async_trait]
impl OauthProvider for FakeOauth {
    fn authorize_url(&self, state: &str) -> String {
        // The tester curls the callback directly; encode state so it's easy to grep.
        format!(
            "{}?state={state}&code=user:REPLACE_WITH_ID",
            self.redirect_uri
        )
    }

    async fn exchange(&self, code: &str) -> anyhow::Result<u64> {
        code.strip_prefix("user:")
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("fake oauth expects code 'user:<id>', got '{code}'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discord_authorize_url_encodes_params() {
        let o = DiscordOauth::new(
            "123".into(),
            "secret".into(),
            "https://coord.example/oauth/callback".into(),
        );
        let url = o.authorize_url("st8");
        assert!(url.starts_with("https://discord.com/oauth2/authorize?"));
        assert!(url.contains("client_id=123"));
        assert!(url.contains("scope=identify"));
        assert!(url.contains("state=st8"));
        // redirect_uri percent-encoded.
        assert!(url.contains("redirect_uri=https%3A%2F%2Fcoord.example%2Foauth%2Fcallback"));
    }

    #[tokio::test]
    async fn fake_oauth_parses_user_id() {
        let o = FakeOauth::new("http://c/oauth/callback".into());
        assert_eq!(o.exchange("user:42").await.unwrap(), 42);
        assert!(o.exchange("nope").await.is_err());
        assert!(o.authorize_url("s").contains("state=s"));
    }
}
