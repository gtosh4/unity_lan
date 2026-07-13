//! Engine-owned Discord OAuth2 with PKCE. The engine is a **public** client: it generates a
//! `code_verifier`/`code_challenge`, spawns a one-shot loopback listener as the redirect target,
//! opens the authorize URL, catches the `code`, exchanges it at Discord's token endpoint (with the
//! verifier in place of a client secret), and hands the coordinator the resulting access token to
//! verify and bind (`POST /oauth/complete`).
//!
//! The loopback redirect (e.g. `http://127.0.0.1:8765/callback`) is fixed and registered once with
//! the Discord app, so login works from any host/VM regardless of its LAN address — nothing needs a
//! reachable coordinator URL. Offline tests run the coordinator in `fake` mode: the engine then
//! skips the Discord round-trip and passes the callback `code` (`user:<id>`) through as the token.

use anyhow::{anyhow, bail, Context};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::coord;

/// A login attempt in progress: the listener is already bound (so the redirect target is live the
/// moment we hand back `authorize_url`), and everything needed to finish the exchange is captured.
pub struct Login {
    pub authorize_url: String,
    listener: TcpListener,
    verifier: String,
    state: String,
    redirect_uri: String,
    client_id: String,
    fake: bool,
    coordinator: String,
    wg_pubkey: [u8; 32],
}

/// Begin login: fetch the public PKCE config from the coordinator, generate the PKCE pair, bind the
/// loopback listener, and build the authorize URL. Caller opens `authorize_url`, then `complete()`s.
pub async fn begin(
    coordinator: &str,
    redirect_uri: &str,
    wg_pubkey: [u8; 32],
) -> anyhow::Result<Login> {
    let cfg = coord::pkce_config(coordinator).await?;

    let verifier = common::crypto::gen_pkce_verifier();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let state = common::crypto::gen_pkce_verifier();

    let bind_addr = loopback_bind_addr(redirect_uri)?;
    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("binding OAuth loopback listener on {bind_addr}"))?;

    let authorize_url = reqwest::Url::parse_with_params(
        "https://discord.com/oauth2/authorize",
        &[
            ("client_id", cfg.client_id.as_str()),
            ("redirect_uri", redirect_uri),
            ("response_type", "code"),
            ("scope", "identify"),
            ("state", state.as_str()),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ],
    )
    .expect("valid authorize url")
    .to_string();

    Ok(Login {
        authorize_url,
        listener,
        verifier,
        state,
        redirect_uri: redirect_uri.to_string(),
        client_id: cfg.client_id,
        fake: cfg.fake,
        coordinator: coordinator.to_string(),
        wg_pubkey,
    })
}

impl Login {
    /// Wait for the browser redirect, exchange the code for an access token, and hand it to the
    /// coordinator to verify + bind. Returns once the coordinator has bound the device.
    pub async fn complete(self) -> anyhow::Result<()> {
        let code = self.await_code().await?;
        let access_token = if self.fake {
            // Offline: the coordinator's fake provider treats the token itself as `user:<id>`.
            code
        } else {
            self.exchange(&code).await?
        };
        coord::oauth_complete(&self.coordinator, self.wg_pubkey, &access_token).await
    }

    /// Accept one connection on the loopback listener, parse `code`+`state` from the redirect, check
    /// `state`, reply with a friendly page, and return the code.
    async fn await_code(&self) -> anyhow::Result<String> {
        let (mut stream, _) = self
            .listener
            .accept()
            .await
            .context("accepting OAuth loopback redirect")?;

        // The request line — `GET /callback?code=..&state=.. HTTP/1.1` — is all we need; read until
        // the end of the headers (blank line) or the buffer fills.
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await.context("reading redirect")?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }

        let req = String::from_utf8_lossy(&buf);
        let target = req
            .split_whitespace()
            .nth(1)
            .ok_or_else(|| anyhow!("malformed redirect request"))?;
        let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");

        let mut code = None;
        let mut state = None;
        let mut oauth_err = None;
        for (k, v) in query.split('&').filter_map(|p| p.split_once('=')) {
            match k {
                "code" => code = Some(v.to_string()),
                "state" => state = Some(v.to_string()),
                "error" => oauth_err = Some(v.to_string()),
                _ => {}
            }
        }

        let (body, result) = match (&code, &state, &oauth_err) {
            (Some(c), Some(s), _) if *s == self.state => (
                "<h1>Logged in \u{2713}</h1><p>You can close this tab and return to UnityLAN.</p>",
                Ok(c.clone()),
            ),
            (_, _, Some(e)) => (
                "<h1>Login failed</h1><p>You can close this tab.</p>",
                Err(anyhow!("Discord returned error: {e}")),
            ),
            (_, Some(_), _) => (
                "<h1>Login failed</h1><p>You can close this tab.</p>",
                Err(anyhow!(
                    "OAuth state mismatch (possible CSRF); login aborted"
                )),
            ),
            _ => (
                "<h1>Login failed</h1><p>You can close this tab.</p>",
                Err(anyhow!("redirect missing code/state")),
            ),
        };

        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.flush().await;
        result
    }

    /// Exchange the authorization `code` for an access token at Discord — PKCE, no client secret.
    async fn exchange(&self, code: &str) -> anyhow::Result<String> {
        #[derive(serde::Deserialize)]
        struct TokenResp {
            access_token: String,
        }
        let token: TokenResp = reqwest::Client::new()
            .post("https://discord.com/api/oauth2/token")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("code_verifier", self.verifier.as_str()),
            ])
            .send()
            .await
            .context("exchanging oauth code")?
            .error_for_status()
            .context("oauth token endpoint rejected the code")?
            .json()
            .await
            .context("decoding token response")?;
        Ok(token.access_token)
    }
}

/// The `host:port` to bind the loopback listener on, parsed from the configured redirect URI.
fn loopback_bind_addr(redirect_uri: &str) -> anyhow::Result<std::net::SocketAddr> {
    let url = reqwest::Url::parse(redirect_uri)
        .with_context(|| format!("parsing oauth_redirect {redirect_uri:?}"))?;
    let host = url.host_str().unwrap_or("127.0.0.1");
    let port = url
        .port()
        .ok_or_else(|| anyhow!("oauth_redirect {redirect_uri:?} must include an explicit port"))?;
    if host != "127.0.0.1" && host != "localhost" {
        bail!("oauth_redirect must be a loopback address (127.0.0.1/localhost), got {host:?}");
    }
    Ok(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
}
