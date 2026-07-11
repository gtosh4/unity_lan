//! Coordinator configuration (TOML). A coordinator may serve multiple guilds.
//!
//! M1 supports an offline `[fake]` role source. Live `[discord]`/`[oauth]` blocks land later.
//! The `[[network]]` seeds pre-populate the registry (simulating admin slash commands) —
//! useful in the test config; in production networks are managed via `/unitylan network`.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Socket address to bind the HTTP API, e.g. "127.0.0.1:8080".
    pub bind: String,
    /// SQLite database path (signing key, network registry, allocations).
    pub database: PathBuf,
    /// Offline role source. Mutually exclusive with a live Discord source.
    pub fake: Option<FakeConfig>,
    /// Live Discord role source (bot token).
    pub discord: Option<DiscordConfig>,
    /// Networks to seed into the registry on startup (test convenience).
    #[serde(default, rename = "network")]
    pub network_seeds: Vec<NetworkSeed>,
    /// Enrollment keys to seed on startup (test convenience; prod mints via `/unitylan enroll`).
    #[serde(default, rename = "enroll")]
    pub enroll_seeds: Vec<EnrollSeed>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EnrollSeed {
    pub key: String,
    pub user_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct DiscordConfig {
    pub bot_token: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkSeed {
    pub guild_id: u64,
    pub role_id: u64,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct FakeConfig {
    #[serde(default, rename = "guild")]
    pub guilds: Vec<FakeGuild>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FakeGuild {
    pub id: u64,
    pub name: String,
    #[serde(default, rename = "member")]
    pub members: Vec<FakeMember>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FakeMember {
    pub user_id: u64,
    pub nick: String,
    #[serde(default)]
    pub role_ids: Vec<u64>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        Ok(toml::from_str(&text)?)
    }
}
