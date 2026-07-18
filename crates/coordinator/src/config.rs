//! Coordinator configuration (TOML). A coordinator may serve multiple guilds.
//!
//! Two role sources: the live `[discord]` + `[oauth]` blocks, or an offline `[fake]` source for
//! dev/tests (mutually exclusive). The `[[network]]` seeds pre-populate the registry (simulating
//! admin slash commands) — useful in the test config; in production networks are managed via
//! `/unitylan network`.

use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Socket address to bind the HTTP API, e.g. "127.0.0.1:8080".
    pub bind: String,
    /// SQLite database path (signing key, network registry, allocations).
    pub database: PathBuf,
    /// The mesh address range this deployment allocates device `/32`s from. Absent → a `/16`
    /// derived from the trust anchor within 100.64.0.0/10 (see `netid::default_cidr`). Set it to
    /// carve a disjoint block so a user on multiple meshes doesn't get colliding IPs, or to fit an
    /// environment. Validated at startup to a private/CGNAT range (fails closed otherwise).
    #[serde(default)]
    pub cidr: Option<ipnet::Ipv4Net>,
    /// Offline role source. Mutually exclusive with a live Discord source.
    pub fake: Option<FakeConfig>,
    /// Live Discord role source (bot token).
    pub discord: Option<DiscordConfig>,
    /// Discord OAuth2 app for interactive login. Absent → OAuth disabled (or fake, in `[fake]`).
    pub oauth: Option<OauthConfig>,
    /// Networks to seed into the registry on startup (test convenience).
    #[serde(default, rename = "network")]
    pub network_seeds: Vec<NetworkSeed>,
    /// Enrollment keys to seed on startup (test convenience; prod mints via `/unitylan enroll`).
    #[serde(default, rename = "enroll")]
    pub enroll_seeds: Vec<EnrollSeed>,
    /// Community slugs to seed on startup (admin config; default is the guild name).
    #[serde(default, rename = "community")]
    pub community_seeds: Vec<CommunitySeed>,
    /// UDP address for the STUN Binding responder (M5.5 ICE bootstrap fallback). When set, the
    /// coordinator serves reflexive-address lookups here and advertises it to clients as the
    /// coordinator-host STUN fallback (used when no relay co-member is online to STUN). Must be a
    /// client-reachable address (admin sets its public `ip:port`, like a relay's `relay_addr`).
    /// Absent → no fallback (clients rely on relay-node STUN only).
    #[serde(default)]
    pub stun_bind: Option<std::net::SocketAddr>,
    /// Auto-update release manifest (design phase 3). When set, the coordinator signs it with its
    /// trust anchor and advertises it to clients on the long-poll so they can self-update against the
    /// pinned anchor. Absent → auto-update disabled for this deployment (clients still see the plain
    /// version notice). Opt-in, so a deployment ships no update offer until the admin fills this in.
    #[serde(default)]
    pub release: Option<ReleaseConfig>,
    /// Operator admin surface (`/admin` dashboard + `/metrics`). Absent → both routes are disabled
    /// (return 404). The token is the operator's own secret; there is no shipped default, so an
    /// instance exposes nothing until its operator opts in — and only they, never upstream, can
    /// reach it. This surface reads control-plane counts only; it carries no inter-peer traffic.
    #[serde(default)]
    pub admin: Option<AdminConfig>,
    /// How long a signed attestation is valid (seconds). Default 30 min. This is the **revocation
    /// window**: a member who loses a role keeps mesh access until their last attestation expires
    /// (peers drop them on expiry — `docs/gossip-refresh.md` — and the coordinator stops re-issuing).
    /// Shorter = tighter revocation but more refresh churn; longer = the reverse. Also the base for
    /// the client's renewal/gossip cadence. Lowered in tests to exercise expiry quickly.
    #[serde(default = "default_attestation_ttl")]
    pub attestation_ttl_secs: u64,
}

fn default_attestation_ttl() -> u64 {
    common::ATTESTATION_TTL_SECS
}

/// The `[admin]` block: an operator-set bearer token gating `/admin` and `/metrics`.
#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    /// Bearer token required on `Authorization: Bearer <token>`. Operator-generated; keep it long
    /// and random. Compared in constant time.
    pub token: String,
}

/// The `[release]` block: the version to advertise plus one `[[release.artifact]]` per platform.
#[derive(Debug, Deserialize, Clone)]
pub struct ReleaseConfig {
    /// The release version (semver). Clients apply only when it's strictly newer than their own.
    pub version: String,
    #[serde(default, rename = "artifact")]
    pub artifacts: Vec<ArtifactConfig>,
}

/// One `[[release.artifact]]`: a per-platform download + its SHA-256 (pasted from CI's SHA256SUMS).
#[derive(Debug, Deserialize, Clone)]
pub struct ArtifactConfig {
    pub platform: common::update::Platform,
    pub url: String,
    /// SHA-256 of the artifact as a 64-char hex string.
    pub sha256: String,
    pub size: u64,
}

impl ReleaseConfig {
    /// Build the wire manifest, parsing each artifact's hex SHA-256. Fails closed on malformed input
    /// so a typo in the config surfaces at startup rather than shipping an unverifiable update.
    pub fn to_manifest(&self) -> anyhow::Result<common::update::ReleaseManifest> {
        let artifacts = self
            .artifacts
            .iter()
            .map(|a| {
                Ok(common::update::ReleaseArtifact {
                    platform: a.platform,
                    url: a.url.clone(),
                    sha256: parse_sha256(&a.sha256)?,
                    size: a.size,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(common::update::ReleaseManifest {
            version: self.version.clone(),
            artifacts,
        })
    }
}

/// Parse a 64-char hex SHA-256 into 32 bytes. Avoids a hex-crate dependency for this one use.
fn parse_sha256(hex: &str) -> anyhow::Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        anyhow::bail!("sha256 must be 64 hex chars, got {}", hex.len());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| anyhow::anyhow!("bad sha256 hex: {e}"))?;
    }
    Ok(out)
}

#[derive(Debug, Deserialize, Clone)]
pub struct EnrollSeed {
    pub key: String,
    pub user_id: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CommunitySeed {
    pub guild_id: u64,
    pub slug: String,
}

#[derive(Debug, Deserialize)]
pub struct DiscordConfig {
    pub bot_token: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OauthConfig {
    /// The Discord app's public `client_id`. The engine runs PKCE as a public client, so no secret
    /// or redirect URI lives here — the engine owns the loopback redirect and the token exchange.
    pub client_id: String,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_config_parses_and_builds_manifest() {
        let toml = r#"
            version = "0.2.0"
            [[artifact]]
            platform = "linux-amd64"
            url = "https://example.test/unitylan-engine-linux-amd64"
            sha256 = "0000000000000000000000000000000000000000000000000000000000000001"
            size = 1024
        "#;
        let rc: ReleaseConfig = toml::from_str(toml).unwrap();
        let m = rc.to_manifest().unwrap();
        assert_eq!(m.version, "0.2.0");
        let a = m
            .artifact_for(common::update::Platform::LinuxAmd64)
            .unwrap();
        assert_eq!(a.sha256[31], 1);
        assert_eq!(a.sha256[0], 0);
        assert_eq!(a.size, 1024);
    }

    #[test]
    fn bad_sha256_fails_closed() {
        assert!(parse_sha256("deadbeef").is_err()); // too short
        assert!(parse_sha256(&"zz".repeat(32)).is_err()); // non-hex
        assert!(parse_sha256(&"ab".repeat(32)).is_ok()); // exactly 64 hex chars
    }
}
