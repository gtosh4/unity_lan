//! Coordinator configuration (TOML). A coordinator may serve multiple guilds.
//!
//! Two role sources: the live `[discord]` + `[oauth]` blocks, or an offline `[fake]` source for
//! dev/tests (mutually exclusive). The `[[network]]` seeds pre-populate the registry (simulating
//! admin slash commands) — useful in the test config; in production networks are managed via
//! `/unitylan network`.

use std::path::PathBuf;

use serde::Deserialize;

const MIN_ADMIN_TOKEN_BYTES: usize = 32;
const MIN_ATTESTATION_TTL_SECS: u64 = 60;
const MAX_ATTESTATION_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_RELEASE_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

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
    /// Reverse proxies whose `X-Forwarded-For` header may be believed, as CIDRs.
    ///
    /// The rate limiter buckets by source IP. When TLS is terminated by a proxy on the same host
    /// (Caddy, nginx), every request arrives from loopback, so **the whole deployment shares one
    /// bucket** and the per-IP cap throttles everyone together. Listing the proxy here makes the
    /// limiter read the real client from `X-Forwarded-For` instead.
    ///
    /// Empty by default — an unlisted peer's `X-Forwarded-For` is ignored, since a header anyone can
    /// set would otherwise let a caller forge a fresh bucket per request and bypass the limiter
    /// entirely. Only list proxies you control. Typical Caddy-on-the-same-host setup:
    /// `trusted_proxies = ["127.0.0.1/32", "::1/128"]`.
    #[serde(default)]
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// Maximum number of simultaneously parked client register/refresh long-polls. This is a global
    /// coordinator limit (independent of source IP, so reverse proxies do not collapse or bypass it),
    /// with a separate one-active-long-poll-per-device rule. Size it below the coordinator *and*
    /// reverse proxy's fd/memory ceilings. Default: 4096.
    #[serde(default = "default_max_longpolls")]
    pub max_longpolls: usize,
    /// Slowloris guard: seconds a client is given to send its *complete* request headers before the
    /// connection is dropped. `axum::serve` arms no such deadline, so without this a peer that opens a
    /// socket and dribbles (or withholds) header bytes ties up a connection — and an fd — indefinitely,
    /// before the rate limiter or long-poll admission ceiling can act (both run only once a request has
    /// been fully received and dispatched). Applies to the header phase alone; a long-poll that has
    /// already been dispatched is not cut. Default: 15.
    #[serde(default = "default_header_read_timeout_secs")]
    pub header_read_timeout_secs: u64,
    /// Hard ceiling on simultaneously-open TCP connections, enforced at accept time. Every parked
    /// long-poll holds one connection, so this must sit *above* `max_longpolls` with headroom for the
    /// short-lived requests in flight — it bounds the connection flood a slowloris or stalled-handshake
    /// attack can raise before it would exhaust the process fd table (which fails unrelated work — DB
    /// queries, new accepts — process-wide). Keep it under the coordinator's (and any reverse proxy's)
    /// fd ceiling. Default: 8192.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
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
    /// UDP address the STUN Binding responder binds (M5.5 ICE bootstrap fallback). When set, the
    /// coordinator serves reflexive-address lookups here and advertises **only its port** to
    /// clients, which pair it with the coordinator hostname they already dial (see
    /// `RegisterResp::stun_port`) — so `0.0.0.0:3478` is the normal value behind a container
    /// bridge or cloud NAT. Absent → no fallback (clients rely on relay-node STUN only).
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
    /// Enrollment-time device possession proof.
    #[serde(default)]
    pub enrollment: EnrollmentConfig,
}

/// The `[enrollment]` block: policy for the DH possession proof a device presents when it first
/// binds its WireGuard pubkey (proving it holds the matching private key, so a party who only learned
/// the pubkey can't squat it).
#[derive(Debug, Deserialize, Clone, Default)]
pub struct EnrollmentConfig {
    /// Require a valid possession proof on every enrolling register. Default `false` (observe-only):
    /// the coordinator rejects a *malformed* proof but still admits an enrollment that sends none,
    /// logging a warning and counting it (`unitylan_enrollments_unproven_total`) so an operator can
    /// see when the fleet is proof-clean. A *present* proof is always verified regardless.
    ///
    // TODO(phase2): flip this default to `true` once `MIN_PROTOCOL_VERSION` is past the first release
    // that shipped the client-side proof — by then no enrolling client omits it, so fail-closed costs
    // nothing. Until then a mixed fleet with older engines still needs to enroll new devices.
    #[serde(default)]
    pub require_proof: bool,
}

fn default_attestation_ttl() -> u64 {
    common::ATTESTATION_TTL_SECS
}

fn default_max_longpolls() -> usize {
    4096
}

fn default_header_read_timeout_secs() -> u64 {
    15
}

fn default_max_connections() -> usize {
    8192
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
    /// Optional pre-signed manifest blob: a base64 [`common::wire::Signed`] the release pipeline
    /// produced offline with the dedicated release key (`unitylan-coordinator sign-release`). The
    /// coordinator serves it **verbatim** in `RegisterResp.release_signed` — it never holds the
    /// release key. Clients with a baked release pubkey verify it against that key and ignore the
    /// guild-signed manifest, so a leaked guild key can't sign a binary update. Its inner version
    /// must match [`version`](Self::version) (a consistency check, so a stale paste fails at startup).
    /// `None` → only the legacy guild-anchor path is served.
    #[serde(default)]
    pub signed_blob: Option<String>,
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
        let cfg: Self = toml::from_str(&text)?;
        if cfg.max_longpolls == 0 {
            anyhow::bail!("max_longpolls must be at least 1");
        }
        if cfg.max_longpolls > tokio::sync::Semaphore::MAX_PERMITS {
            anyhow::bail!(
                "max_longpolls {} exceeds the implementation maximum {}",
                cfg.max_longpolls,
                tokio::sync::Semaphore::MAX_PERMITS
            );
        }
        if cfg.header_read_timeout_secs == 0 {
            anyhow::bail!("header_read_timeout_secs must be at least 1");
        }
        if cfg.max_connections <= cfg.max_longpolls {
            anyhow::bail!(
                "max_connections ({}) must exceed max_longpolls ({}): each parked long-poll holds a \
                 connection, so an equal or smaller cap would starve new requests",
                cfg.max_connections,
                cfg.max_longpolls
            );
        }
        if cfg.max_connections > tokio::sync::Semaphore::MAX_PERMITS {
            anyhow::bail!(
                "max_connections {} exceeds the implementation maximum {}",
                cfg.max_connections,
                tokio::sync::Semaphore::MAX_PERMITS
            );
        }
        if !(MIN_ATTESTATION_TTL_SECS..=MAX_ATTESTATION_TTL_SECS)
            .contains(&cfg.attestation_ttl_secs)
        {
            anyhow::bail!(
                "attestation_ttl_secs must be between {MIN_ATTESTATION_TTL_SECS} and {MAX_ATTESTATION_TTL_SECS}"
            );
        }
        if let Some(admin) = &cfg.admin {
            if admin.token.len() < MIN_ADMIN_TOKEN_BYTES {
                anyhow::bail!(
                    "admin token must be at least {MIN_ADMIN_TOKEN_BYTES} bytes of random data"
                );
            }
        }
        if let Some(release) = &cfg.release {
            release.validate()?;
        }
        Ok(cfg)
    }
}

impl ReleaseConfig {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        semver::Version::parse(&self.version).map_err(|e| {
            anyhow::anyhow!("release version {:?} is not semver: {e}", self.version)
        })?;
        let mut platforms = std::collections::HashSet::new();
        for artifact in &self.artifacts {
            let url = reqwest::Url::parse(&artifact.url)
                .map_err(|e| anyhow::anyhow!("invalid release URL {:?}: {e}", artifact.url))?;
            if url.scheme() != "https" {
                anyhow::bail!("release URL must use https: {}", artifact.url);
            }
            if artifact.size == 0 || artifact.size > MAX_RELEASE_ARTIFACT_BYTES {
                anyhow::bail!(
                    "release artifact size must be between 1 and {MAX_RELEASE_ARTIFACT_BYTES} bytes"
                );
            }
            if !platforms.insert(artifact.platform) {
                anyhow::bail!(
                    "release contains duplicate platform {:?}",
                    artifact.platform
                );
            }
        }
        // A pre-signed blob, if present, must be a well-formed `Signed` whose inner manifest names the
        // same version — so an operator can't paste a stale or corrupt blob and unknowingly serve it.
        // We decode (not verify: the coordinator holds no release key) purely for this sanity check.
        if let Some(blob) = &self.signed_blob {
            let manifest = common::update::peek_signed_manifest(blob).map_err(|e| {
                anyhow::anyhow!("release signed_blob is not a valid signed ReleaseManifest: {e}")
            })?;
            if manifest.version != self.version {
                anyhow::bail!(
                    "release signed_blob version {:?} does not match [release] version {:?}",
                    manifest.version,
                    self.version
                );
            }
        }
        Ok(())
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

    #[test]
    fn max_longpolls_defaults_and_zero_is_rejected() {
        let base = "bind = '127.0.0.1:8080'\ndatabase = 'test.db'\n";
        let cfg: Config = toml::from_str(base).unwrap();
        assert_eq!(cfg.max_longpolls, 4096);

        let path = std::env::temp_dir().join(format!(
            "unitylan-zero-longpolls-{}.toml",
            std::process::id()
        ));
        std::fs::write(&path, format!("{base}max_longpolls = 0\n")).unwrap();
        let err = Config::load(&path).unwrap_err();
        let _ = std::fs::remove_file(path);
        assert!(err.to_string().contains("max_longpolls must be at least 1"));
    }

    #[test]
    fn connection_guards_default_and_validate() {
        let base = "bind = '127.0.0.1:8080'\ndatabase = 'test.db'\n";
        let cfg: Config = toml::from_str(base).unwrap();
        assert_eq!(cfg.header_read_timeout_secs, 15);
        assert_eq!(cfg.max_connections, 8192);

        // A connection cap at or below the long-poll cap would starve new requests: every parked
        // long-poll holds a connection, so all slots could sit on held long-polls.
        let err = load_text("max_longpolls = 4096\nmax_connections = 4096\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("max_connections") && err.contains("must exceed max_longpolls"),
            "{err}"
        );

        // A zero header-read timeout disables the slowloris guard.
        let err = load_text("header_read_timeout_secs = 0\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("header_read_timeout_secs must be at least 1"),
            "{err}"
        );
    }

    fn load_text(extra: &str) -> anyhow::Result<Config> {
        let path = std::env::temp_dir().join(format!(
            "unitylan-config-{}-{}.toml",
            std::process::id(),
            common::crypto::gen_enrollment_key()
        ));
        std::fs::write(
            &path,
            format!("bind = '127.0.0.1:8080'\ndatabase = 'test.db'\n{extra}"),
        )?;
        let result = Config::load(&path);
        let _ = std::fs::remove_file(path);
        result
    }

    #[test]
    fn rejects_unsafe_security_configuration() {
        assert!(load_text("attestation_ttl_secs = 0\n").is_err());
        assert!(load_text("[admin]\ntoken = ''\n").is_err());
        assert!(load_text("[admin]\ntoken = 'short'\n").is_err());
    }

    #[test]
    fn validates_release_metadata_at_load() {
        let artifact = |version: &str, url: &str, size: u64| {
            format!(
                "[release]\nversion = '{version}'\n[[release.artifact]]\nplatform = 'linux-amd64'\nurl = '{url}'\nsha256 = '{}'\nsize = {size}\n",
                "ab".repeat(32)
            )
        };
        assert!(load_text(&artifact("not-semver", "https://example.test/a", 1)).is_err());
        assert!(load_text(&artifact("1.2.3", "http://example.test/a", 1)).is_err());
        assert!(load_text(&artifact("1.2.3", "https://example.test/a", 0)).is_err());
        assert!(load_text(&artifact("1.2.3", "https://example.test/a", 1024)).is_ok());

        let duplicate = format!(
            "{}[[release.artifact]]\nplatform = 'linux-amd64'\nurl = 'https://example.test/b'\nsha256 = '{}'\nsize = 1\n",
            artifact("1.2.3", "https://example.test/a", 1),
            "cd".repeat(32)
        );
        assert!(load_text(&duplicate).is_err());
    }

    #[test]
    fn validates_signed_blob_at_load() {
        let block = |version: &str, blob: &str| {
            format!(
                "[release]\nversion = '{version}'\nsigned_blob = '{blob}'\n[[release.artifact]]\nplatform = 'linux-amd64'\nurl = 'https://example.test/a'\nsha256 = '{}'\nsize = 1\n",
                "ab".repeat(32)
            )
        };
        let sign = |version: &str| {
            let key = common::crypto::CoordinatorKey::generate();
            let manifest = common::update::ReleaseManifest {
                version: version.into(),
                artifacts: vec![],
            };
            common::wire::Signed::sign(&key, &manifest)
                .unwrap()
                .to_base64()
        };
        // Blob's inner version matches [release].version → accepted.
        assert!(load_text(&block("1.2.3", &sign("1.2.3"))).is_ok());
        // Stale/mismatched blob version → fail closed at load.
        assert!(load_text(&block("1.2.3", &sign("9.9.9"))).is_err());
        // Garbage blob → fail closed.
        assert!(load_text(&block("1.2.3", "not-a-blob")).is_err());
    }
}
