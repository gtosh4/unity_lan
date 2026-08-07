//! Coordinator configuration (TOML). A coordinator may serve multiple guilds.
//!
//! Two role sources: the live `[discord]` + `[oauth]` blocks, or an offline `[fake]` source for
//! dev/tests (mutually exclusive). The `[[network]]` seeds pre-populate the registry (simulating
//! admin slash commands) — useful in the test config; in production networks are managed via
//! `/unitylan network`.

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

const MIN_ADMIN_TOKEN_BYTES: usize = 32;

/// Wire limits from RFC 1035 §2.3.4, enforced on `[dns] domain` so an over-long name fails at
/// startup instead of producing an unencodable response later.
const MAX_DNS_NAME_LEN: usize = 253;
const MAX_DNS_LABEL_LEN: usize = 63;

/// Floor on `attestation_ttl_secs`, **relaxed in debug builds**.
///
/// The bound guards coordinator load, not security: the long-poll hold is TTL/2, so a short TTL
/// multiplies how often every parked client wakes and rebuilds a snapshot. That is a concern for a
/// *deployment*, and every shipped artifact is built `--release` (`packaging/build.sh`,
/// `windows/build.ps1`, `docker/coordinator.Dockerfile`) — so `debug_assertions` is a reliable
/// "not production" signal here.
///
/// A debug build lowers it because the end-to-end scripts time their phases in multiples of the
/// TTL, and waiting out a 60-second attestation lifetime three times over costs minutes per run for
/// no extra coverage. `scripts/gossip-test.sh` goes from ~3m10s to ~1m10s.
///
/// The divergence only ever *removes* a restriction in debug — release is strictly stricter, the
/// same direction as `StatusReport::directive`, which only a debug-build GUI honors. A config below
/// the release floor fails at startup with the message below, loudly and immediately, which is the
/// benign end of dev/prod divergence. `MAX` is not relaxed: nothing needs it and a huge TTL is a
/// real hazard in either profile.
#[cfg(not(debug_assertions))]
const MIN_ATTESTATION_TTL_SECS: u64 = 60;
#[cfg(debug_assertions)]
const MIN_ATTESTATION_TTL_SECS: u64 = 5;
/// The floor a *release* coordinator enforces, named separately so the error message can say so
/// even when a debug build accepted the same value.
const RELEASE_MIN_ATTESTATION_TTL_SECS: u64 = 60;

// The relaxation must only ever loosen, never tighten. Checked at compile time in both profiles, so
// swapping the two constants is a build error rather than a surprise at deploy time.
const _: () = assert!(MIN_ATTESTATION_TTL_SECS <= RELEASE_MIN_ATTESTATION_TTL_SECS);
// ...and in a release build the two must be the same number: the shipped coordinator enforces the
// release floor and nothing weaker. The behavioural test for this can only run under
// `cargo test --release`, which CI doesn't do — this fires during the release build itself, which
// is the moment that actually matters.
#[cfg(not(debug_assertions))]
const _: () = assert!(MIN_ATTESTATION_TTL_SECS == RELEASE_MIN_ATTESTATION_TTL_SECS);

const MAX_ATTESTATION_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_RELEASE_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

/// Gate on `[discord] api_proxy`, which redirects every Discord REST call — **including the one
/// carrying the bot token** — at whatever it names. A shipped coordinator has no reason to want
/// that, so it is refused outright in release builds; a debug one accepts only a plaintext loopback
/// address, so the worst a stray config can do is talk to something on the same machine.
fn validate_api_proxy(proxy: &str) -> anyhow::Result<()> {
    if !cfg!(debug_assertions) {
        anyhow::bail!(
            "[discord] api_proxy is a benchmark-only hook and is refused by a release coordinator; \
             remove it from the config"
        );
    }
    let rest = proxy.strip_prefix("http://").ok_or_else(|| {
        anyhow::anyhow!("[discord] api_proxy must start with http:// (got {proxy:?})")
    })?;
    let host = rest
        .split('/')
        .next()
        .unwrap_or_default()
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(rest);
    let loopback = host == "localhost"
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if !loopback {
        anyhow::bail!(
            "[discord] api_proxy must point at loopback — it decides where the bot token is sent \
             (got host {host:?})"
        );
    }
    Ok(())
}

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
    /// Public DNS domain this deployment issues TLS certificates under. Absent → no certificate
    /// feature: peers are reachable as `<device>.<user>.unity.internal` only, and clients are told
    /// so (`RegisterResp::dns_domain` is `None`), so they never attempt issuance.
    #[serde(default)]
    pub dns: Option<DnsConfig>,
}

/// The `[enrollment]` block: policy for the DH possession proof a device presents when it first
/// binds its WireGuard pubkey (proving it holds the matching private key, so a party who only learned
/// the pubkey can't squat it).
#[derive(Debug, Deserialize, Clone)]
pub struct EnrollmentConfig {
    /// Require a valid possession proof on every enrolling register. Default `true`: an enrollment
    /// that sends no proof is refused, so a party who only learned an unbound WireGuard pubkey can't
    /// claim it under their own account.
    ///
    /// This shipped observe-only in v0.4.1 (verify a proof when sent, admit and count enrollments
    /// without one) so a coordinator could upgrade ahead of its clients. Every client that enrolls
    /// sends one from that release on, and the fleet is now well past it, so the gate is closed by
    /// default. `require_proof = false` restores observe-only for a deployment that still has
    /// pre-v0.4.1 engines enrolling new devices — it counts them in
    /// `unitylan_enrollments_unproven_total` rather than refusing them.
    #[serde(default = "default_require_proof")]
    pub require_proof: bool,
}

impl Default for EnrollmentConfig {
    fn default() -> Self {
        Self {
            require_proof: default_require_proof(),
        }
    }
}

fn default_require_proof() -> bool {
    true
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

/// The `[dns]` block: the public domain mesh certificate names live under, plus the authoritative
/// responder that proves control of it to a CA.
///
/// A mesh name resolves to a `100.64.0.0/10` address only reachable inside the mesh, so a CA can
/// never connect to it — HTTP-01 and TLS-ALPN-01 are both unusable, and DNS-01 is the only challenge
/// left. That needs a `_acme-challenge` TXT record in *public* DNS, which is what this responder
/// serves. Delegate `domain` here with one `NS` record in the parent zone:
///
/// ```text
/// mesh   NS   coordinator.example.com.
/// ```
///
/// The zone carries challenge records and nothing else — no `A` records, so mesh addresses are never
/// published. Clients resolve those locally through the engine's resolver hook, as they always have.
#[derive(Debug, Deserialize, Clone)]
pub struct DnsConfig {
    /// Public domain certificate names live under, e.g. `mesh.example.com`. Devices are named
    /// `<device>.<user>.<domain>`, alongside (never replacing) their `unity.internal` name.
    pub domain: String,
    /// Address the authoritative responder binds, UDP **and** TCP (a truncated UDP answer is retried
    /// over TCP, so a UDP-only responder fails for any resolver that retries). Bind an unprivileged
    /// port and publish it as 53 rather than granting the coordinator `CAP_NET_BIND_SERVICE`; in
    /// Docker that is `53:5353/udp` plus `53:5353/tcp`.
    pub bind: SocketAddr,
    /// Ceiling on certificate issuances admitted per rolling week, across the whole deployment.
    ///
    /// Let's Encrypt caps certificates per *registered domain* (eTLD+1) per week. Until `domain`'s
    /// parent is on the Public Suffix List, every user here shares the parent's single bucket, and
    /// exhausting it locks the deployment out for the remainder of the week — worse than declining
    /// early. Keep this under the CA's real cap so a burst (a LAN party enrolling at once) is refused
    /// with a clear error instead of spending the last of the budget.
    ///
    /// The client-side gates — opt-in per device, and only for devices exposing a port — keep normal
    /// use far below this. It exists for the burst.
    #[serde(default = "default_max_certs_per_week")]
    pub max_certs_per_week: u32,
}

fn default_max_certs_per_week() -> u32 {
    40
}

/// Suffixes no public CA will ever issue for: reserved or special-use names (RFC 6761 `.test`,
/// `.example`, `.invalid`, `.localhost`; RFC 6762 `.local`; RFC 7686 `.onion`; RFC 8375 `.home.arpa`;
/// RFC 9476 `.alt`; and ICANN's `.internal`). Configuring one is always a mistake, and catching it at
/// startup beats discovering it when the first client's order is rejected days later.
const UNISSUABLE_SUFFIXES: &[&str] = &[
    "internal",
    "local",
    "localhost",
    "test",
    "example",
    "invalid",
    "onion",
    "alt",
    "home.arpa",
];

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
    /// Send Discord REST at this base URL instead of `discord.com` — the benchmark hook for
    /// `examples/mock_discord.rs` (see `scripts/coordinator-discord-scale-test.sh`).
    ///
    /// This decides where the **bot token** is sent, so it is fenced twice: rejected outright in
    /// release builds, and restricted to a loopback host in debug ones. Setting it also suppresses
    /// the gateway task, which would otherwise dial the real `gateway.discord.gg` alongside a mocked
    /// REST API and log reconnect failures through the whole run.
    #[serde(default)]
    pub api_proxy: Option<String>,
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
    /// The member's global Discord username. Seeds the `<user>` DNS label.
    pub username: String,
    #[serde(default)]
    pub role_ids: Vec<u64>,
}

impl Config {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading {}: {e}", path.display()))?;
        let mut cfg: Self = toml::from_str(&text)?;
        if let Some(dns) = &mut cfg.dns {
            dns.normalize();
            dns.validate()?;
        }
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
        // Say so explicitly rather than letting a value that loaded in a debug build fail at deploy
        // time against a floor whose number appears nowhere the operator looked.
        if cfg.attestation_ttl_secs < RELEASE_MIN_ATTESTATION_TTL_SECS {
            tracing::warn!(
                ttl = cfg.attestation_ttl_secs,
                "attestation_ttl_secs is below {RELEASE_MIN_ATTESTATION_TTL_SECS}: accepted by this \
                 debug build for the end-to-end scripts, but a release coordinator will refuse to \
                 start on this config"
            );
        }
        if let Some(discord) = &cfg.discord {
            if let Some(proxy) = &discord.api_proxy {
                validate_api_proxy(proxy)?;
            }
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

impl DnsConfig {
    /// Lower-case the domain and drop a trailing root dot, so `Mesh.Example.Com.` and
    /// `mesh.example.com` are the same config. DNS is case-insensitive, but the rest of the
    /// coordinator compares these as plain strings — normalising once here keeps that safe.
    pub(crate) fn normalize(&mut self) {
        self.domain = self
            .domain
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
    }

    /// Reject a domain no CA could ever issue for, at startup rather than at the first client's
    /// order — the failure would otherwise surface days later, in a client's logs, as an opaque CA
    /// rejection nowhere near the config that caused it.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        let domain = &self.domain;
        if domain.is_empty() {
            anyhow::bail!("dns domain must not be empty");
        }
        if domain.len() > MAX_DNS_NAME_LEN {
            anyhow::bail!("dns domain exceeds the {MAX_DNS_NAME_LEN}-byte DNS name limit");
        }
        let labels: Vec<&str> = domain.split('.').collect();
        if labels.len() < 2 {
            anyhow::bail!(
                "dns domain {domain:?} must be a fully-qualified public domain of at least two \
                 labels, e.g. \"mesh.example.com\""
            );
        }
        for label in &labels {
            if label.is_empty() {
                anyhow::bail!("dns domain {domain:?} has an empty label");
            }
            if label.len() > MAX_DNS_LABEL_LEN {
                anyhow::bail!(
                    "dns domain label {label:?} exceeds the {MAX_DNS_LABEL_LEN}-byte limit"
                );
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                anyhow::bail!(
                    "dns domain label {label:?} may contain only ASCII letters, digits, and hyphens \
                     (punycode an internationalised name before configuring it)"
                );
            }
            if label.starts_with('-') || label.ends_with('-') {
                anyhow::bail!("dns domain label {label:?} may not start or end with a hyphen");
            }
        }
        // An all-digit final label means this is an IP address, not a name a CA can validate.
        if labels[labels.len() - 1].bytes().all(|b| b.is_ascii_digit()) {
            anyhow::bail!("dns domain {domain:?} looks like an IP address, not a domain name");
        }
        for suffix in UNISSUABLE_SUFFIXES {
            if domain == suffix || domain.ends_with(&format!(".{suffix}")) {
                anyhow::bail!(
                    "dns domain {domain:?} ends in the reserved suffix {suffix:?}: no publicly-trusted \
                     CA will ever issue a certificate for it. Use a domain you own, or leave [dns] \
                     out entirely to run without certificates on unity.internal names"
                );
            }
        }
        if self.max_certs_per_week == 0 {
            anyhow::bail!(
                "max_certs_per_week must be at least 1 (omit [dns] to disable certificates instead)"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These run in a debug build, which is the profile that *accepts* `api_proxy` at all — so they
    // pin the loopback restriction. The release refusal is enforced by the `cfg!` above and can only
    // be observed under `cargo test --release`, which CI does not run.
    #[test]
    fn api_proxy_accepts_loopback_only() {
        for good in [
            "http://127.0.0.1:18081",
            "http://localhost:18081",
            "http://[::1]:18081",
            "http://127.0.0.1:18081/",
        ] {
            assert!(validate_api_proxy(good).is_ok(), "should accept {good}");
        }
    }

    #[test]
    fn api_proxy_rejects_anything_that_leaves_the_machine() {
        // The bot token rides on every call this redirects, so a non-loopback host is the whole
        // hazard the check exists for.
        for bad in [
            "http://discord.com",
            "http://10.0.0.5:8080",
            "http://example.test:18081",
            "https://127.0.0.1:18081", // plaintext only — the mock serves nothing else
            "127.0.0.1:18081",         // no scheme
        ] {
            assert!(validate_api_proxy(bad).is_err(), "should reject {bad}");
        }
    }

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

    /// Parse a `[dns]` body, normalise it, and validate — the same order `Config::load` uses.
    fn dns(body: &str) -> anyhow::Result<DnsConfig> {
        let mut cfg: DnsConfig = toml::from_str(body)?;
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn dns_domain_is_normalized() {
        let cfg = dns("domain = 'Mesh.Example.Com.'\nbind = '0.0.0.0:5353'").unwrap();
        assert_eq!(cfg.domain, "mesh.example.com");
        assert_eq!(cfg.max_certs_per_week, 40);
    }

    #[test]
    fn dns_rejects_unissuable_suffixes() {
        // The whole point of the block is getting a *publicly-trusted* certificate, and no CA will
        // issue for a reserved suffix — so these must fail at startup, not at the first order.
        for domain in [
            "mesh.unity.internal",
            "sub.internal",
            "mesh.local",
            "box.home.arpa",
            "foo.test",
            "site.example",
            "hidden.onion",
        ] {
            let err = dns(&format!("domain = '{domain}'\nbind = '0.0.0.0:5353'")).unwrap_err();
            assert!(
                err.to_string().contains("reserved suffix"),
                "{domain} should be rejected as reserved, got: {err}"
            );
        }
    }

    #[test]
    fn dns_rejects_malformed_domains() {
        for domain in [
            "example",     // single label
            "internal",    // ...including a bare reserved one
            "mesh..com",   // empty label
            "mesh_1.com",  // underscore is not a hostname character
            "-mesh.com",   // leading hyphen
            "mesh-.com",   // trailing hyphen
            "192.168.1.1", // an address, not a name
        ] {
            assert!(
                dns(&format!("domain = '{domain}'\nbind = '0.0.0.0:5353'")).is_err(),
                "{domain} should be rejected"
            );
        }
        assert!(dns("domain = 'mesh.example.com'\nbind = '0.0.0.0:5353'").is_ok());
    }

    #[test]
    fn dns_rejects_zero_cert_budget() {
        let err = dns("domain = 'mesh.example.com'\nbind = '0.0.0.0:5353'\nmax_certs_per_week = 0")
            .unwrap_err();
        assert!(err.to_string().contains("max_certs_per_week"));
    }

    #[test]
    fn dns_block_is_optional_and_validated_at_load() {
        let base = "bind = '127.0.0.1:8080'\ndatabase = 'test.db'\n";
        let dir = common::testutil::TempDir::new("dns-block");

        // Absent → no certificate feature, and the coordinator still starts.
        let path = dir.join("no-dns.toml");
        std::fs::write(&path, base).unwrap();
        assert!(Config::load(&path).unwrap().dns.is_none());

        // Present but unissuable → refuse to start, rather than failing per-client later.
        let path = dir.join("bad-dns.toml");
        std::fs::write(
            &path,
            format!("{base}[dns]\ndomain = 'mesh.unity.internal'\nbind = '0.0.0.0:5353'\n"),
        )
        .unwrap();
        assert!(Config::load(&path)
            .unwrap_err()
            .to_string()
            .contains("reserved suffix"));

        let path = dir.join("good-dns.toml");
        std::fs::write(
            &path,
            format!("{base}[dns]\ndomain = 'mesh.example.com'\nbind = '0.0.0.0:5353'\n"),
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap().dns.unwrap();
        assert_eq!(cfg.domain, "mesh.example.com");
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

        let dir = common::testutil::TempDir::new("zero-longpolls");
        let path = dir.join("coordinator.toml");
        std::fs::write(&path, format!("{base}max_longpolls = 0\n")).unwrap();
        let err = Config::load(&path).unwrap_err();
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
        // A counter rather than the process id: tests run concurrently and several call this more
        // than once, so the scratch dir has to be unique per *call*, not per process. The `TempDir`
        // then cleans up on the way out of this function, including the `?` above.
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = common::testutil::TempDir::new(&format!(
            "config-{}",
            N.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let path = dir.join("coordinator.toml");
        std::fs::write(
            &path,
            format!("bind = '127.0.0.1:8080'\ndatabase = 'test.db'\n{extra}"),
        )?;
        Config::load(&path)
    }

    /// The TTL floor is deliberately lower in debug builds so the end-to-end scripts don't spend
    /// minutes waiting out attestation lifetimes — `scripts/gossip-test.sh` runs at 20. Asserted
    /// through `load`, not against the constants, so it's the actual accept/reject behaviour that's
    /// pinned. Relaxed, never removed: absurd values and the ceiling are refused either way.
    #[cfg(debug_assertions)]
    #[test]
    fn a_debug_build_accepts_the_short_ttls_the_scripts_need() {
        assert!(load_text("attestation_ttl_secs = 20\n").is_ok());
        assert!(load_text("attestation_ttl_secs = 1\n").is_err());
        assert!(load_text("attestation_ttl_secs = 604801\n").is_err());
    }

    /// The counterpart, and the reason the relaxation above is safe rather than merely convenient:
    /// a shipped coordinator still refuses anything under 60. Only runs under
    /// `cargo test --release`; the `const _` assertions beside the constants are what enforce the
    /// same property during an ordinary release build.
    #[cfg(not(debug_assertions))]
    #[test]
    fn a_release_build_enforces_the_full_ttl_floor() {
        assert!(load_text("attestation_ttl_secs = 20\n").is_err());
        assert!(load_text("attestation_ttl_secs = 59\n").is_err());
        assert!(load_text("attestation_ttl_secs = 60\n").is_ok());
        assert!(load_text("attestation_ttl_secs = 604801\n").is_err());
    }

    #[test]
    fn rejects_unsafe_security_configuration() {
        assert!(load_text("attestation_ttl_secs = 0\n").is_err());
        assert!(load_text("[admin]\ntoken = ''\n").is_err());
        assert!(load_text("[admin]\ntoken = 'short'\n").is_err());
    }

    #[test]
    fn enrollment_proof_is_required_unless_a_deployment_opts_out() {
        // Both spellings of "not configured" — no block at all, and a block that omits the key —
        // must land on the fail-closed side; a default that only holds in one of them is how a
        // security gate silently reverts.
        let cfg = load_text("").expect("a minimal config");
        assert!(cfg.enrollment.require_proof, "absent [enrollment] block");
        let cfg = load_text("[enrollment]\n").expect("empty block");
        assert!(cfg.enrollment.require_proof, "block without the key");
        // Explicit opt-out for a deployment still enrolling pre-v0.4.1 engines.
        let cfg = load_text("[enrollment]\nrequire_proof = false\n").expect("opt-out");
        assert!(!cfg.enrollment.require_proof);
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
