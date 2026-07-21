//! UnityLAN coordinator: serves 1..N guilds — reads roles, allocates IPs, signs attestations
//! (design.md §3.1). Networks (role→network) live in a registry managed by admin slash
//! commands; the offline test config seeds them directly.

mod api;
mod commands;
mod config;
mod discord;
mod limiter;
mod oauth;
mod presence;
mod roles;
mod rotate;
mod signer;
mod store;
mod stun;
mod versions;

use std::sync::Arc;

use anyhow::Context;

use common::update::ReleaseManifest;

use crate::api::AppState;
use crate::config::Config;
use crate::roles::{FakeRoleSource, RoleSource};
use crate::signer::GuildKeys;
use crate::store::Store;

/// Resolve the deployment's mesh CIDR: the configured `cidr` (validated), or a `/16` derived from
/// the deployment seed within 100.64.0.0/10. Fails closed on a configured range outside private space.
fn resolve_mesh_cidr(cfg: &Config, seed: &[u8; 32]) -> anyhow::Result<ipnet::Ipv4Net> {
    match cfg.cidr {
        Some(net) => {
            validate_mesh_cidr(net)?;
            Ok(net)
        }
        None => {
            let anchor = common::crypto::CoordinatorKey::from_seed(seed).anchor_bytes();
            Ok(common::netid::default_cidr(&anchor))
        }
    }
}

/// A configured mesh CIDR must sit inside RFC1918/RFC6598 private space (so it can't collide with
/// the public internet or be spoofed as one) and be a sane size. Fails closed — a bad range surfaces
/// at startup, not as broken clients.
fn validate_mesh_cidr(net: ipnet::Ipv4Net) -> anyhow::Result<()> {
    const PRIVATE: [&str; 4] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
    ];
    let prefix = net.prefix_len();
    if !(8..=30).contains(&prefix) {
        anyhow::bail!("mesh cidr {net} prefix /{prefix} out of range (want /8..=/30)");
    }
    let inside = PRIVATE.iter().any(|s| {
        let sup: ipnet::Ipv4Net = s.parse().unwrap();
        sup.contains(&net.network()) && prefix >= sup.prefix_len()
    });
    if !inside {
        anyhow::bail!(
            "mesh cidr {net} is not within RFC1918/RFC6598 private space {PRIVATE:?}; refusing"
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // twilight's HTTPS (rustls) needs a process-wide crypto provider selected explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // `rotate-key --guild <id> [config]` is an offline admin subcommand: rotate one guild's signing
    // key and exit (keys are per-guild, §3.1). The operator restarts to sign under the new key.
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (rotate_guild, config_path): (Option<u64>, String) =
        if argv.first().map(String::as_str) == Some("rotate-key") {
            let mut guild = None;
            let mut config = None;
            let mut it = argv[1..].iter();
            while let Some(a) = it.next() {
                match a.as_str() {
                    "--guild" => {
                        let id = it.next().context("rotate-key: --guild needs an id")?;
                        guild = Some(id.parse::<u64>().context("rotate-key: bad --guild id")?);
                    }
                    other => config = Some(other.to_string()),
                }
            }
            let guild = guild.context("rotate-key requires --guild <guild_id>")?;
            (
                Some(guild),
                config.unwrap_or_else(|| "coordinator.toml".to_string()),
            )
        } else {
            (
                None,
                argv.first()
                    .cloned()
                    .unwrap_or_else(|| "coordinator.toml".to_string()),
            )
        };
    let cfg = Config::load(std::path::Path::new(&config_path))
        .with_context(|| format!("loading config {config_path}"))?;
    tracing::info!(
        max_longpolls = cfg.max_longpolls,
        "client long-poll admission configured"
    );

    raise_fd_limit();

    let store = Arc::new(Store::open(&cfg.database).await?);

    if let Some(guild_id) = rotate_guild {
        let anchor = crate::rotate::rotate_key(&store, guild_id).await?;
        let hex: String = anchor.iter().map(|b| format!("{b:02x}")).collect();
        println!("guild {guild_id} trust anchor rotated. new anchor: {hex}");
        println!("restart the coordinator to sign under the new key.");
        return Ok(());
    }

    let deployment_seed = store.load_or_create_deployment_seed().await?;
    let mesh_cidr = resolve_mesh_cidr(&cfg, &deployment_seed)?;
    tracing::info!(cidr = %mesh_cidr, "mesh address range");
    let guild_keys = Arc::new(GuildKeys::new(
        store.clone(),
        mesh_cidr,
        cfg.attestation_ttl_secs,
    ));

    // Seed the network registry from config (test convenience; prod uses slash commands).
    for n in &cfg.network_seeds {
        store.upsert_network(n.guild_id, n.role_id, &n.name).await?;
    }
    // Seed enrollment keys from config (test convenience; prod mints via `/unitylan enroll`).
    for e in &cfg.enroll_seeds {
        store.create_enrollment_key(&e.key, e.user_id, None).await?;
    }
    // Seed community slugs from config (admin config; default is the guild name).
    for c in &cfg.community_seeds {
        store.set_community_slug(c.guild_id, &c.slug).await?;
    }

    let fake = cfg.fake;
    let discord = cfg.discord;
    let fake_mode = fake.is_some();
    let roles: Arc<dyn RoleSource> = match (fake, &discord) {
        (Some(_), Some(_)) => anyhow::bail!("config has both [fake] and [discord]; pick one"),
        (Some(fk), None) => {
            tracing::warn!("running with FAKE role source (offline dev mode)");
            Arc::new(FakeRoleSource::new(fk))
        }
        (None, Some(d)) => {
            tracing::info!("running with live Discord role source");
            Arc::new(crate::discord::TwilightRoleSource::new(d.bot_token.clone()))
        }
        (None, None) => anyhow::bail!("no role source configured; add a [fake] or [discord] block"),
    };

    let presence = Arc::new(crate::presence::Presence::default());
    let versions = Arc::new(crate::versions::Versions::default());

    // Live Discord: run the gateway for `/unitylan` slash commands + role-revocation events.
    if let Some(d) = &discord {
        let token = d.bot_token.clone();
        let store = store.clone();
        let presence = presence.clone();
        let versions = versions.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::commands::run_gateway(token, store, presence, versions).await {
                tracing::error!("gateway task ended: {e:#}");
            }
        });
    }

    // Interactive-login provider: live Discord OAuth if configured, else a fake one in dev mode.
    let oauth: Option<Arc<dyn crate::oauth::OauthProvider>> = match (cfg.oauth, fake_mode) {
        (Some(o), _) => {
            tracing::info!("interactive login: Discord OAuth (PKCE, public client)");
            Some(Arc::new(crate::oauth::DiscordOauth::new(o.client_id)))
        }
        (None, true) => {
            tracing::warn!("interactive login: FAKE oauth (offline dev mode)");
            Some(Arc::new(crate::oauth::FakeOauth))
        }
        (None, false) => None,
    };

    // STUN Binding responder (M5.5 ICE bootstrap fallback), when configured. Only the port goes out
    // to clients (RegisterResp.stun_port) — they pair it with our hostname, since behind NAT we
    // can't know our own reachable address. Carries no traffic, so it's a detached background task.
    let stun_port = cfg.stun_bind.map(|a| a.port());
    if let Some(bind) = cfg.stun_bind {
        tokio::spawn(async move {
            if let Err(e) = crate::stun::serve(bind).await {
                tracing::error!("STUN responder exited: {e:#}");
            }
        });
    }

    // Parse + validate the auto-update manifest from `[release]`. It's signed per-request under a
    // guild key the caller holds (§3.1), so we hold the *parsed* manifest, not a pre-signed string.
    // Fails closed at startup: a malformed `[release]` aborts boot. Behind a RwLock so SIGHUP can
    // swap it without a restart (see below).
    let release = Arc::new(std::sync::RwLock::new(build_release(cfg.release.as_ref())?));

    // Reload the release manifest on SIGHUP (unix): re-read the config, re-sign `[release]`, and swap
    // it in — so an admin publishes a new release with `kill -HUP`, no restart. Only the release
    // manifest is reloaded (other config is seeded to the DB at startup and still needs a restart).
    // Unlike boot, a bad config here is non-fatal: log and keep serving the previous manifest.
    #[cfg(unix)]
    {
        let release = release.clone();
        let config_path = config_path.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut hup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("SIGHUP handler unavailable; release reload disabled: {e}");
                    return;
                }
            };
            while hup.recv().await.is_some() {
                match Config::load(std::path::Path::new(&config_path))
                    .and_then(|cfg| build_release(cfg.release.as_ref()))
                {
                    Ok(new) => {
                        *release.write().unwrap() = new;
                        tracing::info!("reloaded [release] manifest on SIGHUP");
                    }
                    Err(e) => {
                        tracing::error!("SIGHUP reload failed; keeping previous manifest: {e:#}")
                    }
                }
            }
        });
    }

    let state = AppState {
        guild_keys,
        sign_cache: Arc::new(crate::signer::SignCache::new(cfg.attestation_ttl_secs)),
        wakers: Arc::new(api::Wakers::default()),
        // Hold a renewal long-poll ≈ half the attestation TTL, so a client's own attestation is
        // refreshed (on poll return) well before it expires.
        longpoll_hold_secs: (cfg.attestation_ttl_secs / 2).max(1),
        park_slots: Arc::new(api::ParkSlots::new(cfg.max_longpolls)),
        roles,
        store,
        presence,
        versions,
        oauth,
        trusted_proxies: Arc::new(cfg.trusted_proxies.clone()),
        source_ip: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        reflexive: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        relays: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        relay_allocs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        ice: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        stun_port,
        release,
        admin_token: cfg.admin.as_ref().map(|a| a.token.clone()),
    };

    // Presence reaper: evict devices that stopped refreshing (crashed/dropped client, or the old
    // pubkey a re-keyed device abandoned). Bumps the scopes it actually reaped from, so co-members
    // prune the dead peer while unaffected guilds stay parked, then drops that device's now-orphaned
    // NAT side-table entries (reflexive / source-IP / relay / ICE) so those maps don't grow forever.
    {
        let st = state.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                st.versions.bump_all(
                    st.presence
                        .reap(common::now_unix(), common::PRESENCE_TTL_SECS),
                );
                api::prune_nat_tables(&st, &st.presence.present_pubkeys());
            }
        });
    }

    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| format!("binding {}", cfg.bind))?;
    tracing::info!(addr = %cfg.bind, "coordinator listening");
    // `into_make_service_with_connect_info` surfaces the peer address to the rate-limit middleware.
    axum::serve(
        listener,
        api::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// Raise the open-file soft limit to the hard limit.
///
/// Every parked long-poll is a held connection, so the coordinator's client ceiling is an fd count:
/// with a soft limit of 1024 (the systemd/glibc default on most distros) it stops accepting at ~1000
/// devices, well below what its CPU and memory can serve. Raising the *soft* limit up to the hard
/// limit needs no privilege, so the process does it for itself rather than relying on every operator
/// to remember a `LimitNOFILE=` / `--ulimit`.
///
/// Best-effort: a failure is logged, not fatal — the coordinator still runs, just with a lower
/// ceiling. Raising past the **hard** limit does need privilege; if that ceiling is the binding one
/// the logged numbers are what tells an operator to lift it in the unit file or container runtime.
#[cfg(unix)]
fn raise_fd_limit() {
    // SAFETY: both calls take a valid, fully initialized `rlimit` for a real resource and are
    // documented to only read/write through it.
    unsafe {
        let mut lim = std::mem::zeroed::<libc::rlimit>();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            tracing::warn!("could not read the open-file limit: {}", errno());
            return;
        }
        if lim.rlim_cur >= lim.rlim_max {
            tracing::debug!(
                limit = lim.rlim_cur,
                "open-file limit already at its maximum"
            );
            return;
        }
        let was = lim.rlim_cur;
        lim.rlim_cur = lim.rlim_max;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
            tracing::warn!(
                soft = was,
                hard = lim.rlim_max,
                "could not raise the open-file limit: {}; concurrent clients are capped by it",
                errno()
            );
            return;
        }
        tracing::info!(
            from = was,
            to = lim.rlim_max,
            "raised the open-file soft limit (each parked long-poll holds one)"
        );
    }
}

#[cfg(unix)]
fn errno() -> std::io::Error {
    std::io::Error::last_os_error()
}

/// Windows has no `RLIMIT_NOFILE`; its socket ceiling is governed by the OS, not a per-process soft
/// limit, so there's nothing to raise.
#[cfg(not(unix))]
fn raise_fd_limit() {}

/// Build the signed auto-update manifest from the `[release]` config, or `None` if unconfigured.
/// Signs with the coordinator anchor so clients verify it against their pinned key. Shared by the
/// startup path and the SIGHUP reload. Takes just the release block (not `&Config`) because the rest
/// of `cfg` is partially moved into the role/oauth sources by the time this runs at startup.
fn build_release(
    release: Option<&crate::config::ReleaseConfig>,
) -> anyhow::Result<Option<ReleaseManifest>> {
    match release {
        Some(rc) => {
            let manifest = rc.to_manifest()?;
            tracing::info!(
                version = %rc.version,
                artifacts = rc.artifacts.len(),
                "serving auto-update manifest"
            );
            Ok(Some(manifest))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::validate_mesh_cidr;

    fn net(s: &str) -> ipnet::Ipv4Net {
        s.parse().unwrap()
    }

    #[test]
    fn accepts_private_ranges() {
        for s in [
            "100.72.0.0/16",
            "10.0.0.0/8",
            "192.168.5.0/24",
            "172.16.0.0/12",
        ] {
            assert!(validate_mesh_cidr(net(s)).is_ok(), "{s} should be accepted");
        }
    }

    #[test]
    fn rejects_public_and_absurd_ranges() {
        // Public space — a MITM/typo mustn't point the mesh at real internet addresses.
        assert!(validate_mesh_cidr(net("8.8.8.0/24")).is_err());
        // Straddles private/public (192.168/16 is private but /15 leaks into 192.169).
        assert!(validate_mesh_cidr(net("192.168.0.0/15")).is_err());
        // Too small to allocate from, and too large.
        assert!(validate_mesh_cidr(net("10.0.0.0/31")).is_err());
        assert!(validate_mesh_cidr(net("10.0.0.0/7")).is_err());
    }
}
