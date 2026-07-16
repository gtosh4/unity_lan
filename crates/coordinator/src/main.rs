//! UnityLAN coordinator: serves 1..N guilds — reads roles, allocates IPs, signs attestations
//! (design.md §3.1). Networks (role→network) live in a registry managed by admin slash
//! commands; the offline test config seeds them directly.

mod api;
mod commands;
mod config;
mod discord;
mod oauth;
mod presence;
mod roles;
mod rotate;
mod signer;
mod store;
mod stun;

use std::sync::Arc;

use anyhow::Context;

use crate::api::AppState;
use crate::config::Config;
use crate::roles::{FakeRoleSource, RoleSource};
use crate::signer::Signer;
use crate::store::Store;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // twilight's HTTPS (rustls) needs a process-wide crypto provider selected explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // `rotate-key [config]` is an offline admin subcommand: rotate the trust anchor and exit. The
    // operator restarts the coordinator afterward to sign under the new key.
    let mut args = std::env::args().skip(1);
    let first = args.next();
    let (rotate_only, config_path) = match first.as_deref() {
        Some("rotate-key") => (true, args.next()),
        other => (false, other.map(String::from)),
    };
    let config_path = config_path.unwrap_or_else(|| "coordinator.toml".to_string());
    let cfg = Config::load(std::path::Path::new(&config_path))
        .with_context(|| format!("loading config {config_path}"))?;

    let store = Arc::new(Store::open(&cfg.database).await?);

    if rotate_only {
        let anchor = crate::rotate::rotate_key(&store).await?;
        let hex: String = anchor.iter().map(|b| format!("{b:02x}")).collect();
        println!("trust anchor rotated. new anchor: {hex}");
        println!("restart the coordinator to sign under the new key.");
        return Ok(());
    }

    let seed = store.load_or_create_seed().await?;
    let signer = Arc::new(Signer::from_seed(&seed));
    let rotation_chain = store.rotation_chain().await?;

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
    let version = Arc::new(tokio::sync::watch::channel(0u64).0);

    // Live Discord: run the gateway for `/unitylan` slash commands + role-revocation events.
    if let Some(d) = &discord {
        let token = d.bot_token.clone();
        let store = store.clone();
        let presence = presence.clone();
        let version = version.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::commands::run_gateway(token, store, presence, version).await {
                tracing::error!("gateway task ended: {e:#}");
            }
        });
    }

    // Presence reaper: evict devices that stopped refreshing (crashed/dropped client, or the old
    // pubkey a re-keyed device abandoned). Bumps the version so co-members prune the dead peer.
    {
        let presence = presence.clone();
        let version = version.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                if presence.reap(common::now_unix(), common::PRESENCE_TTL_SECS) {
                    version.send_modify(|v| *v += 1);
                }
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

    // STUN Binding responder (M5.5 ICE bootstrap fallback), when configured. Advertised to clients
    // via RegisterResp.stun_addr; carries no traffic, so it runs as a detached background task.
    let stun_addr = cfg.stun_bind;
    if let Some(bind) = stun_addr {
        tokio::spawn(async move {
            if let Err(e) = crate::stun::serve(bind).await {
                tracing::error!("STUN responder exited: {e:#}");
            }
        });
    }

    // Sign the auto-update manifest from `[release]` — it's static, so every RegisterResp serves the
    // cached string with no per-request work. Fails closed at startup: a malformed `[release]` aborts
    // boot. Held behind a RwLock so SIGHUP can re-sign it without a restart (see below).
    let release = Arc::new(std::sync::RwLock::new(build_release(
        cfg.release.as_ref(),
        &signer,
    )?));

    // Reload the release manifest on SIGHUP (unix): re-read the config, re-sign `[release]`, and swap
    // it in — so an admin publishes a new release with `kill -HUP`, no restart. Only the release
    // manifest is reloaded (other config is seeded to the DB at startup and still needs a restart).
    // Unlike boot, a bad config here is non-fatal: log and keep serving the previous manifest.
    #[cfg(unix)]
    {
        let release = release.clone();
        let signer = signer.clone();
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
                    .and_then(|cfg| build_release(cfg.release.as_ref(), &signer))
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
        signer,
        roles,
        store,
        presence,
        version,
        oauth,
        reflexive: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        relays: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        relay_allocs: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        ice: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        stun_addr,
        rotation_chain,
        release,
    };

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

/// Build the signed auto-update manifest from the `[release]` config, or `None` if unconfigured.
/// Signs with the coordinator anchor so clients verify it against their pinned key. Shared by the
/// startup path and the SIGHUP reload. Takes just the release block (not `&Config`) because the rest
/// of `cfg` is partially moved into the role/oauth sources by the time this runs at startup.
fn build_release(
    release: Option<&crate::config::ReleaseConfig>,
    signer: &Signer,
) -> anyhow::Result<Option<String>> {
    match release {
        Some(rc) => {
            let signed = signer.sign_to_base64(&rc.to_manifest()?)?;
            tracing::info!(
                version = %rc.version,
                artifacts = rc.artifacts.len(),
                "serving signed auto-update manifest"
            );
            Ok(Some(signed))
        }
        None => Ok(None),
    }
}
