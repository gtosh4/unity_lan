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
        rotation_chain,
    };

    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| format!("binding {}", cfg.bind))?;
    tracing::info!(addr = %cfg.bind, "coordinator listening");
    axum::serve(listener, api::router(state)).await?;
    Ok(())
}
