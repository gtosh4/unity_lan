//! UnityLAN coordinator: serves 1..N guilds — reads roles, allocates IPs, signs attestations
//! (design.md §3.1). Networks (role→network) live in a registry managed by admin slash
//! commands; the offline test config seeds them directly.

mod api;
mod config;
mod discord;
mod roles;
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

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "coordinator.toml".to_string());
    let cfg = Config::load(std::path::Path::new(&config_path))
        .with_context(|| format!("loading config {config_path}"))?;

    let store = Arc::new(Store::open(&cfg.database).await?);
    let seed = store.load_or_create_seed().await?;
    let signer = Arc::new(Signer::from_seed(&seed));

    // Seed the network registry from config (test convenience; prod uses slash commands).
    for n in &cfg.network_seeds {
        store.upsert_network(n.guild_id, n.role_id, &n.name).await?;
    }

    let roles: Arc<dyn RoleSource> = match (cfg.fake, cfg.discord) {
        (Some(_), Some(_)) => anyhow::bail!("config has both [fake] and [discord]; pick one"),
        (Some(fake), None) => {
            tracing::warn!("running with FAKE role source (offline dev mode)");
            Arc::new(FakeRoleSource::new(fake))
        }
        (None, Some(d)) => {
            tracing::info!("running with live Discord role source");
            Arc::new(crate::discord::TwilightRoleSource::new(d.bot_token))
        }
        (None, None) => anyhow::bail!("no role source configured; add a [fake] or [discord] block"),
    };

    if cfg.dev_auth {
        tracing::warn!("dev_auth enabled: ?dev_user= bypasses OAuth — testing only");
    }

    let state = AppState {
        signer,
        roles,
        store,
        allow_dev: cfg.dev_auth,
    };

    let listener = tokio::net::TcpListener::bind(&cfg.bind)
        .await
        .with_context(|| format!("binding {}", cfg.bind))?;
    tracing::info!(addr = %cfg.bind, "coordinator listening");
    axum::serve(listener, api::router(state)).await?;
    Ok(())
}
