//! UnityLAN engine (M1, headless): register with the coordinator, verify the signed
//! attestations, pin the trust anchor, and print the resulting IPs + hostnames.

mod config;
mod coord;
mod keys;

use anyhow::Context;

use crate::config::Config;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "engine.toml".to_string());
    let cfg = Config::load(std::path::Path::new(&config_path))
        .with_context(|| format!("loading config {config_path}"))?;

    let wg_pubkey = keys::load_or_generate_wg(&cfg.state_dir)?;

    let (resp, memberships) = coord::register(&cfg.coordinator, wg_pubkey, cfg.dev_user).await?;

    // Trust-on-first-use: pin the anchor, reject if it ever changes.
    keys::pin_anchor(&cfg.state_dir, &resp.coord_pubkey)?;

    if memberships.is_empty() {
        tracing::warn!("registered, but hold no networks (no roles)");
    }
    println!("verified {} membership(s):", memberships.len());
    for m in &memberships {
        println!(
            "  {:<16} {:<44} [{} / {} · role {}]",
            m.wg_ip, m.hostname, m.guild_name, m.network_name, m.role_id
        );
    }
    Ok(())
}
