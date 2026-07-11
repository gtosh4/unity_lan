//! Mesh daemon: register → bring up the WG interface with our `/32`s → peer the seeds →
//! refresh periodically, adding newly-seen co-members. Seed-based meshing (design.md §5);
//! P2P gossip layers on top later.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use crate::config::Config;
use crate::control;
use crate::coord::{self, SeedPeer};
use crate::dns;
use crate::keys;
use crate::wg::{IfaceConfig, PeerConfig, UserspaceBackend, WgBackend};

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let (wg_priv, wg_pub) = keys::load_or_generate_keypair(&cfg.state_dir)?;

    // Register + verify our own device.
    let (resp, device) = coord::register(
        &cfg.coordinator,
        wg_pub,
        cfg.device_name(),
        cfg.endpoint,
        cfg.enrollment_key.clone(),
    )
    .await?;
    keys::pin_anchor(&cfg.state_dir, &resp.coord_pubkey)?;
    let Some(device) = device else {
        anyhow::bail!("registered but hold no networks — nothing to mesh");
    };
    tracing::info!(
        "{} -> {}{}  (networks: {})",
        device.wg_ip,
        device.hostname,
        if device.is_primary { " [primary]" } else { "" },
        device.networks.join(", ")
    );

    // Bring up the single interface with our device /32.
    let mut backend = UserspaceBackend::new(&cfg.iface)?;
    backend.up(&IfaceConfig {
        private_key: wg_priv,
        addresses: vec![(device.wg_ip, 32)],
        listen_port: cfg.listen_port,
    })?;
    tracing::info!(iface = %cfg.iface, port = cfg.listen_port, "interface up");

    // Optional `.internal` resolver: serves our device + peers by name from verified attestations.
    let zone = dns::empty_zone();
    if let Some(bind) = cfg.dns_bind {
        let z = zone.clone();
        tokio::spawn(async move {
            if let Err(e) = dns::serve(bind, z).await {
                tracing::error!("dns resolver ended: {e:#}");
            }
        });
    }

    // Control socket: read-only status for CLI/GUI frontends.
    let status = control::shared();
    {
        let path = cfg.control_socket_path();
        let s = status.clone();
        tokio::spawn(async move {
            if let Err(e) = control::serve(&path, s).await {
                tracing::error!("control socket ended: {e:#}");
            }
        });
    }

    // Apply initial seeds, then refresh on an interval picking up new co-members.
    let mut peers: HashMap<[u8; 32], PeerConfig> = HashMap::new();
    let seeds = coord::verified_seeds(&resp)?;
    dns::update(&zone, &device, &seeds).await;
    control::update(&status, &device, &seeds).await;
    apply_seeds(&backend, seeds, &mut peers)?;

    let mut ticker = tokio::time::interval(Duration::from_secs(cfg.refresh_secs.max(1)));
    ticker.tick().await; // first tick is immediate
    loop {
        ticker.tick().await;
        match coord::refresh(
            &cfg.coordinator,
            wg_pub,
            cfg.device_name(),
            cfg.endpoint,
            cfg.enrollment_key.clone(),
        )
        .await
        {
            Ok((resp, dev)) => match coord::verified_seeds(&resp) {
                Ok(seeds) => {
                    if let Some(dev) = &dev {
                        dns::update(&zone, dev, &seeds).await;
                        control::update(&status, dev, &seeds).await;
                    }
                    apply_seeds(&backend, seeds, &mut peers)?;
                }
                Err(e) => tracing::warn!("bad seeds: {e:#}"),
            },
            Err(e) => tracing::warn!("refresh failed: {e:#}"),
        }
    }
}

/// Fold seeds (one per co-member per shared network) into peers keyed by pubkey, then push
/// any additions/changes to the backend and (re)install routing.
fn apply_seeds(
    backend: &dyn WgBackend,
    seeds: Vec<SeedPeer>,
    peers: &mut HashMap<[u8; 32], PeerConfig>,
) -> anyhow::Result<()> {
    // Aggregate this round's seeds by pubkey (a co-member may share several networks → several /32s).
    let mut desired: HashMap<[u8; 32], (Vec<(Ipv4Addr, u8)>, Option<SocketAddr>)> = HashMap::new();
    for s in seeds {
        let e = desired.entry(s.pubkey).or_insert_with(|| (Vec::new(), s.endpoint));
        e.0.push((s.ip, 32));
        if e.1.is_none() {
            e.1 = s.endpoint;
        }
    }

    let mut changed = false;
    for (pubkey, (mut allowed, endpoint)) in desired {
        allowed.sort();
        allowed.dedup();
        let peer = PeerConfig {
            public_key: pubkey,
            allowed_ips: allowed,
            endpoint,
            keepalive: Some(25),
        };
        let is_new = match peers.get(&pubkey) {
            Some(existing) => {
                existing.allowed_ips != peer.allowed_ips || existing.endpoint != peer.endpoint
            }
            None => true,
        };
        if is_new {
            backend.set_peer(&peer)?;
            tracing::info!(peer = %hex8(&pubkey), ips = ?peer.allowed_ips, "peer set");
            peers.insert(pubkey, peer);
            changed = true;
        }
    }

    if changed {
        let all: Vec<PeerConfig> = peers
            .values()
            .map(|p| PeerConfig {
                public_key: p.public_key,
                allowed_ips: p.allowed_ips.clone(),
                endpoint: p.endpoint,
                keepalive: p.keepalive,
            })
            .collect();
        if let Err(e) = backend.configure_routing(&all) {
            tracing::warn!("routing not applied (needs iface up): {e:#}");
        }
        tracing::info!(peers = all.len(), "mesh updated");
    }
    Ok(())
}

fn hex8(b: &[u8; 32]) -> String {
    b[..4].iter().map(|x| format!("{x:02x}")).collect()
}
