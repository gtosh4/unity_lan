//! Mesh daemon: register → bring up the WG interface with our `/32`s → peer the seeds →
//! refresh periodically, adding newly-seen co-members. Seed-based meshing (design.md §5);
//! P2P gossip layers on top later.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use crate::config::Config;
use crate::control;
use crate::coord::{self, SeedPeer};
use crate::dns;
use crate::fw::{Exposed, Firewall, NftBackend};
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

    // Persist the device token (for control mutations) and keep it live for the control socket.
    let token = std::sync::Arc::new(tokio::sync::RwLock::new(keys::load_token(&cfg.state_dir)));
    if let Some(tok) = &resp.device_token {
        keys::save_token(&cfg.state_dir, tok)?;
        *token.write().await = Some(tok.clone());
    }

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

    // Host firewall: default-deny inbound on the wg iface, plus any config-seeded exposes
    // (design.md §M7). On by default; a grant to peer still needs an explicit `expose` per port.
    let fw = if cfg.firewall {
        let seeds: Vec<Exposed> = cfg
            .expose
            .iter()
            .map(|e| Exposed {
                proto: match e.proto.to_ascii_lowercase().as_str() {
                    "udp" => common::control::Proto::Udp,
                    _ => common::control::Proto::Tcp,
                },
                port: e.port,
            })
            .collect();
        let f = Arc::new(Firewall::new(Box::new(NftBackend), cfg.iface.clone(), seeds));
        f.init()
            .context("installing firewall (default-deny); set `firewall = false` to disable")?;
        tracing::info!(iface = %cfg.iface, "firewall: default-deny inbound + established/icmp/exposed");
        Some(f)
    } else {
        None
    };

    // Control socket: status + device-management + expose for CLI/GUI frontends.
    let status = control::shared();
    {
        let path = cfg.control_socket_path();
        let ctx = control::Ctx {
            status: status.clone(),
            coordinator: cfg.coordinator.clone(),
            token: token.clone(),
            fw: fw.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = control::serve(&path, ctx).await {
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

    // Long-poll loop: each /refresh blocks at the coordinator until membership changes or the
    // hold (~TTL/2) elapses, then returns a fresh snapshot + new version. Near-zero idle traffic;
    // a co-member joining wakes this call at once. `since` echoes the last version we applied.
    let mut since = Some(resp.version);
    loop {
        let refreshed = tokio::select! {
            // Clean shutdown: tear down the firewall so no stale default-deny rules linger.
            _ = tokio::signal::ctrl_c() => {
                if let Some(fw) = &fw {
                    if let Err(e) = fw.reset() {
                        tracing::warn!("firewall reset on shutdown: {e:#}");
                    }
                }
                tracing::info!("shutting down");
                return Ok(());
            }
            r = coord::refresh(
                &cfg.coordinator,
                wg_pub,
                cfg.device_name(),
                cfg.endpoint,
                cfg.enrollment_key.clone(),
                since,
            ) => r,
        };
        match refreshed {
            Ok((resp, dev)) => {
                since = Some(resp.version);
                match coord::verified_seeds(&resp) {
                    Ok(seeds) => {
                        match &dev {
                            Some(dev) => {
                                dns::update(&zone, dev, &seeds).await;
                                control::update(&status, dev, &seeds).await;
                            }
                            // No grant: we hold no networks anymore (role revoked). Seeds are empty
                            // → apply_seeds prunes every peer, isolating us until access returns.
                            None => tracing::warn!("no grant — access revoked; dropping all peers"),
                        }
                        apply_seeds(&backend, seeds, &mut peers)?;
                    }
                    Err(e) => tracing::warn!("bad seeds: {e:#}"),
                }
            }
            // Coordinator unreachable: back off (don't hammer), keep the existing mesh alive.
            Err(e) => {
                tracing::warn!("refresh failed: {e:#}");
                tokio::time::sleep(Duration::from_secs(cfg.refresh_secs.max(1))).await;
            }
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

    // Prune peers no longer in the seed set: a co-member who lost the role (revoked / left) drops
    // out of the coordinator's presence, so its next-absent refresh here means "remove this peer".
    let stale: Vec<[u8; 32]> = peers
        .keys()
        .filter(|pk| !desired.contains_key(*pk))
        .copied()
        .collect();
    for pubkey in stale {
        backend.remove_peer(&pubkey)?;
        peers.remove(&pubkey);
        tracing::info!(peer = %hex8(&pubkey), "peer removed (revoked or left)");
        changed = true;
    }

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
