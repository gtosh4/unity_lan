//! Mesh daemon: register → bring up the WG interface with our `/32`s → peer the seeds →
//! refresh periodically, adding newly-seen co-members. Seed-based meshing (design.md §5);
//! P2P gossip layers on top later.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;

use crate::config::Config;
use crate::control;
use crate::coord::{self, SeedPeer, SelfDevice};
use crate::dns;
use crate::fw::{Exposed, Firewall, NftBackend};
use crate::keys;
use crate::netcfg::LocalNet;
use crate::wg::{IfaceConfig, PeerConfig, UserspaceBackend, WgBackend};

pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let (wg_priv, wg_pub) = keys::load_or_generate_keypair(&cfg.state_dir)?;

    // Local per-network peering opt-out (persisted; the client is the source of truth). Sent to
    // the coordinator on every register/refresh; also enforced locally so it works while the
    // coordinator is unreachable.
    let localnet = Arc::new(LocalNet::load(&cfg.state_dir));

    let token = std::sync::Arc::new(tokio::sync::RwLock::new(keys::load_token(&cfg.state_dir)));

    // Optional `.internal` resolver: serves our device + peers by name (empty until we mesh).
    let zone = dns::empty_zone();
    if let Some(bind) = cfg.dns_bind {
        let z = zone.clone();
        tokio::spawn(async move {
            if let Err(e) = dns::serve(bind, z).await {
                tracing::error!("dns resolver ended: {e:#}");
            }
        });
    }

    // Host firewall, built *before* we register so the control socket can serve `expose` from the
    // start and the rules are in place the instant the interface appears (nft matches by iface
    // name, which loads fine before the iface exists). §M7.
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
                net: None,
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

    // Control socket up first — so a frontend (GUI) can drive interactive login before we're
    // enrolled. status starts empty; `needs_login` is toggled by the register loop below.
    let status = control::shared();
    {
        let path = cfg.control_socket_path();
        let ctx = control::Ctx {
            status: status.clone(),
            coordinator: cfg.coordinator.clone(),
            token: token.clone(),
            fw: fw.clone(),
            localnet: localnet.clone(),
            pubkey: wg_pub,
        };
        tokio::spawn(async move {
            if let Err(e) = control::serve(&path, ctx).await {
                tracing::error!("control socket ended: {e:#}");
            }
        });
    }

    // Endpoint we advertise to peers: an explicit config value wins (manual forward / known
    // public addr); otherwise try UPnP-IGD to map our port; otherwise none (rely on being dialed).
    let endpoint = match cfg.endpoint {
        Some(e) => Some(e),
        None if cfg.upnp => match crate::nat::map_port(cfg.listen_port).await {
            Ok(ep) => {
                tracing::info!(endpoint = %ep, "UPnP: mapped external endpoint");
                Some(ep)
            }
            Err(e) => {
                tracing::info!("UPnP unavailable ({e:#}); advertising no endpoint");
                None
            }
        },
        None => None,
    };

    // Register, waiting (serving control) until we're logged in and hold a network to mesh.
    let Some((resp, device)) =
        register_until_ready(&cfg, endpoint, wg_pub, &localnet, &status, &fw).await?
    else {
        return Ok(()); // interrupted before login
    };
    keys::pin_anchor(&cfg.state_dir, &resp.coord_pubkey)?;
    if let Some(tok) = &resp.device_token {
        keys::save_token(&cfg.state_dir, tok)?;
        *token.write().await = Some(tok.clone());
    }
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

    // Apply the initial snapshot; then keep the last one so a local network toggle can re-mesh
    // immediately (filtering by the opt-out set) even while the coordinator is unreachable.
    let mut peers: HashMap<[u8; 32], PeerConfig> = HashMap::new();
    let mut last_seeds = coord::verified_seeds(&resp)?;
    let mut last_device = Some(device);
    apply_state(
        &backend, &fw, &zone, &status, &localnet, &last_device, &last_seeds, &mut peers,
    )
    .await?;

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
            // Local network toggle: re-mesh from the last snapshot at once (works offline), then
            // loop round to re-refresh so the coordinator picks up the new opt-out set.
            _ = localnet.wake.notified() => {
                apply_state(
                    &backend, &fw, &zone, &status, &localnet, &last_device, &last_seeds, &mut peers,
                ).await?;
                continue;
            }
            r = coord::refresh(
                &cfg.coordinator,
                wg_pub,
                cfg.device_name(),
                endpoint,
                cfg.enrollment_key.clone(),
                since,
                localnet.as_refs(),
            ) => r,
        };
        match refreshed {
            Ok((resp, dev)) => {
                since = Some(resp.version);
                match coord::verified_seeds(&resp) {
                    Ok(seeds) => {
                        last_seeds = seeds;
                        // A grant of `None` means we hold no networks (role revoked): keep the last
                        // device for name context, but the empty seed set prunes every peer.
                        if dev.is_some() {
                            last_device = dev;
                        } else {
                            tracing::warn!("no grant — access revoked; dropping all peers");
                        }
                        apply_state(
                            &backend, &fw, &zone, &status, &localnet, &last_device, &last_seeds,
                            &mut peers,
                        )
                        .await?;
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

/// Filter the snapshot through the local opt-out set, then push it to DNS, the control socket, the
/// firewall, and the WG backend. A peer is kept if it shares at least one *enabled* network with
/// us; peers whose every shared network is locally disabled are dropped (both here and — once the
/// opt-out reaches the coordinator — from its seed list too).
async fn apply_state(
    backend: &dyn WgBackend,
    fw: &Option<Arc<Firewall>>,
    zone: &dns::Zone,
    status: &control::Shared,
    localnet: &LocalNet,
    device: &Option<SelfDevice>,
    seeds: &[SeedPeer],
    peers: &mut HashMap<[u8; 32], PeerConfig>,
) -> anyhow::Result<()> {
    let disabled = localnet.snapshot();
    let active: Vec<SeedPeer> = match device {
        Some(dev) => filter_active(seeds, &disabled, &dev.networks_status),
        None => Vec::new(),
    };
    if let Some(dev) = device {
        dns::update(zone, dev, &active).await;
        control::update(status, dev, &active, &disabled).await;
    }
    if let Some(fw) = fw {
        fw.update_peers(peers_by_net(&active))?;
    }
    apply_seeds(backend, active, peers)?;
    Ok(())
}

/// Keep peers that share at least one network we haven't locally disabled. Shared networks arrive
/// as names; we resolve them to (guild, role) via our own `networks_status` to compare against the
/// opt-out set. A peer with no known shared network (older coordinator) is kept.
fn filter_active(
    seeds: &[SeedPeer],
    disabled: &HashSet<(u64, u64)>,
    networks_status: &[common::api::NetworkStatus],
) -> Vec<SeedPeer> {
    let name_to_id: HashMap<&str, (u64, u64)> = networks_status
        .iter()
        .map(|n| (n.name.as_str(), (n.guild_id, n.role_id)))
        .collect();
    seeds
        .iter()
        .filter(|s| {
            s.networks.is_empty()
                || s.networks.iter().any(|name| match name_to_id.get(name.as_str()) {
                    Some(id) => !disabled.contains(id),
                    None => true,
                })
        })
        .cloned()
        .collect()
}

/// Register in a loop, keeping the control socket alive, until we're logged in *and* hold a
/// network to mesh. Sets `needs_login` so a frontend can start OAuth; returns `None` on ctrl_c.
async fn register_until_ready(
    cfg: &Config,
    endpoint: Option<SocketAddr>,
    wg_pub: [u8; 32],
    localnet: &LocalNet,
    status: &control::Shared,
    fw: &Option<Arc<Firewall>>,
) -> anyhow::Result<Option<(common::api::RegisterResp, SelfDevice)>> {
    loop {
        let attempt = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if let Some(fw) = fw {
                    if let Err(e) = fw.reset() { tracing::warn!("firewall reset on shutdown: {e:#}"); }
                }
                tracing::info!("shutting down");
                return Ok(None);
            }
            r = coord::register(
                &cfg.coordinator,
                wg_pub,
                cfg.device_name(),
                endpoint,
                cfg.enrollment_key.clone(),
                localnet.as_refs(),
            ) => r,
        };
        match attempt {
            Ok((resp, Some(dev))) => {
                control::set_needs_login(status, false).await;
                return Ok(Some((resp, dev)));
            }
            // Enrolled but no networks yet — not a login problem; wait for a role.
            Ok((_resp, None)) => {
                control::set_needs_login(status, false).await;
                tracing::info!("registered but hold no networks yet; waiting for a role");
            }
            Err(e) => {
                // A 401 means we're not logged in; flag it so a frontend offers login. Other
                // errors (coordinator down) are transient — just retry without the flag.
                let msg = format!("{e:#}");
                let needs_login = msg.contains("not enrolled") || msg.contains("log in");
                control::set_needs_login(status, needs_login).await;
                if needs_login {
                    tracing::info!("not logged in — waiting for interactive login");
                } else {
                    tracing::warn!("register failed (retrying): {e:#}");
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(cfg.refresh_secs.max(2))).await;
    }
}

/// Group seed peer IPs by shared-network name → the source sets for `--net`-scoped exposes.
fn peers_by_net(seeds: &[SeedPeer]) -> crate::fw::PeersByNet {
    let mut map: crate::fw::PeersByNet = HashMap::new();
    for s in seeds {
        for n in &s.networks {
            map.entry(n.clone()).or_default().push(s.ip);
        }
    }
    map
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
