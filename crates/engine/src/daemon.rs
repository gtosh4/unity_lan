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
use crate::fw::{self, Exposed, Firewall};
use crate::keys;
use crate::netcfg::LocalNet;
use crate::resolver::ResolverHook;
use crate::shutdown::Shutdown;
use crate::wg::{self, IfaceConfig, PeerConfig, WgBackend};

pub async fn run(cfg: Config, shutdown: Shutdown) -> anyhow::Result<()> {
    // Local per-network peering opt-out (persisted; the client is the source of truth). Sent to
    // the coordinator on every register/refresh; also enforced locally so it works while the
    // coordinator is unreachable.
    let localnet = Arc::new(LocalNet::load(&cfg.state_dir, cfg.disable_new_networks));

    let token = std::sync::Arc::new(tokio::sync::RwLock::new(keys::load_token(&cfg.state_dir)));
    // This device's WG public key, shared with the control socket so interactive login binds the
    // *current* key. A logout re-keys the device; the enrollment loop below refreshes this each
    // iteration.
    let pubkey = std::sync::Arc::new(tokio::sync::RwLock::new([0u8; 32]));
    // Signalled by a `Logout` control request to break the mesh loop into its teardown + re-key path.
    let logout = std::sync::Arc::new(tokio::sync::Notify::new());

    // Optional `.unity.internal` resolver: serves our device + peers by name (empty until we mesh).
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
        let f = Arc::new(Firewall::new(
            fw::default_backend(),
            cfg.iface.clone(),
            seeds,
        ));
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
    // Reflect the persisted connect/disconnect intent from the start (before the first mesh).
    control::set_connected(&status, !localnet.is_paused()).await;
    {
        let name = cfg.control_name();
        let control_group = cfg.control_group.clone();
        let ctx = control::Ctx {
            status: status.clone(),
            coordinator: cfg.coordinator.clone(),
            token: token.clone(),
            fw: fw.clone(),
            localnet: localnet.clone(),
            pubkey: pubkey.clone(),
            oauth_redirect: cfg.oauth_redirect.clone(),
            logout: logout.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = control::serve(&name, control_group, ctx).await {
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

    // Ciphertext relay (§7.2, M5.4): if opted in *and* directly dialable, run an embedded TURN
    // server and advertise it so co-members whose hole punch fails can relay WG ciphertext through
    // us. A NAT'd device (no endpoint) can't serve as a relay, so it's skipped. The server + secret
    // outlive an enrollment cycle (a logout/login doesn't tear them down); a spawned task stops it
    // on shutdown (its internal tasks keep it running without us holding the handle).
    let relay_report = match (cfg.relay, endpoint) {
        (true, Some(ep)) => {
            let secret = keys::load_or_create_relay_secret(&cfg.state_dir)?;
            let relay_addr = SocketAddr::new(ep.ip(), cfg.relay_port);
            let bind = SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), cfg.relay_port);
            match crate::relay::RelayServer::start(bind, ep.ip(), secret.clone()).await {
                Ok(server) => {
                    let sd = shutdown.clone();
                    tokio::spawn(async move {
                        sd.wait().await;
                        if let Err(e) = server.stop().await {
                            tracing::warn!("relay: TURN server stop on shutdown: {e:#}");
                        }
                    });
                    coord::RelayReport {
                        capable: true,
                        addr: Some(relay_addr),
                        secret: Some(secret),
                        need_relay: Vec::new(),
                    }
                }
                Err(e) => {
                    tracing::warn!("relay: TURN server failed to start ({e:#}); not advertising");
                    coord::RelayReport::default()
                }
            }
        }
        (true, None) => {
            tracing::info!("relay: enabled but not dialable (no endpoint); not advertising");
            coord::RelayReport::default()
        }
        (false, _) => coord::RelayReport::default(),
    };

    // Enrollment lifecycle. Runs once normally; a `Logout` tears the mesh down and loops back here
    // to re-key and wait for the next login. Setup above (dns, firewall, control socket, endpoint)
    // is done once and outlives every enrollment.
    'lifecycle: loop {
        // Fresh key per enrollment: a logout deletes `wg.key`, so this regenerates one (steady state
        // just reloads the existing key). Publish it so an interactive login binds the current key.
        let (wg_priv, wg_pub) = keys::load_or_generate_keypair(&cfg.state_dir)?;
        *pubkey.write().await = wg_pub;

        // Register, waiting (serving control) until we're logged in and hold a network to mesh.
        let Some((resp, device)) = register_until_ready(
            &cfg,
            endpoint,
            wg_pub,
            &localnet,
            &status,
            &fw,
            &shutdown,
            &relay_report,
        )
        .await?
        else {
            return Ok(()); // interrupted before login
        };
        keys::pin_anchor(&cfg.state_dir, &resp.coord_pubkey, &resp.rotation_chain)?;
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
        let mut backend = wg::new_backend(&cfg.iface)?;
        backend.up(&IfaceConfig {
            private_key: wg_priv,
            addresses: vec![(device.wg_ip, 32)],
            listen_port: cfg.listen_port,
        })?;
        tracing::info!(iface = %cfg.iface, port = cfg.listen_port, "interface up");

        // Point the OS resolver at our `.unity.internal` server on this link (best-effort). Reverted on
        // clean shutdown; also clears with the link if we exit uncleanly.
        let resolver: Option<Box<dyn ResolverHook>> = match (cfg.resolver_hook, cfg.dns_bind) {
            (true, Some(bind)) => match crate::resolver::platform_hook() {
                Some(hook) => {
                    if let Err(e) = hook.install(&cfg.iface, bind) {
                        tracing::warn!(
                            "resolver hook (set `resolver_hook = false` to disable): {e:#}"
                        );
                    }
                    Some(hook)
                }
                None => None, // no OS resolver backend on this platform yet (e.g. macOS /etc/resolver)
            },
            _ => None,
        };

        // Apply the initial snapshot; then keep the last one so a local network toggle can re-mesh
        // immediately (filtering by the opt-out set) even while the coordinator is unreachable.
        let mut peers: HashMap<[u8; 32], PeerConfig> = HashMap::new();
        let mut last_seeds = coord::verified_seeds(&resp)?;
        let mut last_device = Some(device);
        // Whether the last coordinator refresh succeeded. We just registered, so start `true`; a failed
        // refresh flips it (the mesh keeps running from cache), a successful one flips it back.
        let mut coord_online = true;
        apply_state(
            backend.as_ref(),
            &fw,
            &zone,
            &status,
            &localnet,
            &last_device,
            &last_seeds,
            &mut peers,
            coord_online,
        )
        .await?;

        // Long-poll loop: each /refresh blocks at the coordinator until membership changes or the
        // hold (~TTL/2) elapses, then returns a fresh snapshot + new version. Near-zero idle traffic;
        // a co-member joining wakes this call at once. `since` echoes the last version we applied.
        let mut since = Some(resp.version);
        // The last observed-endpoint set we reported to the coordinator (sorted for stable compare).
        let mut last_reported: Vec<common::api::ObservedEndpoint> = Vec::new();
        // When we first started punching each peer (endpoint from `punch`), for the reach classifier.
        let mut punch_since: HashMap<[u8; 32], std::time::Instant> = HashMap::new();
        loop {
            // Read live per-peer WG stats. Report where WG sees each peer sending from (its reflexive
            // NAT mapping) so the coordinator can hand two NAT'd co-members each other's address to
            // hole-punch. The reflexive appears only after a peer handshakes — later than a long-poll
            // hold would return — so we re-read every couple seconds and report on change (a cheap
            // local uapi read; no network traffic unless the set actually changed). A failed read
            // (boringtun's uapi is racy under load) is treated as "unchanged" so it never flaps.
            let stats = backend.peer_stats().ok();
            let observed = match &stats {
                Some(map) => {
                    let mut v: Vec<common::api::ObservedEndpoint> = map
                        .iter()
                        .filter_map(|(pk, s)| {
                            s.endpoint.map(|endpoint| common::api::ObservedEndpoint {
                                pubkey: *pk,
                                endpoint,
                            })
                        })
                        .collect();
                    v.sort_by_key(|o| o.pubkey);
                    v
                }
                None => last_reported.clone(),
            };

            // Reachability diagnostics (§7.2): classify each peer and overlay it onto the status so a
            // stuck hole punch surfaces. A peer is "punched" if its only endpoint is a punch target
            // (no dialable endpoint); "connected" if WG has a recent handshake for it.
            let now = std::time::Instant::now();
            let mut reach: HashMap<std::net::Ipv4Addr, common::control::PeerReach> = HashMap::new();
            for (pk, cfg) in &peers {
                let punched = last_seeds
                    .iter()
                    .any(|s| s.pubkey == *pk && s.endpoint.is_none() && s.punch.is_some());
                if punched {
                    punch_since.entry(*pk).or_insert(now);
                } else {
                    punch_since.remove(pk);
                }
                let connected = stats
                    .as_ref()
                    .and_then(|m| m.get(pk))
                    .and_then(|s| s.last_handshake)
                    .is_some_and(|t| t.elapsed().map_or(true, |d| d < Duration::from_secs(180)));
                let age = punch_since
                    .get(pk)
                    .map_or(0, |t| now.duration_since(*t).as_secs());
                let r = common::control::classify_reach(punched, connected, age);
                if let Some((ip, _)) = cfg.allowed_ips.first() {
                    reach.insert(*ip, r);
                }
            }
            control::set_reach(&status, &reach).await;

            let changed = observed != last_reported;
            if changed {
                tracing::info!(
                    eps = ?observed.iter().map(|o| o.endpoint).collect::<Vec<_>>(),
                    "reflexive: reporting observed endpoints to coordinator"
                );
            }
            // Report immediately (no hold) when our view changed; else hold for membership.
            let poll_since = if changed { None } else { since };
            let refreshed = tokio::select! {
                // Clean shutdown: tear down the firewall so no stale default-deny rules linger.
                _ = shutdown.wait() => {
                    if let Some(fw) = &fw {
                        if let Err(e) = fw.reset() {
                            tracing::warn!("firewall reset on shutdown: {e:#}");
                        }
                    }
                    if let Some(r) = &resolver {
                        if let Err(e) = r.revert(&cfg.iface) {
                            tracing::warn!("resolver revert on shutdown: {e:#}");
                        }
                    }
                    tracing::info!("shutting down");
                    return Ok(());
                }
                // Logout: break out to the teardown path below, which un-enrolls, drops the mesh, and
                // loops back to `'lifecycle` to re-key and await the next login.
                _ = logout.notified() => break,
                // Local network toggle (also mesh connect/disconnect): re-mesh from the last snapshot at
                // once (works offline), then loop round to re-refresh so the coordinator picks up the
                // new opt-out / paused state.
                _ = localnet.wake.notified() => {
                    apply_state(
                        backend.as_ref(), &fw, &zone, &status, &localnet, &last_device, &last_seeds, &mut peers, coord_online,
                    ).await?;
                    continue;
                }
                // Re-check peer endpoints every couple seconds (a freshly-learned reflexive gets
                // reported on the next loop). Only while unchanged — a change goes straight to a report.
                _ = tokio::time::sleep(Duration::from_secs(2)), if !changed => {
                    continue;
                }
                r = coord::refresh(
                    &cfg.coordinator,
                    wg_pub,
                    cfg.device_name(),
                    endpoint,
                    cfg.enrollment_key.clone(),
                    poll_since,
                    localnet.as_refs(),
                    observed.clone(),
                    localnet.is_paused(),
                    relay_report.clone(),
                ) => r,
            };
            match refreshed {
                Ok((resp, dev)) => {
                    coord_online = true;
                    since = Some(resp.version);
                    last_reported = observed; // the coordinator now has this reflexive set
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
                                backend.as_ref(),
                                &fw,
                                &zone,
                                &status,
                                &localnet,
                                &last_device,
                                &last_seeds,
                                &mut peers,
                                coord_online,
                            )
                            .await?;
                        }
                        Err(e) => tracing::warn!("bad seeds: {e:#}"),
                    }
                }
                // Coordinator unreachable: back off (don't hammer), keep the existing mesh alive but
                // flag it so the GUI shows the coordinator as offline.
                Err(e) => {
                    tracing::warn!("refresh failed: {e:#}");
                    coord_online = false;
                    control::set_coord_online(&status, false).await;
                    tokio::time::sleep(Duration::from_secs(cfg.refresh_secs.max(1))).await;
                }
            }
        }

        // Reached only when the mesh loop broke on a logout signal.
        tracing::info!("logout: un-enrolling and tearing down the mesh");
        // Un-enroll this device at the coordinator (best-effort — the re-key below already prevents any
        // reuse of the old identity, so a failure here just leaves an orphaned device row to expire).
        if let Some(tok) = token.read().await.clone() {
            let op = common::api::ManageOp::Remove {
                device_name: cfg.device_name(),
            };
            if let Err(e) = coord::manage(&cfg.coordinator, tok, op).await {
                tracing::warn!("logout: coordinator un-enroll failed (continuing): {e:#}");
            }
        }
        // Drop every peer and destroy the interface; a fresh one comes up on the next login.
        if let Err(e) = backend.down() {
            tracing::warn!("logout: interface down: {e:#}");
        }
        if let Some(fw) = &fw {
            if let Err(e) = fw.update_peers(crate::fw::PeersByNet::new()) {
                tracing::warn!("logout: clearing firewall peers: {e:#}");
            }
        }
        if let Some(r) = &resolver {
            if let Err(e) = r.revert(&cfg.iface) {
                tracing::warn!("logout: resolver revert: {e:#}");
            }
        }
        // Discard the local key + token so the next register re-keys and reports not-logged-in.
        keys::clear_enrollment(&cfg.state_dir)?;
        *token.write().await = None;
        control::set_logged_out(&status).await;
        continue 'lifecycle;
    }
}

/// Filter the snapshot through the local opt-out set, then push it to DNS, the control socket, the
/// firewall, and the WG backend. A peer is kept if it shares at least one *enabled* network with
/// us; peers whose every shared network is locally disabled are dropped (both here and — once the
/// opt-out reaches the coordinator — from its seed list too).
// Cohesive per-refresh state application; splitting the args adds no clarity.
#[allow(clippy::too_many_arguments)]
async fn apply_state(
    backend: &dyn WgBackend,
    fw: &Option<Arc<Firewall>>,
    zone: &dns::Zone,
    status: &control::Shared,
    localnet: &LocalNet,
    device: &Option<SelfDevice>,
    seeds: &[SeedPeer],
    peers: &mut HashMap<[u8; 32], PeerConfig>,
    coord_online: bool,
) -> anyhow::Result<()> {
    // Fold any newly-discovered networks into the opt-out set per the local policy (secure default:
    // disable on discovery) before snapshotting, so a brand-new network doesn't peer this cycle. The
    // opt-out rides to the coordinator on the next refresh.
    if let Some(dev) = device {
        let present: Vec<(u64, u64)> = dev
            .networks_status
            .iter()
            .map(|n| (n.guild_id, n.role_id))
            .collect();
        if let Err(e) = localnet.reconcile_new(&present) {
            tracing::warn!("reconciling new networks: {e:#}");
        }
    }
    let disabled = localnet.snapshot();
    let paused = localnet.is_paused();
    if let Some(dev) = device {
        tracing::debug!(
            paused,
            coord_online,
            networks = ?dev
                .networks_status
                .iter()
                .map(|n| format!("{}({}/{})={}", n.name, n.guild_id, n.role_id, n.enabled))
                .collect::<Vec<_>>(),
            disabled = ?disabled,
            "apply_state: networks from coordinator + local opt-out set"
        );
    }
    // Disconnected: bring the interface administratively down (no traffic, /32 route inactive) *and*
    // drop every peer — no mesh. Reconnect brings the link back up. The device, its uapi socket and
    // the resolver config all persist across the toggle, so this is idempotent and needs no teardown.
    // The coordinator withdraws our presence (via the `paused` flag on refresh), so co-members prune us.
    backend.set_link_up(!paused)?;
    let active: Vec<SeedPeer> = match device {
        Some(dev) if !paused => filter_active(seeds, &disabled, &dev.networks_status),
        _ => Vec::new(),
    };
    if let Some(dev) = device {
        dns::update(zone, dev, &active).await;
        control::update(
            status,
            dev,
            &active,
            &disabled,
            !paused,
            localnet.disable_new(),
            coord_online,
        )
        .await;
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
                || s.networks
                    .iter()
                    .any(|name| match name_to_id.get(name.as_str()) {
                        Some(id) => !disabled.contains(id),
                        None => true,
                    })
        })
        .cloned()
        .collect()
}

/// Register in a loop, keeping the control socket alive, until we're logged in *and* hold a
/// network to mesh. Sets `needs_login` so a frontend can start OAuth; returns `None` on shutdown.
#[allow(clippy::too_many_arguments)]
async fn register_until_ready(
    cfg: &Config,
    endpoint: Option<SocketAddr>,
    wg_pub: [u8; 32],
    localnet: &LocalNet,
    status: &control::Shared,
    fw: &Option<Arc<Firewall>>,
    shutdown: &Shutdown,
    relay: &coord::RelayReport,
) -> anyhow::Result<Option<(common::api::RegisterResp, SelfDevice)>> {
    // Our persisted device token as of startup. If we re-keyed (new wg.key) since it was issued,
    // it still names the old pubkey → the coordinator retires that stale identity on our first
    // register. No-op when it names our current key (the steady case) or once the old row is gone.
    let supersede = keys::load_token(&cfg.state_dir);
    loop {
        let attempt = tokio::select! {
            _ = shutdown.wait() => {
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
                supersede.clone(),
                localnet.is_paused(),
                relay.clone(),
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
    // pubkey -> (allowed /32s, endpoint); a named alias for one local adds noise.
    #[allow(clippy::type_complexity)]
    let mut desired: HashMap<[u8; 32], (Vec<(Ipv4Addr, u8)>, Option<SocketAddr>)> = HashMap::new();
    for s in seeds {
        // A directly dialable endpoint wins; otherwise fall back to the punch target (reflexive) so
        // WG handshakes toward it — the coordinator only sets `punch` when both sides will punch.
        if s.endpoint.is_none() {
            if let Some(p) = s.punch {
                tracing::info!(peer = %hex8(&s.pubkey), punch = %p, "hole-punch: dialing peer reflexive");
            }
        }
        let ep = s.endpoint.or(s.punch);
        let e = desired.entry(s.pubkey).or_insert_with(|| (Vec::new(), ep));
        e.0.push((s.ip, 32));
        if e.1.is_none() {
            e.1 = ep;
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
