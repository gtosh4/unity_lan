//! Mesh daemon: register → bring up the WG interface with our `/32`s → peer the seeds →
//! refresh periodically, adding newly-seen co-members. Seed-based meshing (design.md §5), with the
//! P2P peer-direct gossip refresh layered on top (on by default).

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
use crate::ping;
use crate::resolver::ResolverHook;
use crate::shutdown::Shutdown;
use crate::util::hex8;
use crate::wg::{self, IfaceConfig, PeerConfig, WgBackend};

/// A peer counts as reachable if its last WireGuard handshake is younger than this. It sits well
/// above the 25s keepalive, so a live tunnel always refreshes inside the window; a peer that goes
/// this long without a handshake is treated as down (and drives relay/ICE fallback + status).
const HANDSHAKE_FRESH: Duration = Duration::from_secs(180);

/// The `.unity.internal` resolver always listens on port 53 of this device's own mesh IP. Fixed (not
/// configurable): `:53` is what Windows NRPT forwards to, and own-IP keeps it free on every platform,
/// so there's nothing to tune. The `dns` config flag only toggles the resolver on/off.
const DNS_PORT: u16 = 53;

/// Peer-direct attestation refresh (`docs/gossip-refresh.md`, stage 2): start pulling a held peer's
/// fresh attestation once it's within this of expiry, renewing a live peer's credential before it
/// lapses. Set to the long-poll interval so a coordinator-up client still gets a peer-direct attempt
/// each cycle before Option A would fetch a full from the coordinator (the fallback).
const P2P_REFRESH_MARGIN: u64 = common::LONGPOLL_HOLD_SECS;
/// How long to wait on a peer-direct pull before giving up on that peer (the coordinator covers it).
const P2P_PULL_TIMEOUT: Duration = Duration::from_secs(2);
/// Last-ditch margin: only when a held peer's attestation is within this of expiry do we concede and
/// force a **full** coordinator refresh (empty `held`, Option A). Kept well below `P2P_REFRESH_MARGIN`
/// so peer-direct owns nearly the whole pre-expiry window — the coordinator only re-sends attestations
/// the mesh genuinely couldn't refresh peer-to-peer (peer offline/revoked for ~13 min). The forced
/// full is issued as a *completing* poll (returns at once), so this small margin still leaves ample
/// slack for the round-trip, unlike an empty-`held` poll that would otherwise hold out the long-poll.
const COORD_FULL_MARGIN: u64 = 120;

/// Retry interval after the coordinator refuses us on wire protocol version. Deliberately far longer
/// than `refresh_secs`: the refusal is a version gap, not a blip, so it clears only when an operator
/// updates one side. We still retry — an update can land at any time, and a coordinator rollback
/// would restore service — but at a rate that doesn't hammer a coordinator that already said no.
const PROTO_MISMATCH_BACKOFF: Duration = Duration::from_secs(300);

/// How often the mesh loop re-reads **local** WG stats to notice a freshly-learned reflexive endpoint
/// (one only appears after a handshake — later than a long-poll hold would return). Local only: it
/// never cancels the held `/refresh`, so idle clients still park for the full hold.
const STATS_RECHECK: Duration = Duration::from_secs(2);

/// Grace before a bootstrap-stuck peer (unpunchable + unconnected) escalates to ICE. Shorter than the
/// classifier's Punching→Unreachable grace because there is nothing to wait for — no observer will
/// ever report a reflexive, so ICE's own STUN is the only way forward and delaying it just stalls.
const BOOTSTRAP_STUCK_SECS: u64 = 15;

/// Per-peer connection bookkeeping carried across mesh-loop iterations, folding the three parallel
/// maps (`attempt_since`, `bootstrap_since`, last reported reach) that each keyed a peer's pubkey and
/// were advanced together every recheck. [`PeerConn::step`] runs the whole per-peer transition.
#[derive(Default)]
struct PeerConn {
    /// When the peer last had *no* fresh handshake — armed while unconnected, cleared on connect. Its
    /// age is what the reach classifier grades Punching→Unreachable. A dialable endpoint that never
    /// completes (same-NAT peers behind a router that won't hairpin) ages out this way too, or nothing
    /// would ever escalate it to ICE.
    attempt_since: Option<std::time::Instant>,
    /// When the peer first became *unpunchable* (no endpoint, no reflexive → no punch target) and
    /// still unconnected — the bootstrap case. Armed only then, cleared otherwise; its age gates ICE.
    bootstrap_since: Option<std::time::Instant>,
    /// Last (up, reach) reported, so `step` can flag the edge for logging: the recompute is otherwise
    /// silent and a flap (up↔down / Direct↔Unreachable) leaves no trace but a `ctl status` poll.
    last: Option<(bool, common::control::PeerReach)>,
}

/// One iteration's outcome for a peer, returned by [`PeerConn::step`].
struct PeerStep {
    /// This iteration's classified reachability (relay/ICE overrides applied).
    reach: common::control::PeerReach,
    /// `Some((was_up, was_reach))` when the (up, reach) pair changed — the caller logs the edge.
    flipped: Option<(bool, common::control::PeerReach)>,
    /// Whether the bootstrap timer has aged past [`BOOTSTRAP_STUCK_SECS`] (drives ICE escalation).
    bootstrap_stuck: bool,
}

impl PeerConn {
    /// Advance the FSM from this iteration's liveness: age the attempt/bootstrap timers, classify
    /// reachability (relay/ICE win over the punch classifier), and report whether the reported pair
    /// flipped since last iteration.
    fn step(
        &mut self,
        now: std::time::Instant,
        punched: bool,
        connected: bool,
        unpunchable: bool,
        relaying: bool,
        icing: bool,
    ) -> PeerStep {
        if connected {
            self.attempt_since = None;
        } else {
            self.attempt_since.get_or_insert(now);
        }
        let age = self
            .attempt_since
            .map_or(0, |t| now.duration_since(t).as_secs());
        if unpunchable && !connected {
            self.bootstrap_since.get_or_insert(now);
        } else {
            self.bootstrap_since = None;
        }
        let bootstrap_stuck = self
            .bootstrap_since
            .is_some_and(|t| now.duration_since(t).as_secs() >= BOOTSTRAP_STUCK_SECS);
        // On the userspace path a peer routed through relay/ICE reads as connected; mark it so its
        // Seed.relay/Seed.ice keep flowing (else the coordinator withdraws them and the session flaps).
        let reach = if relaying {
            common::control::PeerReach::Relayed
        } else if icing {
            common::control::PeerReach::Ice
        } else {
            common::control::classify_reach(punched, connected, age)
        };
        let flipped = match self.last.replace((connected, reach)) {
            Some((was_up, was_reach)) if was_up != connected || was_reach != reach => {
                Some((was_up, was_reach))
            }
            _ => None,
        };
        PeerStep {
            reach,
            flipped,
            bootstrap_stuck,
        }
    }
}

/// What we last reported to the coordinator and are echoing on the currently-held `/refresh`. Each
/// field has a freshly-computed counterpart every mesh-loop iteration; when [`SentReport::stale`]
/// finds any of them changed, the held long-poll is stale and must be dropped so a fresh poll carries
/// the update and returns at once (instead of the idle recheck silently sitting on old data until the
/// hold elapses). Folds the four loop-scoped `last_*` locals that were committed together on every
/// successful refresh. The echoed delta-sync version (`since`) is deliberately *not* here — it isn't
/// diffed, only echoed and advanced on completion — nor are `own_grant_stale`/`forced_full`, which
/// are derived from the seed set rather than from what we reported.
#[derive(Default)]
struct SentReport {
    /// Observed reflexive endpoints (sorted for a stable compare).
    observed: Vec<common::api::ObservedEndpoint>,
    /// Peers we asked the coordinator to relay (sorted).
    relay_need: Vec<[u8; 32]>,
    /// Relayed addresses we've allocated for peers to learn (sorted).
    relay_alloc: Vec<common::api::RelayAllocation>,
    /// Our ICE offers — candidates + creds, growing as gathering completes (sorted).
    ice_offers: Vec<common::api::IceEndpoint>,
}

impl SentReport {
    /// True if any set we'd report now differs from what the coordinator already holds — meaning the
    /// held request is stale. The inputs are already sorted at the call site, so this is a plain
    /// order-sensitive compare (the sort is what makes it stable across iterations).
    fn stale(
        &self,
        observed: &[common::api::ObservedEndpoint],
        relay_need: &[[u8; 32]],
        relay_alloc: &[common::api::RelayAllocation],
        ice_offers: &[common::api::IceEndpoint],
    ) -> bool {
        self.observed != observed
            || self.relay_need != relay_need
            || self.relay_alloc != relay_alloc
            || self.ice_offers != ice_offers
    }
}

/// The attestations carried by a coordinator response's grant (empty if it carried none) — what the
/// p2p service (`gossip`) hands co-members over the tunnel. Refreshed on every register/refresh, so
/// a delta response that renews only the grant still updates what we serve.
fn grant_attestations(resp: &common::api::RegisterResp) -> Vec<common::api::GuildAttestation> {
    resp.grant
        .as_ref()
        .map(|g| g.attestations.clone())
        .unwrap_or_default()
}

/// Reflect the coordinator's advertised version, and verify + stage a release manifest from `resp`
/// for the control socket's `ApplyUpdate`.
///
/// Called on the initial register *and* on every refresh. Register matters because a device whose
/// membership never changes — a solo install, or any idle mesh — parks its first `/refresh` for the
/// full long-poll hold (half the deployment's attestation TTL, ~15 min by default), and would
/// otherwise not learn about a published update until then. Both responses carry the manifest, so
/// there's no reason to wait for the second.
fn note_update(
    status: &control::Shared,
    resp: &common::api::RegisterResp,
    state_dir: &std::path::Path,
    pending_update: &crate::selfupdate::PendingSlot,
) {
    control::set_update_available(status, &resp.server_version);
    let staged = crate::selfupdate::stage(resp, state_dir);
    control::set_update_ready(status, staged.is_some());
    *pending_update.lock().unwrap() = staged;
}

/// How [`run`] ended, so `main`/`service` know whether to just exit, re-exec, or hand the restart to
/// the SCM.
pub enum RunOutcome {
    /// Clean shutdown (signal or logout-then-interrupted) — the caller exits.
    Stopped,
    /// A Unix auto-update swapped the binary and the daemon tore down fully; the caller re-execs
    /// this plan (same PID) so the update takes effect regardless of the supervisor.
    #[cfg(unix)]
    ReExec(crate::selfupdate::ExecPlan),
    /// A Windows file-swap update swapped the binary and the daemon tore down fully; the caller lets
    /// the SCM restart the service onto the new binary (Windows can't re-exec a service in place, and
    /// leaning on the SCM as supervisor is the intended Windows restart — see `service::run_service`).
    #[cfg(windows)]
    RestartService,
}

/// Reverse every host mutation this enrollment made — in the order that survives a SIGKILL
/// mid-teardown: withdraw presence at the coordinator, then host-global state (firewall, resolver)
/// *before* the interface, then stop the background tasks. Shared by the clean-shutdown and
/// re-exec-for-update paths: both end the daemon and must leave no live TUN fd, bound socket, or
/// stranded host state behind.
#[allow(clippy::too_many_arguments)]
async fn teardown(
    cfg: &Config,
    wg_pub: [u8; 32],
    endpoint: Option<SocketAddr>,
    localnet: &LocalNet,
    fw: &Option<Arc<Firewall>>,
    resolver: &Option<Box<dyn ResolverHook>>,
    backend: &dyn WgBackend,
    dns_task: &Option<tokio::task::JoinHandle<()>>,
    p2p_task: &Option<tokio::task::JoinHandle<()>>,
) {
    // Best-effort: tell the coordinator we're leaving so co-members prune us within seconds instead
    // of waiting out the presence reaper (~31 min). Bounded to 3s so an unreachable coordinator
    // can't stall teardown; a crash/power-loss can't send this — the reaper is the backstop.
    let withdraw = coord::refresh(
        &cfg.coordinator,
        &cfg.state_dir,
        coord::CoordReq {
            wg_pubkey: wg_pub,
            device_name: cfg.device_name(),
            endpoint,
            enrollment_key: cfg.enrollment_key.clone(),
            since: None, // no long-poll hold: return as soon as the eviction is applied
            disabled_networks: Vec::new(),
            observed: Vec::new(),
            supersede: None,
            paused: true, // paused → evict from all networks
            peer_own_devices: localnet.peer_own_devices(),
            relay: coord::RelayReport::default(),
            ice: Vec::new(),
            held: Vec::new(), // withdrawing → no held set to diff against
        },
    );
    match tokio::time::timeout(Duration::from_secs(3), withdraw).await {
        Ok(Ok(_)) => tracing::info!("withdrew presence on shutdown"),
        Ok(Err(e)) => tracing::debug!("shutdown withdraw failed: {e:#}"),
        Err(_) => tracing::debug!("shutdown withdraw timed out"),
    }
    // Revert host-global state *before* the interface. `backend.down()` can wedge inside boringtun's
    // uapi (seen in the field), and a SIGKILL runs nothing after it — stranding the firewall table,
    // the resolved routing domain, and the exemption we inserted into another product's nft chain.
    // Those outlive the process and nothing else cleans them; a leftover interface + uapi socket are
    // both recovered on the next start.
    if let Some(fw) = fw {
        if let Err(e) = fw.reset() {
            tracing::warn!("firewall reset on shutdown: {e:#}");
        }
    }
    if let Some(r) = resolver {
        if let Err(e) = r.revert(&cfg.iface) {
            tracing::warn!("resolver revert on shutdown: {e:#}");
        }
    }
    if let Err(e) = backend.down() {
        tracing::warn!("interface down on shutdown: {e:#}");
    }
    if let Some(t) = dns_task {
        t.abort();
    }
    if let Some(t) = p2p_task {
        t.abort();
    }
}

/// Build the host firewall from `cfg.expose` (default-deny + established/icmp/exposed), *before* we
/// register so the control socket can serve `expose` from the start and the rules are in place the
/// instant the interface appears (nft matches by iface name, which loads before the iface exists).
/// `None` when `firewall` is off. Runs once per process — it outlives every enrollment. §M7.
fn build_firewall(cfg: &Config) -> anyhow::Result<Option<Arc<Firewall>>> {
    if !cfg.firewall {
        return Ok(None);
    }
    let seeds: Vec<Exposed> = cfg
        .expose
        .iter()
        .map(|e| {
            Ok(Exposed {
                proto: match e.proto.to_ascii_lowercase().as_str() {
                    "udp" => common::control::Proto::Udp,
                    _ => common::control::Proto::Tcp,
                },
                port: e.port,
                scope: e.scope()?,
            })
        })
        .collect::<anyhow::Result<_>>()
        .context("reading the `expose` list")?;
    let f = Arc::new(Firewall::load(
        fw::default_backend(cfg.listen_port, cfg.beacon.then_some(cfg.beacon_port)),
        cfg.iface.clone(),
        seeds,
        &cfg.state_dir,
        cfg.tailscale_compat,
    ));
    f.init()
        .context("installing firewall (default-deny); set `firewall = false` to disable")?;
    tracing::info!(iface = %cfg.iface, "firewall: default-deny inbound + established/icmp/exposed");
    Ok(Some(f))
}

/// The endpoint we advertise to peers: an explicit config value wins (manual forward / known public
/// addr); otherwise try UPnP-IGD to map our port; otherwise none (rely on being dialed).
async fn resolve_endpoint(cfg: &Config, shutdown: &Shutdown) -> Option<SocketAddr> {
    match cfg.endpoint {
        Some(e) => Some(e),
        None if cfg.upnp => match crate::nat::map_port(cfg.listen_port, shutdown.clone()).await {
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
    }
}

/// Ciphertext relay (§7.2, M5.4): if opted in *and* directly dialable, start an embedded TURN server
/// and advertise it so co-members whose hole punch fails can relay WG ciphertext through us. A NAT'd
/// device (no endpoint) can't serve as a relay, so it's skipped. The server + secret outlive an
/// enrollment cycle (a logout/login doesn't tear them down); a spawned task stops it on shutdown (its
/// internal tasks keep it running without us holding the handle).
async fn start_relay(
    cfg: &Config,
    endpoint: Option<SocketAddr>,
    shutdown: &Shutdown,
) -> anyhow::Result<coord::RelayReport> {
    let report = match (cfg.relay, endpoint) {
        (true, Some(ep)) => {
            let secret = keys::load_or_create_relay_secret(&cfg.state_dir)?;
            let relay_addr = SocketAddr::new(ep.ip(), cfg.relay_port);
            let bind = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), cfg.relay_port);
            match crate::relay::RelayServer::start(
                bind,
                ep.ip(),
                secret.clone(),
                cfg.relay_max_allocations,
                cfg.relay_allow_private_dst,
            )
            .await
            {
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
                        allocated: Vec::new(),
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
    Ok(report)
}

pub async fn run(cfg: Config, shutdown: Shutdown) -> anyhow::Result<RunOutcome> {
    // Reconcile any pending-update breadcrumb: if a prior update restarted us onto the new version,
    // log success and clear it; if we came back up on the old version, warn that the update didn't
    // take. A no-op on an ordinary startup (no marker).
    crate::selfupdate::reconcile_update_marker(&cfg.state_dir);

    // Local per-network peering opt-out (persisted; the client is the source of truth). Sent to
    // the coordinator on every register/refresh; also enforced locally so it works while the
    // coordinator is unreachable.
    let localnet = Arc::new(LocalNet::load(
        &cfg.state_dir,
        cfg.disable_new_networks,
        cfg.peer_own_devices,
    ));

    let token = Arc::new(tokio::sync::RwLock::new(keys::load_token(&cfg.state_dir)));
    // This device's WG public key, shared with the control socket so interactive login binds the
    // *current* key. A logout re-keys the device; the enrollment loop below refreshes this each
    // iteration.
    let pubkey = Arc::new(tokio::sync::RwLock::new([0u8; 32]));
    // Signalled by a `Logout` control request to break the mesh loop into its teardown + re-key path.
    let logout = Arc::new(tokio::sync::Notify::new());
    // Signalled by `ApplyUpdate` once a file-swap update has swapped the binary: the mesh loop tears
    // down fully, then re-execs the plan left in `exec_slot` (Unix) or returns `RestartService` so the
    // SCM relaunches the service (Windows). The legacy Windows MSI path exits via msiexec instead.
    let restart_for_update = Arc::new(tokio::sync::Notify::new());
    #[cfg(unix)]
    let exec_slot = crate::selfupdate::exec_slot();
    // Signalled once interactive login binds the device — wakes the enrollment loop out of its
    // `refresh_secs` backoff so the mesh comes up at once instead of on the next poll.
    let login_done = Arc::new(tokio::sync::Notify::new());

    // Optional `.unity.internal` resolver: serves our device + peers by name (empty until we mesh).
    // The server itself is bound per-enrollment inside `'lifecycle` — it listens on this device's own
    // mesh IP, which is only known after register and changes on re-key. The zone outlives enrollments.
    let zone = dns::empty_zone();

    // Host firewall (default-deny), installed before we register — see `build_firewall`.
    let fw = build_firewall(&cfg)?;

    // Control socket up first — so a frontend (GUI) can drive interactive login before we're
    // enrolled. status starts empty; `needs_login` is toggled by the register loop below.
    let status = control::shared();
    // Reflect the persisted connect/disconnect intent from the start (before the first mesh).
    control::set_connected(&status, !localnet.is_paused());
    // Verified auto-update staged on register + each refresh; consumed by control's ApplyUpdate.
    let pending_update = crate::selfupdate::pending_slot();
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
            login_done: login_done.clone(),
            state_dir: cfg.state_dir.clone(),
            pending_update: pending_update.clone(),
            restart_for_update: restart_for_update.clone(),
            #[cfg(unix)]
            exec_slot: exec_slot.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = control::serve(&name, control_group, ctx).await {
                tracing::error!("control socket ended: {e:#}");
            }
        });
    }

    // The endpoint we advertise to peers (config / UPnP / none) — see `resolve_endpoint`.
    let endpoint = resolve_endpoint(&cfg, &shutdown).await;

    // Embedded ciphertext relay (TURN), advertised only when dialable — see `start_relay`.
    let relay_report = start_relay(&cfg, endpoint, &shutdown).await?;

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
            &login_done,
        )
        .await?
        else {
            return Ok(RunOutcome::Stopped); // interrupted before login
        };
        // `register` already pinned/verified the anchor (via `coord::post`); no separate pin here.
        // The register response already carries the release manifest, so stage from it here rather
        // than waiting for the first refresh to return.
        note_update(&status, &resp, &cfg.state_dir, &pending_update);
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

        // Check the coordinator's mesh range against local interfaces once at join: an overlap with
        // the user's real LAN could shadow it. Advisory — routes come from signed attestations — so
        // we warn and surface it, we don't refuse.
        let overlap = crate::netcfg::lan_overlap_warning(device.wg_net, &cfg.iface);
        if let Some(w) = &overlap {
            tracing::warn!("{w}");
        }
        control::set_lan_overlap(&status, overlap);

        // The CGNAT exemption needs our own mesh address as well as the interface: anything we send
        // to ourselves (the resolver below is exactly that) loops back on `lo`, where a rule scoped
        // to the mesh interface can't match it.
        if let Some(fw) = &fw {
            if let Err(e) = fw.set_mesh_addr(device.wg_ip) {
                tracing::warn!("firewall: recording mesh address: {e:#}");
            }
        }

        // Resolver address: this device's own mesh IP (now on the interface) + the configured port.
        // Bound here, not on loopback, so `:53` is free on every platform and Windows NRPT (port-53
        // only) can forward to it. The IP is pubkey-derived, so it changes on re-key — hence the
        // server is (re)bound per enrollment and torn down with the interface below.
        let dns_bind = cfg
            .dns
            .then(|| SocketAddr::new(device.wg_ip.into(), DNS_PORT));

        // Serve the `.unity.internal` zone on that address. Held so the logout/shutdown paths can stop
        // it before the interface (and thus its bound IP) goes away.
        let dns_task = dns_bind.map(|bind| {
            let z = zone.clone();
            tokio::spawn(async move {
                match tokio::net::UdpSocket::bind(bind).await {
                    Ok(sock) => {
                        tracing::info!(%bind, "dns resolver listening");
                        if let Err(e) = dns::serve(sock, z).await {
                            tracing::error!("dns resolver ended: {e:#}");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("dns resolver bind {bind} failed ({e}); name resolution off")
                    }
                }
            })
        });

        // Point the OS resolver at our `.unity.internal` server on this link (best-effort). Reverted on
        // clean shutdown; also clears with the link if we exit uncleanly.
        let resolver: Option<Box<dyn ResolverHook>> = match (cfg.resolver_hook, dns_bind) {
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

        // Peer-direct attestation refresh (docs/gossip-refresh.md, stage 1): serve our own
        // coordinator-minted attestations to meshed co-members over the tunnel, so the mesh can keep
        // credentials fresh without the coordinator fanning them out. Off unless `gossip` is set; the
        // coordinator stays the fallback. Bound to our mesh /32 (now on the interface), torn down with
        // it. `own_atts` is refreshed from the grant on every register below.
        let own_atts = crate::p2p::OwnAttestations::default();
        let p2p_task = cfg.gossip.then(|| {
            own_atts.set(grant_attestations(&resp));
            let bind = SocketAddr::new(device.wg_ip.into(), common::p2p::P2P_PORT);
            let own = own_atts.clone();
            tokio::spawn(async move {
                match tokio::net::UdpSocket::bind(bind).await {
                    Ok(sock) => {
                        tracing::info!(%bind, "p2p attestation service listening");
                        if let Err(e) = crate::p2p::serve(sock, own).await {
                            tracing::warn!("p2p service ended: {e:#}");
                        }
                    }
                    Err(e) => {
                        tracing::warn!("p2p bind {bind} failed ({e}); peer-direct refresh off")
                    }
                }
            })
        });

        // LAN discovery beacon (`beacon.rs`): broadcast our WG pubkey + listen port on the local
        // segment so two peers behind one NAT find a direct LAN path instead of hairpinning through
        // the router's public IP. Bound to `0.0.0.0` (the physical segment, not the mesh /32) so it
        // can send/receive segment broadcasts. Off when `beacon` is unset; a bind / broadcast failure
        // is non-fatal (the mesh still works via coordinator-supplied endpoints).
        let mut beacon = if cfg.beacon {
            let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, cfg.beacon_port));
            match tokio::net::UdpSocket::bind(bind).await {
                Ok(sock) => match sock.set_broadcast(true) {
                    Ok(()) => {
                        tracing::info!(port = cfg.beacon_port, "LAN discovery beacon active");
                        Some(crate::beacon::Beacon::spawn(
                            sock,
                            wg_pub,
                            cfg.listen_port,
                            cfg.beacon_port,
                        ))
                    }
                    Err(e) => {
                        tracing::warn!("beacon: set_broadcast failed ({e}); LAN discovery off");
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!("beacon bind {bind} failed ({e}); LAN discovery off");
                    None
                }
            }
        } else {
            None
        };

        // Apply the initial snapshot; then keep the last one so a local network toggle can re-mesh
        // immediately (filtering by the opt-out set) even while the coordinator is unreachable.
        let mut peers: HashMap<[u8; 32], PeerConfig> = HashMap::new();
        let mut last_seeds = coord::verified_seeds(&resp, &cfg.state_dir)?;
        let mut last_device = Some(device);
        // Whether the last coordinator refresh succeeded. We just registered, so start `true`; a failed
        // refresh flips it (the mesh keeps running from cache), a successful one flips it back.
        let mut coord_online = true;
        // Relay sessions (§7.2, M5.4): a TURN allocation + loopback shim per peer we can only reach
        // via a relay. `relay_eps` maps such a peer to its shim address, used as the peer's WG
        // endpoint. Persist across refreshes within an enrollment; rebuilt on re-login.
        let mut relays = crate::relay::RelayManager::new();
        let mut relay_eps: HashMap<[u8; 32], SocketAddr> =
            sync_relays(&mut relays, &last_seeds).await;
        // Side-socket ICE (§7.2, M5.5): userspace-only. For a stuck peer we run an ICE agent beside
        // boringtun and route its WG traffic through the negotiated path via a loopback shim (like the
        // relay). `ice_eps` maps such a peer to its shim; on the kernel path it stays empty (that path
        // keeps the M5.4 relay above). `coord_stun` is the coordinator's STUN bootstrap fallback.
        let ice_enabled = backend.is_userspace() && cfg.ice;
        let mut ice = crate::ice::IceManager::new();
        let mut coord_stun = coord::stun_addr(&cfg.coordinator, resp.stun_port).await;
        tracing::debug!(?coord_stun, port = ?resp.stun_port, "coordinator STUN bootstrap");
        let mut ice_eps: HashMap<[u8; 32], SocketAddr> = HashMap::new();
        // Per-peer direct LAN endpoints learned from discovery beacons (`beacon.rs`), recomputed each
        // loop iteration from this device's ping-reachability of each peer. Empty until a beacon is
        // received *and* the LAN path verifies; tops endpoint precedence in `apply_seeds`.
        let mut lan_eps: HashMap<[u8; 32], SocketAddr> = HashMap::new();
        // The host-side handles that stay fixed for this enrollment; every apply_state below reuses it.
        let ctx = MeshCtx {
            backend: backend.as_ref(),
            fw: &fw,
            zone: &zone,
            status: &status,
            localnet: &localnet,
        };
        apply_state(
            &ctx,
            &last_device,
            &last_seeds,
            &mut peers,
            coord_online,
            Endpoints {
                relay: &relay_eps,
                ice: &ice_eps,
                lan: &lan_eps,
            },
        )
        .await?;

        // Long-poll loop: each /refresh blocks at the coordinator until membership changes or the
        // hold (~TTL/2) elapses, then returns a fresh snapshot + new version. Near-zero idle traffic;
        // a co-member joining wakes this call at once. `since` echoes the last version we applied.
        let mut since = Some(resp.version);
        // The in-flight `/refresh`, held **across** loop iterations. The loop re-reads local WG stats
        // every RECHECK to notice a freshly-learned reflexive, but that re-check must not cancel a
        // held long-poll — otherwise an idle client re-polls every RECHECK instead of parking for the
        // hold (measured: 30 req/min/client, and each poll costs the coordinator an O(peers) snapshot
        // build). So the request lives here and is dropped only when we actually have something new
        // to report (or the local opt-out state changed), which is exactly when it's stale anyway.
        let mut pending_refresh = None;
        // What we last reported to the coordinator (reflexive endpoints, relay need/allocations, ICE
        // offers). A change in any of these must break the long-poll hold so the update reports at
        // once — else a freshly-`Unreachable` peer's relay request, or a freshly-gathered ICE
        // candidate, would sit until the hold elapses. All sets are sorted for a stable compare.
        let mut sent = SentReport::default();
        // Per-peer connection bookkeeping (attempt/bootstrap timers + last reported reach), carried
        // across long-poll cycles and advanced each recheck by `PeerConn::step`.
        let mut conns: HashMap<[u8; 32], PeerConn> = HashMap::new();
        // Shared ICMP socket for the per-peer latency probe. Opening it needs privilege (we have it);
        // if it fails we run without latency numbers rather than aborting the daemon.
        let ping_client = match ping::client() {
            Ok(c) => Some(c),
            Err(e) => {
                tracing::warn!("latency probe disabled: {e:#}");
                None
            }
        };
        loop {
            // Peer-direct attestation refresh (docs/gossip-refresh.md, stage 2): before polling the
            // coordinator, renew any held peer whose attestation is near expiry by pulling a fresh one
            // straight from that peer over the tunnel (verified against our pinned anchor — no new
            // trust). What a pull can't cover falls through to the coordinator (`held_for_refresh`
            // returns empty → full) below. A peer whose attestation then lapses with no source — it
            // went offline, or was revoked and can no longer be issued a fresh one — is dropped and its
            // tunnel torn down, so revocation propagates via expiry even while the coordinator is
            // unreachable.
            if cfg.gossip {
                let now_secs = common::now_unix();
                for seed in last_seeds.iter_mut() {
                    if seed.expires_at > now_secs + P2P_REFRESH_MARGIN {
                        continue;
                    }
                    let target = SocketAddr::from((seed.ip, common::p2p::P2P_PORT));
                    match crate::p2p::pull(target, P2P_PULL_TIMEOUT).await {
                        Ok(blobs) => {
                            if let Some(att) = coord::verify_pulled(
                                &blobs,
                                seed.pubkey,
                                seed.expires_at,
                                &cfg.state_dir,
                                now_secs,
                            ) {
                                coord::apply_pulled(seed, &att);
                                tracing::debug!(peer = %seed.hostname, "attestation refreshed peer-direct");
                            }
                        }
                        Err(e) => tracing::debug!(
                            peer = %seed.hostname,
                            "peer-direct refresh failed ({e:#}); coordinator will cover it"
                        ),
                    }
                }
                let before = last_seeds.len();
                last_seeds.retain(|s| s.expires_at > now_secs);
                if last_seeds.len() != before {
                    tracing::info!(
                        dropped = before - last_seeds.len(),
                        "dropped peers with lapsed attestations (revocation via expiry)"
                    );
                    apply_state(
                        &ctx,
                        &last_device,
                        &last_seeds,
                        &mut peers,
                        coord_online,
                        Endpoints {
                            relay: &relay_eps,
                            ice: &ice_eps,
                            lan: &lan_eps,
                        },
                    )
                    .await?;
                }
            }

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
                None => sent.observed.clone(),
            };

            // Reachability diagnostics (§7.2): classify each peer and overlay it onto the status so a
            // stuck hole punch surfaces. A peer is "punched" if its only endpoint is a punch target
            // (no dialable endpoint); "connected" if WG has a recent handshake for it.
            let now = std::time::Instant::now();
            // Latency probe: one concurrent ICMP echo per peer's wg IP (peers answer ping by default).
            let peer_ips: Vec<Ipv4Addr> = peers
                .values()
                .filter_map(|c| c.allowed_ips.first().map(|(ip, _)| *ip))
                .collect();
            let latency = match &ping_client {
                Some(pc) => ping::probe(pc, &peer_ips).await,
                None => HashMap::new(),
            };
            let mut live: HashMap<Ipv4Addr, control::PeerLive> = HashMap::new();
            // Per-peer ping reachability this iteration — the health signal the beacon adoption check
            // uses to confirm a LAN endpoint carries traffic (a switched-to endpoint keeps the old WG
            // session, so only live round-trips, not handshake age, prove the new path).
            let mut reach_by_pk: HashMap<[u8; 32], bool> = HashMap::new();
            // Peers to ask the coordinator for a relay: those whose punch is stuck (`Unreachable`)
            // *plus* those we're already relaying — a working relay tunnel reads as connected, so
            // without this it would drop out of `need_relay` and the coordinator would withdraw the
            // relay, flapping it.
            let mut want_relay: Vec<[u8; 32]> = Vec::new();
            for (pk, cfg) in &peers {
                let punched = last_seeds
                    .iter()
                    .any(|s| s.pubkey == *pk && s.endpoint.is_none() && s.punch.is_some());
                let last_handshake = stats
                    .as_ref()
                    .and_then(|m| m.get(pk))
                    .and_then(|s| s.last_handshake);
                let last_handshake_secs = last_handshake
                    .and_then(|t| t.elapsed().ok())
                    .map(|d| d.as_secs());
                let connected = last_handshake
                    .is_some_and(|t| t.elapsed().map_or(true, |d| d < HANDSHAKE_FRESH));
                // A peer with no dialable endpoint *and* no punch target (no observer reported a
                // reflexive) that hasn't connected — the bootstrap case, cleared the moment a punch
                // target or handshake appears.
                let unpunchable = last_seeds
                    .iter()
                    .any(|s| s.pubkey == *pk && s.endpoint.is_none() && s.punch.is_none());
                let relaying = relays.is_relaying(pk);
                let icing = ice.is_connected(pk);
                // Advance this peer's connection FSM from the liveness above: age the attempt/bootstrap
                // timers and classify reachability (relay/ICE override the punch classifier).
                let step = conns.entry(*pk).or_default().step(
                    now,
                    punched,
                    connected,
                    unpunchable,
                    relaying,
                    icing,
                );
                let r = step.reach;
                // Log the flip (not every recheck): the state is otherwise only visible via
                // `ctl status`, so a peer flapping down leaves no trace. Carries the handshake age so
                // a stale-read glitch (age tiny) reads differently from a real outage (age large).
                if let Some((was_up, was_reach)) = step.flipped {
                    tracing::info!(
                        peer = %hex8(pk),
                        up = connected,
                        was_up,
                        reach = ?r,
                        was_reach = ?was_reach,
                        last_handshake_secs = ?last_handshake_secs,
                        "peer reachability changed"
                    );
                }
                if relaying
                    || icing
                    || r == common::control::PeerReach::Unreachable
                    || (ice_enabled && step.bootstrap_stuck)
                {
                    want_relay.push(*pk);
                }
                if let Some((ip, _)) = cfg.allowed_ips.first() {
                    reach_by_pk.insert(*pk, latency.contains_key(ip));
                    let (rx_bytes, tx_bytes) = stats
                        .as_ref()
                        .and_then(|m| m.get(pk))
                        .map_or((0, 0), |s| (s.rx_bytes, s.tx_bytes));
                    live.insert(
                        *ip,
                        control::PeerLive {
                            reach: r,
                            up: connected,
                            latency_ms: latency.get(ip).copied(),
                            rx_bytes,
                            tx_bytes,
                            last_handshake_secs,
                        },
                    );
                }
            }
            // Drop bookkeeping for peers that have left the mesh.
            conns.retain(|pk, _| peers.contains_key(pk));
            control::set_live(&status, &live);

            // Recompute direct LAN endpoints from received beacons + this iteration's ping health.
            // `lan_changed` flags an adoption/reversion so the local-recheck branch re-applies at once
            // (this transition is async to the long-poll, like an ICE session coming up).
            let lan_changed = if let Some(b) = beacon.as_mut() {
                let new = b.select(now, &reach_by_pk);
                let changed = new != lan_eps;
                lan_eps = new;
                changed
            } else {
                false
            };

            // This iteration's relay report: our fixed capability (from `relay_report`) plus the
            // dynamic per-loop bits — peers we want relayed and the relayed addresses we've allocated.
            // Sorted for a stable change comparison against the last report.
            want_relay.sort();
            // The stuck-peer set for this iteration (Unreachable ∪ relaying ∪ ICE-connected) — the
            // peers we run ICE / request a relay for.
            let want_set: HashSet<[u8; 32]> = want_relay.iter().copied().collect();
            let mut allocated = relays.allocations();
            allocated.sort_by_key(|a| a.peer);
            let mut relay_iter = relay_report.clone();
            relay_iter.need_relay = want_relay;
            relay_iter.allocated = allocated;
            let this_relay_need = relay_iter.need_relay.clone();
            let this_relay_alloc = relay_iter.allocated.clone();

            // Our ICE offers to report (userspace path only). Sorted for a stable change compare — a
            // change (fresh candidates as gathering completes, or an ICE restart's creds) must report
            // at once so the peer gets them without waiting out the long-poll hold.
            let mut ice_offers = if ice_enabled {
                ice.offers()
            } else {
                Vec::new()
            };
            ice_offers.sort_by_key(|e| e.peer);

            // Worth logging when the observed reflexive set changes (the endpoints we hand the
            // coordinator to pair peers); the relay/ICE report changes are silent.
            if observed != sent.observed {
                tracing::info!(
                    eps = ?observed.iter().map(|o| o.endpoint).collect::<Vec<_>>(),
                    "reflexive: reporting observed endpoints to coordinator"
                );
            }
            // Our own grant is refreshed only when a poll *completes*; the idle re-poll above keeps
            // cancelling the held request, so near expiry we must force a completing (non-held) poll —
            // otherwise our own attestation goes stale and peers refreshing it from us (gossip) reject
            // it. One such renewal per attestation lifetime (it jumps the expiry a full TTL forward).
            let own_grant_stale = last_device
                .as_ref()
                .map(|d| d.grant_expires_at <= common::now_unix() + common::LONGPOLL_HOLD_SECS)
                .unwrap_or(false);
            // Delta sync: echo our held peers' revs so the coordinator sends only what changed. Goes
            // empty only once a peer's attestation is within `COORD_FULL_MARGIN` of expiry and
            // peer-direct still hasn't refreshed it (Option A) — that empty set forces a full. Peer-
            // direct (above) owns the whole window before this margin, so a healthy mesh reaches here
            // with a non-empty (delta) set and never triggers a full.
            let held = coord::held_for_refresh(&last_seeds, common::now_unix(), COORD_FULL_MARGIN);
            // We conceded to the coordinator for at least one peer: an empty `held` with peers present
            // means a near-expiry forced full. That poll must *complete* (not hold), or the full could
            // arrive only after the long-poll elapses — too late this close to expiry. Treat it like a
            // report so `poll_since` goes `None`.
            let forced_full = !last_seeds.is_empty() && held.is_empty();
            // Anything new to tell the coordinator (a reflexive/relay/ICE report), a grant that needs
            // renewing, or a conceded attestation full means the currently-held request is stale: drop
            // it so the re-issue below carries the report and returns immediately (no hold). Otherwise
            // keep holding the existing request — the local re-check below must not cost a round-trip.
            let have_report =
                sent.stale(&observed, &this_relay_need, &this_relay_alloc, &ice_offers)
                    || own_grant_stale
                    || forced_full;
            if have_report {
                pending_refresh = None;
            }
            if pending_refresh.is_none() {
                let poll_since = if have_report { None } else { since };
                pending_refresh = Some(Box::pin(coord::refresh(
                    &cfg.coordinator,
                    &cfg.state_dir,
                    coord::CoordReq {
                        wg_pubkey: wg_pub,
                        device_name: cfg.device_name(),
                        endpoint,
                        enrollment_key: cfg.enrollment_key.clone(),
                        since: poll_since,
                        disabled_networks: localnet.as_refs(),
                        observed: observed.clone(),
                        supersede: None,
                        paused: localnet.is_paused(),
                        peer_own_devices: localnet.peer_own_devices(),
                        relay: relay_iter,
                        ice: ice_offers.clone(),
                        held,
                    },
                )));
            }
            // Set by arms that invalidate the held request; applied after the select, since the arms
            // can't assign to `pending_refresh` while the refresh arm holds it borrowed.
            let mut drop_pending = false;
            // The auto-update restart wake-up — signalled once a file-swap update has swapped the
            // binary (Unix and Windows both; only the legacy Windows MSI path bypasses this by exiting
            // via msiexec).
            let restart_signal = restart_for_update.notified();
            tokio::pin!(restart_signal);
            let refreshed = tokio::select! {
                // Clean shutdown: reverse every host mutation so a stop leaves no trace — destroy the
                // interface, tear down the firewall, revert the resolver. (UPnP unmaps via its own
                // shutdown-aware task.)
                _ = shutdown.wait() => {
                    teardown(
                        &cfg, wg_pub, endpoint, &localnet, &fw, &resolver,
                        backend.as_ref(), &dns_task, &p2p_task,
                    ).await;
                    tracing::info!("shutting down");
                    return Ok(RunOutcome::Stopped);
                }
                // Auto-update: same full teardown as a clean shutdown (so an update leaves no stranded
                // interface, firewall, or resolver state — the whole reason the file-swap path replaced
                // the old Windows hard-exit), then restart onto the binary the `ApplyUpdate` task
                // already swapped in. Unix re-execs the staged plan (same PID); Windows hands the
                // restart to the SCM. On Unix, falls back to a clean stop if, impossibly, no plan was
                // staged.
                _ = &mut restart_signal => {
                    tracing::info!("auto-update: tearing down before restarting onto the new engine");
                    teardown(
                        &cfg, wg_pub, endpoint, &localnet, &fw, &resolver,
                        backend.as_ref(), &dns_task, &p2p_task,
                    ).await;
                    #[cfg(unix)]
                    {
                        return match exec_slot.lock().unwrap().take() {
                            Some(plan) => Ok(RunOutcome::ReExec(plan)),
                            None => {
                                tracing::error!("update restart signalled with no staged plan; stopping");
                                Ok(RunOutcome::Stopped)
                            }
                        };
                    }
                    #[cfg(windows)]
                    {
                        return Ok(RunOutcome::RestartService);
                    }
                    // No auto-update artifact exists off unix/windows (`current_platform` is `None`),
                    // so `restart_for_update` is never signalled — but keep the arm diverging like the
                    // others so the `select!` type-checks everywhere.
                    #[cfg(not(any(unix, windows)))]
                    unreachable!("auto-update restart is unix/windows only");
                }
                // Logout: break out to the teardown path below, which un-enrolls, drops the mesh, and
                // loops back to `'lifecycle` to re-key and await the next login.
                _ = logout.notified() => break,
                // Local network toggle (also mesh connect/disconnect): re-mesh from the last snapshot at
                // once (works offline), then loop round to re-refresh so the coordinator picks up the
                // new opt-out / paused state.
                _ = localnet.wake.notified() => {
                    if ice_enabled {
                        ice_eps = sync_ice(&mut ice, &last_seeds, wg_pub, coord_stun, &want_set).await;
                    } else {
                        relay_eps = sync_relays(&mut relays, &last_seeds).await;
                    }
                    apply_state(
                        &ctx, &last_device, &last_seeds, &mut peers, coord_online,
                        Endpoints { relay: &relay_eps, ice: &ice_eps, lan: &lan_eps },
                    ).await?;
                    // The held request carries the *old* opt-out/paused state — re-issue it.
                    drop_pending = true;
                    None
                }
                // Re-read local WG stats every couple seconds so a freshly-learned reflexive is
                // noticed promptly (it only appears after a handshake — later than a hold would
                // return). Purely local: the held request above keeps waiting, so an idle client
                // costs the coordinator one request per hold, not one per re-check.
                _ = tokio::time::sleep(STATS_RECHECK) => {
                    // ICE connects asynchronously and nothing about that transition wakes the
                    // long-poll, so the shim would otherwise sit unused until the next refresh
                    // completed — up to a whole hold after the path was actually ready. Re-sync here
                    // and apply the moment either endpoint set changes. A beacon adopting/reverting a
                    // LAN endpoint (`lan_changed`) is likewise async to the long-poll. Purely local:
                    // no coordinator traffic, so an idle client still costs one request per hold.
                    let mut ice_changed = false;
                    if ice_enabled {
                        let eps = sync_ice(&mut ice, &last_seeds, wg_pub, coord_stun, &want_set).await;
                        if eps != ice_eps {
                            ice_eps = eps;
                            ice_changed = true;
                        }
                    }
                    if ice_changed || lan_changed {
                        apply_state(
                            &ctx, &last_device, &last_seeds, &mut peers, coord_online,
                            Endpoints { relay: &relay_eps, ice: &ice_eps, lan: &lan_eps },
                        ).await?;
                    }
                    None
                }
                r = pending_refresh.as_mut().expect("a request is always in flight here") => Some(r),
            };
            if drop_pending {
                pending_refresh = None;
            }
            // No result yet (local re-check / local toggle) — loop round and re-evaluate.
            let Some(refreshed) = refreshed else { continue };
            pending_refresh = None; // this request completed
            match refreshed {
                Ok((resp, dev)) => {
                    coord_online = true;
                    // A successful exchange means the versions reconciled — clear any prior refusal
                    // (an operator updated a side, or the coordinator rolled back).
                    control::set_proto_mismatch(&status, None);
                    note_update(&status, &resp, &cfg.state_dir, &pending_update);
                    since = Some(resp.version);
                    // The coordinator now has this reflexive / relay / ICE report.
                    sent = SentReport {
                        observed,
                        relay_need: this_relay_need,
                        relay_alloc: this_relay_alloc,
                        ice_offers,
                    };
                    // the STUN fallback may have (dis)appeared
                    coord_stun = coord::stun_addr(&cfg.coordinator, resp.stun_port).await;
                    if cfg.gossip {
                        // Keep the p2p service handing out our freshest attestations (delta responses
                        // may carry a refreshed grant even when nothing else changed).
                        own_atts.set(grant_attestations(&resp));
                    }
                    match coord::merge_seeds(&last_seeds, &resp, &cfg.state_dir) {
                        Ok(seeds) => {
                            last_seeds = seeds;
                            // A grant of `None` means we hold no networks (role revoked): keep the last
                            // device for name context, but the empty seed set prunes every peer.
                            if dev.is_some() {
                                last_device = dev;
                            } else {
                                tracing::warn!("no grant — access revoked; dropping all peers");
                            }
                            // Ensure/refresh the per-peer overlay for stuck peers before applying: on
                            // the userspace path an ICE session per stuck peer (its shim as the WG
                            // endpoint); on the kernel path the M5.4 relay allocation + shim.
                            if ice_enabled {
                                ice_eps =
                                    sync_ice(&mut ice, &last_seeds, wg_pub, coord_stun, &want_set)
                                        .await;
                            } else {
                                relay_eps = sync_relays(&mut relays, &last_seeds).await;
                            }
                            apply_state(
                                &ctx,
                                &last_device,
                                &last_seeds,
                                &mut peers,
                                coord_online,
                                Endpoints {
                                    relay: &relay_eps,
                                    ice: &ice_eps,
                                    lan: &lan_eps,
                                },
                            )
                            .await?;
                        }
                        Err(e) => tracing::warn!("bad seeds: {e:#}"),
                    }
                }
                // Coordinator unreachable: back off (don't hammer), keep the existing mesh alive but
                // flag it so the GUI shows the coordinator as offline.
                Err(e) => {
                    // A protocol refusal isn't unreachability — the coordinator answered. Keep the
                    // mesh running from cache (peers we already hold stay reachable), but say so and
                    // back off hard: no retry interval fixes a version gap.
                    let stale = e
                        .downcast_ref::<coord::UpgradeRequired>()
                        .map(|u| u.to_string());
                    let backoff = if let Some(why) = stale {
                        tracing::error!("coordinator refused this build: {why}");
                        control::set_proto_mismatch(&status, Some(why));
                        PROTO_MISMATCH_BACKOFF
                    } else {
                        tracing::warn!("refresh failed: {e:#}");
                        Duration::from_secs(cfg.refresh_secs.max(1))
                    };
                    coord_online = false;
                    control::set_coord_online(&status, false);
                    tokio::time::sleep(backoff).await;
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
            if let Err(e) = fw.update_peers(crate::fw::PeerSets::default()) {
                tracing::warn!("logout: clearing firewall peers: {e:#}");
            }
        }
        if let Some(r) = &resolver {
            if let Err(e) = r.revert(&cfg.iface) {
                tracing::warn!("logout: resolver revert: {e:#}");
            }
        }
        if let Some(t) = &dns_task {
            t.abort();
        }
        if let Some(t) = &p2p_task {
            t.abort();
        }
        // Discard the local key + token so the next register re-keys and reports not-logged-in.
        keys::clear_enrollment(&cfg.state_dir)?;
        *token.write().await = None;
        control::set_logged_out(&status);
        continue 'lifecycle;
    }
}

/// Host-side handles fixed for a whole enrollment — the mesh loop threads these into every
/// `apply_state`, so its five call sites pass one context instead of five separate refs.
struct MeshCtx<'a> {
    backend: &'a dyn WgBackend,
    fw: &'a Option<Arc<Firewall>>,
    zone: &'a dns::Zone,
    status: &'a control::Shared,
    localnet: &'a LocalNet,
}

/// The three per-peer endpoint overlays resolved each loop iteration — relay shim, ICE shim, LAN
/// beacon — passed together as the endpoint-precedence source for `apply_seeds`. A borrowed view:
/// each map is still produced independently by its own subsystem (`sync_relays` / `sync_ice` /
/// beacon); this only groups them for the consumer that always reads all three together.
#[derive(Clone, Copy)]
struct Endpoints<'a> {
    relay: &'a HashMap<[u8; 32], SocketAddr>,
    ice: &'a HashMap<[u8; 32], SocketAddr>,
    lan: &'a HashMap<[u8; 32], SocketAddr>,
}

/// Filter the snapshot through the local opt-out set, then push it to DNS, the control socket, the
/// firewall, and the WG backend. A peer is kept if it shares at least one *enabled* network with
/// us; peers whose every shared network is locally disabled are dropped (both here and — once the
/// opt-out reaches the coordinator — from its seed list too).
async fn apply_state(
    ctx: &MeshCtx<'_>,
    device: &Option<SelfDevice>,
    seeds: &[SeedPeer],
    peers: &mut HashMap<[u8; 32], PeerConfig>,
    coord_online: bool,
    eps: Endpoints<'_>,
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
        if let Err(e) = ctx.localnet.reconcile_new(&present) {
            tracing::warn!("reconciling new networks: {e:#}");
        }
    }
    let disabled = ctx.localnet.snapshot();
    let blocked = ctx.localnet.blocked_snapshot();
    let paused = ctx.localnet.is_paused();
    // Disconnected: bring the interface administratively down (no traffic, /32 route inactive) *and*
    // drop every peer — no mesh. Reconnect brings the link back up. The device, its uapi socket and
    // the resolver config all persist across the toggle, so this is idempotent and needs no teardown.
    // The coordinator withdraws our presence (via the `paused` flag on refresh), so co-members prune us.
    ctx.backend.set_link_up(!paused)?;
    let active: Vec<SeedPeer> = match device {
        Some(dev) if !paused => filter_active(seeds, &disabled, &blocked, &dev.networks_status),
        _ => Vec::new(),
    };
    // Track whether any sink actually changed, so a no-delta refresh (the coordinator re-sending the
    // same membership every hold) does no work and logs nothing rather than churning every ~2s.
    // `control::update` still runs unconditionally — it's an in-memory status snapshot that also
    // carries `coord_online`, which can flip with no membership change.
    let mut changed = false;
    if let Some(dev) = device {
        changed |= dns::update(ctx.zone, dev, &active).await;
        control::update(
            ctx.status,
            dev,
            &active,
            &disabled,
            &blocked,
            !paused,
            ctx.localnet.disable_new(),
            ctx.localnet.peer_own_devices(),
            coord_online,
        );
    }
    if let Some(fw) = ctx.fw {
        changed |= fw.update_peers(peer_sets(&active, device.as_ref().map(|d| d.user_id)))?;
    }
    changed |= apply_seeds(ctx.backend, active, peers, eps)?;
    if changed {
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
    }
    Ok(())
}

/// For every seed carrying relay info, ensure a TURN allocation + loopback shim exists (allocating
/// on first sight, refreshing the peer's relayed address each time), and return the map of
/// relayed-peer → local shim endpoint. Sessions for peers no longer relayed are dropped.
async fn sync_relays(
    relays: &mut crate::relay::RelayManager,
    seeds: &[SeedPeer],
) -> HashMap<[u8; 32], SocketAddr> {
    let mut eps = HashMap::new();
    let mut keep = HashSet::new();
    for s in seeds {
        if let Some(info) = &s.relay {
            keep.insert(s.pubkey);
            if let Some(shim) = relays.ensure(s.pubkey, info).await {
                eps.insert(s.pubkey, shim);
            }
        }
    }
    relays.retain(&keep);
    eps
}

/// For each stuck peer (in `want`), ensure an ICE agent exists (starting it + gathering on first
/// sight, feeding the peer's latest ICE offer each call) and return the map of peer → local shim
/// endpoint for those that have connected. Sessions for peers no longer stuck are dropped. STUN is
/// relay-first (a dialable relay co-member answers Binding too) with the coordinator host as a
/// fallback; the peer's `relay` reservation doubles as ICE's TURN relay candidate.
async fn sync_ice(
    ice: &mut crate::ice::IceManager,
    seeds: &[SeedPeer],
    self_pk: [u8; 32],
    coord_stun: Option<SocketAddr>,
    want: &HashSet<[u8; 32]>,
) -> HashMap<[u8; 32], SocketAddr> {
    let mut eps = HashMap::new();
    let mut keep = HashSet::new();
    for s in seeds {
        // Start ICE for a peer in the stuck set; keep an already-started session alive as long as
        // the peer is still a seed, even if `want` (computed before the ~TTL/2 long-poll hold) no
        // longer lists it — the age classifier flips Punching→Unreachable *during* the hold, so a
        // stale `want` would otherwise tear a mid-negotiation session down and restart it each cycle.
        if !want.contains(&s.pubkey) && !ice.has_session(&s.pubkey) {
            continue;
        }
        keep.insert(s.pubkey);
        let mut stun = Vec::new();
        if let Some(r) = &s.relay {
            stun.push(r.turn_addr); // a relay co-member answers STUN Binding too (relay-first)
        }
        if let Some(cs) = coord_stun {
            stun.push(cs); // coordinator-host fallback
        }
        let cfg = crate::ice::IcePeerConfig {
            controlling: self_pk < s.pubkey, // deterministic role: the lower pubkey dials
            stun,
            turn: s.relay.clone(),
            remote: s.ice.clone(),
        };
        if let Some(shim) = ice.ensure(s.pubkey, cfg).await {
            eps.insert(s.pubkey, shim);
        }
    }
    ice.retain(&keep);
    eps
}

/// Keep peers that share at least one network we haven't locally disabled and whose owner we
/// haven't locally blocked. Shared networks arrive as names; we resolve them to (guild, role) via
/// our own `networks_status` to compare against the opt-out set. A peer with no known shared network
/// (older coordinator) is kept. A blocked owner's peers are always dropped (a block outranks any
/// shared network), which prunes their tunnels on the next `apply_seeds`.
fn filter_active(
    seeds: &[SeedPeer],
    disabled: &HashSet<(u64, u64)>,
    blocked: &HashMap<u64, String>,
    networks_status: &[common::api::NetworkStatus],
) -> Vec<SeedPeer> {
    let name_to_id: HashMap<&str, (u64, u64)> = networks_status
        .iter()
        .map(|n| (n.name.as_str(), (n.guild_id, n.role_id)))
        .collect();
    seeds
        .iter()
        .filter(|s| !blocked.contains_key(&s.user_id))
        .filter(|s| {
            s.networks.is_empty()
                || s.networks
                    .iter()
                    .any(|n| match name_to_id.get(n.name.as_str()) {
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
    login_done: &tokio::sync::Notify,
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
                &cfg.state_dir,
                coord::CoordReq {
                    wg_pubkey: wg_pub,
                    device_name: cfg.device_name(),
                    endpoint,
                    enrollment_key: cfg.enrollment_key.clone(),
                    since: None,
                    disabled_networks: localnet.as_refs(),
                    observed: Vec::new(),
                    supersede: supersede.clone(),
                    paused: localnet.is_paused(),
                    peer_own_devices: localnet.peer_own_devices(),
                    relay: relay.clone(),
                    ice: Vec::new(),
                    held: Vec::new(),
                },
            ) => r,
        };
        match attempt {
            Ok((resp, Some(dev))) => {
                control::set_needs_login(status, false);
                control::set_proto_mismatch(status, None);
                return Ok(Some((resp, dev)));
            }
            // Enrolled but no networks yet — not a login problem; wait for a role.
            Ok((_resp, None)) => {
                control::set_needs_login(status, false);
                control::set_proto_mismatch(status, None);
                tracing::info!("registered but hold no networks yet; waiting for a role");
            }
            Err(e) => {
                // A protocol refusal is not transient: the coordinator is up and answering, it just
                // won't speak to this build. Retrying at `refresh_secs` would hammer it forever for
                // nothing, so flag it for the GUI and back off hard until someone updates.
                if let Some(u) = e.downcast_ref::<coord::UpgradeRequired>() {
                    tracing::error!("coordinator refused this build: {u}");
                    control::set_proto_mismatch(status, Some(u.to_string()));
                    tokio::time::sleep(PROTO_MISMATCH_BACKOFF).await;
                    continue;
                }
                control::set_proto_mismatch(status, None);
                // A 401 means we're not logged in; flag it so a frontend offers login. Other
                // errors (coordinator down) are transient — just retry without the flag.
                let msg = format!("{e:#}");
                let needs_login = msg.contains("not enrolled") || msg.contains("log in");
                control::set_needs_login(status, needs_login);
                if needs_login {
                    tracing::info!("not logged in — waiting for interactive login");
                } else {
                    tracing::warn!("register failed (retrying): {e:#}");
                }
            }
        }
        // Back off before the next attempt, but wake early if interactive login just bound us —
        // collapses the post-"Login successful" gap from up to `refresh_secs` to near-zero.
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_secs(cfg.refresh_secs.max(2))) => {}
            _ = login_done.notified() => {}
        }
    }
}

/// Build the firewall's view of the mesh from the active seeds: each visible network with its
/// members, plus the owner's own other devices.
///
/// Networks are identified by `(guild_id, role_id)` so two guilds' same-named roles stay separate;
/// the community and role labels ride along for display and for resolving a name someone typed.
///
/// Own devices are *not* a network — the coordinator never sends one, and a peer's `networks` stays
/// empty for the own-device relationship. They're recognized by identity instead: a seed carrying
/// our own `user_id` is another device of ours. `owner` is `None` before enrollment, when we don't
/// yet know who we are and so admit nobody.
fn peer_sets(seeds: &[SeedPeer], owner: Option<u64>) -> crate::fw::PeerSets {
    let mut sets = crate::fw::PeerSets::default();
    let mut unidentified: Vec<&str> = Vec::new();
    for s in seeds {
        for n in &s.networks {
            // A network with no `(guild_id, role_id)` comes from a coordinator that predates the
            // ids. It stays displayable but unscopable: inventing an identity for it (say `0/0`)
            // would merge every such network into one source set and cross-admit all of them.
            let Some((guild_id, role_id)) = n.id() else {
                if !unidentified.contains(&n.name.as_str()) {
                    unidentified.push(&n.name);
                }
                continue;
            };
            match sets
                .nets
                .iter_mut()
                .find(|e| e.guild_id == guild_id && e.role_id == role_id)
            {
                Some(e) => e.ips.push(s.ip),
                None => sets.nets.push(crate::fw::NetInfo {
                    guild_id,
                    role_id,
                    guild: n.community.clone(),
                    name: n.name.clone(),
                    ips: vec![s.ip],
                }),
            }
        }
        if owner.is_some_and(|me| me == s.user_id) {
            sets.own_devices.push(s.ip);
        }
    }
    // Canonicalize member ordering so an unchanged membership compares equal across refreshes: the
    // coordinator delivers seeds in varying order (HashMap iteration), and `PeerSets`'s derived
    // `PartialEq` is order-sensitive on these `Vec`s — without this a herd of refreshes reorders the
    // ip lists and churns the firewall (reconcile + log) every cycle for no real change.
    sets.nets.sort_by_key(|n| (n.guild_id, n.role_id));
    for n in &mut sets.nets {
        n.ips.sort();
    }
    sets.own_devices.sort();
    // Say so once per rebuild rather than leaving a port that never opens with no explanation
    // anywhere: an exposure scoped to one of these admits nobody until the coordinator is updated.
    if !unidentified.is_empty() {
        tracing::warn!(
            networks = ?unidentified,
            "coordinator did not send guild/role ids for these networks, so ports cannot be exposed \
             to them (an existing exposure scoped to one stays closed); update the coordinator"
        );
    }
    sets
}

/// Fold seeds (one per co-member per shared network) into peers keyed by pubkey, then push
/// any additions/changes to the backend and (re)install routing.
fn apply_seeds(
    backend: &dyn WgBackend,
    seeds: Vec<SeedPeer>,
    peers: &mut HashMap<[u8; 32], PeerConfig>,
    eps: Endpoints<'_>,
) -> anyhow::Result<bool> {
    // Aggregate this round's seeds by pubkey (a co-member may share several networks → several /32s).
    // pubkey -> (allowed /32s, endpoint); a named alias for one local adds noise.
    #[allow(clippy::type_complexity)]
    let mut desired: HashMap<[u8; 32], (Vec<(Ipv4Addr, u8)>, Option<SocketAddr>)> = HashMap::new();
    for s in seeds {
        // Endpoint precedence: a LAN endpoint learned from a discovery beacon wins — it's a direct
        // same-segment path that supersedes the coordinator's endpoint (which, for two peers behind
        // one NAT, is a flaky public-IP hairpin); else the coordinator's directly dialable endpoint;
        // else our ICE shim (userspace path, the negotiated best path — direct srflx or relay); else
        // the M5.4 relay shim (kernel path); else the punch target (reflexive) so WG handshakes toward
        // it. The shims are loopback — the daemon's ICE / TURN pump forwards through them.
        let lan_ep = eps.lan.get(&s.pubkey).copied();
        let ice_ep = eps.ice.get(&s.pubkey).copied();
        let relay_ep = eps.relay.get(&s.pubkey).copied();
        if s.endpoint.is_none() && ice_ep.is_none() && relay_ep.is_none() && lan_ep.is_none() {
            if let Some(p) = s.punch {
                tracing::info!(peer = %hex8(&s.pubkey), punch = %p, "hole-punch: dialing peer reflexive");
            }
        }
        let ep = lan_ep.or(s.endpoint).or(ice_ep).or(relay_ep).or(s.punch);
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
        let existing = peers.get(&pubkey);
        let differs = match existing {
            Some(e) => e.allowed_ips != peer.allowed_ips || e.endpoint != peer.endpoint,
            None => true,
        };
        if differs {
            // The userspace (boringtun) backend can't modify a peer in place — it panics on an
            // endpoint/allowed-ips change (e.g. when a peer switches from a punch target to its relay
            // shim). Remove the old peer first, then add the updated one.
            if existing.is_some() {
                backend.remove_peer(&pubkey)?;
            }
            backend.set_peer(&peer)?;
            tracing::info!(peer = %hex8(&pubkey), ips = ?peer.allowed_ips, "peer set");
            // Note the non-obvious path we routed via — but only here, on an actual (re)apply, not on
            // every idle reconcile pass: a peer parked on its LAN/ICE/relay endpoint is re-seen each
            // ~2s recheck, and logging it every pass floods the log (the coordinator's own directly
            // dialable endpoint is the unremarkable default, so it stays unlogged).
            match peer.endpoint {
                Some(ep) if eps.lan.get(&pubkey) == Some(&ep) => {
                    tracing::debug!(peer = %hex8(&pubkey), lan = %ep, "beacon: routing peer via direct LAN endpoint");
                }
                Some(ep) if eps.ice.get(&pubkey) == Some(&ep) => {
                    tracing::debug!(peer = %hex8(&pubkey), shim = %ep, "ice: routing peer via ICE shim");
                }
                Some(ep) if eps.relay.get(&pubkey) == Some(&ep) => {
                    tracing::debug!(peer = %hex8(&pubkey), shim = %ep, "relay: routing peer via TURN shim");
                }
                _ => {}
            }
            peers.insert(pubkey, peer);
            changed = true;
        }
    }

    if changed {
        let all: Vec<PeerConfig> = peers.values().cloned().collect();
        if let Err(e) = backend.configure_routing(&all) {
            tracing::warn!("routing not applied (needs iface up): {e:#}");
        }
        tracing::info!(peers = all.len(), "mesh updated");
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coord::SeedPeer;
    use common::control::PeerReach;
    use std::time::Instant;

    #[test]
    fn step_ages_attempt_then_flags_the_flip() {
        let t0 = Instant::now();
        let mut c = PeerConn::default();
        // First sight, unconnected inside the grace window: Direct, and never a flip (no prior).
        let s = c.step(t0, false, false, false, false, false);
        assert_eq!(s.reach, PeerReach::Direct);
        assert!(s.flipped.is_none());
        // Aged past the classifier grace with no handshake → Unreachable, and the edge is reported.
        let s = c.step(
            t0 + Duration::from_secs(STUCK),
            false,
            false,
            false,
            false,
            false,
        );
        assert_eq!(s.reach, PeerReach::Unreachable);
        assert_eq!(s.flipped, Some((false, PeerReach::Direct)));
        // A handshake clears the attempt timer: back to Direct/up, flip reported once more.
        let s = c.step(
            t0 + Duration::from_secs(STUCK + 1),
            false,
            true,
            false,
            false,
            false,
        );
        assert_eq!(s.reach, PeerReach::Direct);
        assert_eq!(s.flipped, Some((false, PeerReach::Unreachable)));
        // Steady state re-reports the same pair without a flip.
        assert!(c
            .step(
                t0 + Duration::from_secs(STUCK + 2),
                false,
                true,
                false,
                false,
                false
            )
            .flipped
            .is_none());
    }

    #[test]
    fn step_bootstrap_timer_arms_and_clears() {
        let t0 = Instant::now();
        let mut c = PeerConn::default();
        // Unpunchable + unconnected arms the bootstrap timer, but not stuck yet.
        assert!(!c.step(t0, false, false, true, false, false).bootstrap_stuck);
        // Aged past the bootstrap grace → stuck (drives ICE escalation).
        assert!(
            c.step(
                t0 + Duration::from_secs(BOOTSTRAP_STUCK_SECS),
                false,
                false,
                true,
                false,
                false
            )
            .bootstrap_stuck
        );
        // A handshake clears it even while still unpunchable.
        assert!(
            !c.step(
                t0 + Duration::from_secs(BOOTSTRAP_STUCK_SECS + 1),
                false,
                true,
                true,
                false,
                false
            )
            .bootstrap_stuck
        );
    }

    #[test]
    fn step_relay_and_ice_override_the_classifier() {
        let t0 = Instant::now();
        let mut c = PeerConn::default();
        // Aged-out + punched would classify Unreachable, but an active relay wins.
        let s = c.step(
            t0 + Duration::from_secs(STUCK),
            true,
            false,
            false,
            true,
            false,
        );
        assert_eq!(s.reach, PeerReach::Relayed);
        // ICE likewise wins over the punch classifier.
        let s = c.step(
            t0 + Duration::from_secs(STUCK),
            true,
            false,
            false,
            false,
            true,
        );
        assert_eq!(s.reach, PeerReach::Ice);
    }

    #[test]
    fn sent_report_stale_on_each_reportable_change() {
        use common::api::{IceEndpoint, IceParams, ObservedEndpoint, RelayAllocation};
        let ep: SocketAddr = "1.2.3.4:5".parse().unwrap();
        let observed = vec![ObservedEndpoint {
            pubkey: [1; 32],
            endpoint: ep,
        }];
        let relay_need = vec![[2u8; 32]];
        let relay_alloc = vec![RelayAllocation {
            peer: [3; 32],
            relayed: ep,
        }];
        let ice = vec![IceEndpoint {
            peer: [4; 32],
            params: IceParams {
                ufrag: "u".into(),
                pwd: "p".into(),
                candidates: vec![],
            },
        }];

        // Already holding exactly these sets → not stale against them (the idle recheck keeps parking).
        let sent = SentReport {
            observed: observed.clone(),
            relay_need: relay_need.clone(),
            relay_alloc: relay_alloc.clone(),
            ice_offers: ice.clone(),
        };
        assert!(!sent.stale(&observed, &relay_need, &relay_alloc, &ice));

        // Any single set differing makes the held poll stale (must drop it and report at once).
        assert!(sent.stale(&[], &relay_need, &relay_alloc, &ice), "observed");
        assert!(sent.stale(&observed, &[], &relay_alloc, &ice), "relay_need");
        assert!(sent.stale(&observed, &relay_need, &[], &ice), "relay_alloc");
        assert!(sent.stale(&observed, &relay_need, &relay_alloc, &[]), "ice");

        // Nothing reported yet is stale against any non-empty report, but not against an empty one.
        assert!(SentReport::default().stale(&observed, &[], &[], &[]));
        assert!(!SentReport::default().stale(&[], &[], &[], &[]));
    }

    const STUCK: u64 = common::control::STUCK_AFTER_SECS;

    /// Stable fake ids per role name, so two seeds naming the same network agree on its identity.
    fn ids(name: &str) -> (u64, u64) {
        match name {
            "minecraft" => (900_100, 7001),
            "factorio" => (900_200, 7002),
            other => panic!("unknown fixture network {other}"),
        }
    }

    fn seed(user_id: u64, last_octet: u8, nets: &[&str]) -> SeedPeer {
        SeedPeer {
            pubkey: [0; 32],
            user_id,
            username: "u".into(),
            ip: Ipv4Addr::new(100, 64, 0, last_octet),
            endpoint: None,
            punch: None,
            hostname: "d.u.unity.internal".into(),
            primary_alias: None,
            networks: nets
                .iter()
                .map(|n| {
                    let (guild_id, role_id) = ids(n);
                    common::api::SharedNetwork {
                        name: (*n).into(),
                        community: "acme".into(),
                        guild_id,
                        role_id,
                    }
                })
                .collect(),
            relay: None,
            ice: None,
            rev: 0,
            expires_at: 0,
        }
    }

    /// The own-device source set is drawn from peer *identity*, not from any network — so it admits
    /// our other devices (whatever networks they're in) and nobody else. Getting this wrong would
    /// hand a stranger a port the owner scoped to themselves.
    #[test]
    fn own_device_sources_are_the_owners_devices_only() {
        let me = 7;
        let seeds = [
            seed(me, 2, &["minecraft"]), // another device of ours
            seed(me, 3, &[]),            // ...and one sharing no network at all
            seed(99, 4, &["minecraft"]), // a co-member, not us
        ];

        let sets = peer_sets(&seeds, Some(me));
        assert_eq!(
            sets.own_devices,
            vec![Ipv4Addr::new(100, 64, 0, 2), Ipv4Addr::new(100, 64, 0, 3)],
        );
        let mc = sets
            .nets
            .iter()
            .find(|n| n.name == "minecraft")
            .expect("minecraft network present");
        assert_eq!(
            mc.ips,
            vec![Ipv4Addr::new(100, 64, 0, 2), Ipv4Addr::new(100, 64, 0, 4)],
            "network grouping is unaffected by the own-device split",
        );
        assert_eq!((mc.guild_id, mc.role_id), ids("minecraft"));
    }

    /// A coordinator that predates the network ids sends none, so its networks arrive with `0`s.
    /// Zero is not an identity — inventing one would merge every such network into a single source
    /// set and cross-admit all of them — so they're dropped from the scopable set entirely.
    #[test]
    fn networks_without_ids_are_not_scopable() {
        let mut s = seed(7, 2, &["minecraft"]);
        s.networks[0].guild_id = 0;
        s.networks[0].role_id = 0;

        let sets = peer_sets(&[s], Some(1));
        assert!(
            sets.nets.is_empty(),
            "a network with no identity must not become a scope target",
        );
    }

    /// Before enrollment we don't know who we are, so nothing qualifies as our own device.
    #[test]
    fn own_device_sources_are_empty_without_an_identity() {
        let sets = peer_sets(&[seed(7, 2, &["minecraft"])], None);
        assert!(sets.own_devices.is_empty());
    }
}
