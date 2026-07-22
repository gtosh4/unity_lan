//! UnityLAN engine (M1, headless): register with the coordinator, verify the signed
//! attestations, pin the trust anchor, and print the resulting IPs + hostnames.

mod beacon;
mod config;
mod control;
mod coord;
mod daemon;
mod dns;
mod fw;
mod ice;
mod keys;
mod nat;
mod netcfg;
mod oauth;
mod p2p;
mod ping;
mod relay;
mod resolver;
mod selfupdate;
#[cfg(windows)]
mod service;
mod shutdown;
#[cfg(test)]
mod testutil;
mod util;
mod wg;

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};

use crate::config::Config;

/// UnityLAN engine — headless data-plane daemon.
#[derive(Parser)]
#[command(
    name = "unitylan-engine",
    version,
    about,
    after_help = "\
Examples:
  unitylan-engine login                    log in with Discord, then enroll this device
  unitylan-engine run                      run the daemon in the foreground
  unitylan-engine ctl status               show device, networks, and peer reachability
  unitylan-engine ctl expose 25565 gaming  open TCP 25565 to the 'gaming' network's peers

With no -c, the config is looked up in the working directory first, then this platform's
installed location (/etc/unitylan/engine.toml on Linux). Point it anywhere with -c:
  unitylan-engine -c /srv/mesh/engine.toml ctl status"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// Config file to use (also names the control socket `ctl` talks to).
    #[arg(short, long, global = true, value_name = "PATH")]
    config: Option<String>,
    /// One-time enrollment key, overriding `enrollment_key` in the config. Lets a headless box
    /// enroll without writing the bearer secret to disk (e.g. pass it once via a systemd unit
    /// `ExecStart`, an env-substituted arg, or an interactive first run).
    #[arg(long, value_name = "KEY")]
    token: Option<String>,
    /// Also append logs to this file (in addition to stdout), overriding the config's `log_file`.
    /// Useful for a foreground `run` whose console output would otherwise be lost.
    #[arg(long, global = true, value_name = "PATH")]
    log_file: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the engine daemon (console mode; Ctrl-C shuts down).
    Run,
    /// Interactive Discord login, then confirm this device.
    Login,
    /// Talk to a running daemon over its control socket.
    Ctl {
        #[command(subcommand)]
        sub: CtlCmd,
    },
    /// Print a fresh WireGuard keypair as `priv pub` (base64).
    WgKeygen,
    /// Bring a WG iface up, add a dummy peer, tear down (needs CAP_NET_ADMIN).
    #[command(hide = true)]
    WgSmoke {
        #[arg(default_value = "unl-smoke")]
        ifname: String,
    },
    /// Bring up one WG node, hold it up, then tear down (netns tunnel test).
    #[command(hide = true)]
    WgNode {
        iface: String,
        priv_b64: String,
        port: u16,
        /// addr/cidr
        addr: String,
        peer_pub_b64: String,
        peer_ep: SocketAddr,
        /// peer allowed/cidr
        peer_allowed: String,
        hold_secs: u64,
    },
    /// Serve a single `<name> <ip>` record on `<bind>` (dev/test).
    #[command(hide = true)]
    DnsServe {
        bind: SocketAddr,
        name: String,
        ip: Ipv4Addr,
    },
    /// Un-enroll this device at the coordinator, and optionally wipe local state.
    #[command(long_about = "\
Un-enroll this device at the coordinator; with `--purge`, also wipe all local state (keys, token,
pinned anchors) — the \"forget me\" teardown a package purge invokes. Stop the daemon first (it
reverts the interface/firewall/DNS on shutdown); this handles the coordinator + disk.")]
    Uninstall {
        /// Also delete local state (device identity). Without this, state is kept for reinstall.
        #[arg(long)]
        purge: bool,
    },
    /// Install this platform's OS resolver hook.
    #[command(hide = true)]
    ResolverInstall { iface: String, server: SocketAddr },
    /// Revert this platform's OS resolver hook.
    #[command(hide = true)]
    ResolverRevert { iface: String },
}

/// `ctl` subcommands. All of them reach the daemon over the control socket named by the global
/// `-c/--config`, or by the first config on the search path when it's absent.
#[derive(Subcommand)]
enum CtlCmd {
    /// Show this device, its networks, and every peer's address and reachability.
    Status,
    /// List the devices enrolled under your account.
    Devices,
    /// Rename this device (changes its `<device>.<user>.unity.internal` hostname).
    Rename {
        /// New name for this device.
        new_name: String,
    },
    /// Make one of your devices the primary — the one the bare `<user>.unity.internal` resolves to.
    SetPrimary {
        /// Name of the device to promote, as shown by `ctl devices`.
        device: String,
    },
    /// Un-enroll one of your devices at the coordinator.
    Remove {
        /// Name of the device to drop, as shown by `ctl devices`.
        device: String,
    },
    /// Open a local port to mesh peers through the host firewall.
    Expose {
        /// Port to open: `25565` (tcp), or `tcp/25565` / `udp/34197`.
        port: String,
        /// Restrict the port to this network's peers; omit to open it to every peer.
        net: Option<String>,
        /// The guild `net` belongs to, when two of your guilds share the role name.
        #[arg(long, requires = "net")]
        guild: Option<String>,
        /// Restrict the port to the owner's own other devices instead of a network.
        #[arg(long, conflicts_with = "net")]
        own_devices: bool,
    },
    /// Close a port opened with `expose`.
    Unexpose {
        /// Port to close: `25565` (tcp), or `tcp/25565` / `udp/34197`.
        port: String,
        /// Close only the exposure scoped to this network; omit to close every scope of the port.
        #[arg(long)]
        net: Option<String>,
        /// The guild `--net` belongs to, when two of your guilds share the role name.
        #[arg(long, requires = "net")]
        guild: Option<String>,
        /// Close only the own-devices exposure of this port.
        #[arg(long, conflicts_with = "net")]
        own_devices: bool,
    },
    /// List the ports this device currently exposes, and to whom.
    Exposes,
    /// Start a Discord login: prints the URL to open; the daemon finishes the binding.
    Login,
    /// Bring the mesh up (build tunnels to peers).
    Connect,
    /// Take the mesh down without stopping the daemon.
    Disconnect,
    /// Apply the staged auto-update (download → verify → swap → restart). Headless equivalent of
    /// the GUI's update button; errors if no verified update is staged.
    Update,
    /// Enable or disable peering with one of your networks.
    Net {
        /// `enable` to peer with the network again, `disable` to stop.
        action: Toggle,
        /// Network name, as shown by `ctl status`.
        network: String,
    },
    /// Turn peering with your own other devices (regardless of networks) on or off.
    OwnDevices {
        /// `on` to always peer with your own devices, `off` to peer only via shared networks.
        action: OnOff,
    },
    /// Locally block a peer's owner (all their devices) by handle — drops them from the mesh.
    Block {
        /// Discord handle of the person to block, as shown by `ctl status`.
        user: String,
    },
    /// Un-block a previously-blocked user by handle.
    Unblock {
        /// Discord handle to un-block, as shown in `ctl status`'s blocked list.
        user: String,
    },
}

/// `ctl net` action.
#[derive(Clone, Copy, ValueEnum)]
enum Toggle {
    Enable,
    Disable,
}

/// `ctl own-devices` action.
#[derive(Clone, Copy, ValueEnum)]
enum OnOff {
    On,
    Off,
}

fn main() -> anyhow::Result<()> {
    // The Windows service subcommands run *outside* a tokio runtime: `service run` hands the thread
    // to the SCM dispatcher (which builds its own runtime), and install/uninstall are synchronous
    // SCM calls with plain stdout output. Dispatch it before clap so it never enters the runtime.
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("service") {
        return service::main();
    }

    let cli = Cli::parse();

    // An explicit `--log-file` wins; otherwise fall back to the config's `log_file` (resolved under
    // its state_dir). The config is peeked read-only here — a missing/bad one just means no file
    // logging, and the command's own config load surfaces any real error.
    let log_file = match &cli.log_file {
        Some(p) => Some(std::path::PathBuf::from(p)),
        None => config_log_file(cli.config.as_deref()),
    };

    // Two independent sinks rather than one tee'd writer: stdout keeps its ANSI colours while the
    // optional log file stays plain text — a single writer can't hold both ANSI settings at once.
    {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            // boringtun WARN-spams HANDSHAKE(REKEY_TIMEOUT) every ~5s while retrying a handshake
            // with a peer whose device is down — not actionable; reachability is surfaced in status.
            .unwrap_or_else(|_| "info,defguard_boringtun::noise::timers=error".into());
        let stdout_layer = tracing_subscriber::fmt::layer();
        let file_layer = log_file
            .as_deref()
            .map(|path| -> anyhow::Result<_> {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .with_context(|| format!("opening log file {}", path.display()))?;
                // Dup'd per event (`try_clone`) so the subscriber needs no lock.
                Ok(tracing_subscriber::fmt::layer()
                    .with_ansi(false)
                    .with_writer(move || file.try_clone().expect("clone log file handle")))
            })
            .transpose()?;
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .with(file_layer)
            .init();
    }

    // Everything else runs on a multi-threaded runtime (as `#[tokio::main]` did before).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    let result = rt.block_on(async_main(cli));
    // Bound process exit. reqwest's default DNS resolver runs `getaddrinfo` on tokio's *blocking*
    // pool, and a blocking thread can't be cancelled — so a lookup still in flight when we shut down
    // (e.g. a coordinator/STUN resolve interrupted by Ctrl-C) would make the runtime's `Drop` wait on
    // it for the OS resolver timeout (~tens of seconds on Windows), hanging exit long after the
    // daemon already reverted the interface/firewall/DNS. Abandon such stragglers after a short grace.
    rt.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    // `--config`/`--token` are top-level args shared by every arm: the first names the config (and
    // hence the control socket), the second overrides the config's `enrollment_key`.
    let Cli {
        cmd,
        config,
        token,
        log_file: _,
    } = cli;
    match cmd {
        Some(Cmd::WgSmoke { ifname }) => wg_smoke(&ifname),
        Some(Cmd::WgKeygen) => {
            let (priv_k, pub_k) = common::crypto::gen_wg_keypair();
            println!("{} {}", base64_std(&priv_k), base64_std(&pub_k));
            Ok(())
        }
        Some(Cmd::WgNode {
            iface,
            priv_b64,
            port,
            addr,
            peer_pub_b64,
            peer_ep,
            peer_allowed,
            hold_secs,
        }) => wg_node(
            &iface,
            &priv_b64,
            port,
            &addr,
            &peer_pub_b64,
            peer_ep,
            &peer_allowed,
            hold_secs,
        ),
        Some(Cmd::DnsServe { bind, name, ip }) => {
            // Dev/test: serve a single `<name> <ip>` on `<bind>` from the `.unity.internal` resolver.
            let zone = dns::empty_zone();
            zone.write()
                .await
                .insert(name.trim_end_matches('.').to_ascii_lowercase(), ip);
            let sock = tokio::net::UdpSocket::bind(bind).await?;
            dns::serve(sock, zone).await
        }
        Some(Cmd::ResolverInstall { iface, server }) => {
            // Dev/test: drive this platform's ResolverHook.
            let hook = resolver::platform_hook()
                .ok_or_else(|| anyhow::anyhow!("no OS resolver backend on this platform"))?;
            hook.install(&iface, server)
        }
        Some(Cmd::ResolverRevert { iface }) => {
            let hook = resolver::platform_hook()
                .ok_or_else(|| anyhow::anyhow!("no OS resolver backend on this platform"))?;
            hook.revert(&iface)
        }
        Some(Cmd::Run) => {
            let cfg = load_config(config, token)?;
            // Latch the shutdown signal so the daemon runs its teardown (revert interface/firewall/
            // DNS, withdraw presence) rather than being hard-killed: Ctrl-C (SIGINT) everywhere, plus
            // SIGTERM on unix — what `systemctl stop` / a container runtime sends.
            let (trigger, shutdown) = shutdown::channel();
            tokio::spawn(async move {
                wait_for_shutdown_signal().await;
                trigger.trigger();
            });
            match daemon::run(cfg, shutdown).await? {
                daemon::RunOutcome::Stopped => Ok(()),
                // An auto-update swapped the binary and the daemon tore down fully; re-exec (same PID)
                // onto the new engine so the update lands no matter how we were launched. `exec` only
                // returns on failure — fall back to a clean exit so a supervisor can relaunch us.
                #[cfg(unix)]
                daemon::RunOutcome::ReExec(plan) => {
                    let err = plan.exec();
                    tracing::error!("re-exec into the updated engine failed: {err}; exiting");
                    std::process::exit(0);
                }
                // Windows interactive `run` (not the service): the binary was swapped in place, so
                // relaunch it as a fresh process to land the update. (The service path hands the
                // restart to the SCM instead — see `service::run_service`.)
                #[cfg(windows)]
                daemon::RunOutcome::RestartService => {
                    let exe = std::env::current_exe()?;
                    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
                    std::process::Command::new(exe)
                        .args(args)
                        .spawn()
                        .context("relaunching the updated engine")?;
                    Ok(())
                }
            }
        }
        Some(Cmd::Ctl { sub }) => ctl(sub, config).await,
        // Uninstall reads an existing deployment; unlike `run`/`login` it must never bootstrap a
        // starter config, so it loads the resolved path directly instead of via `load_config`.
        Some(Cmd::Uninstall { purge }) => {
            let path = resolve_existing_config(config)?;
            let cfg = Config::load(&path)
                .with_context(|| format!("loading config {}", path.display()))?;
            uninstall(cfg, purge).await
        }
        Some(Cmd::Login) => login(load_config(config, token)?).await,
        None => register_once(config, token).await,
    }
}

/// Wait for a process-termination signal: Ctrl-C (SIGINT) on every platform, plus SIGTERM on unix —
/// the signal `systemctl stop`, `docker stop`, and most service managers send. Returns once either
/// fires. On Windows, `ctrl_c()` also covers console-close; the SCM service path handles Stop itself
/// (see `service.rs`), so this console path is only reached by an interactive `run`.
#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            // Can't register SIGTERM (unusual) — fall back to Ctrl-C only rather than never shutting.
            tracing::warn!("cannot listen for SIGTERM ({e}); handling Ctrl-C only");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}

/// Non-unix: Ctrl-C (which on Windows also fires on console close).
#[cfg(not(unix))]
async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Bare invocation (register-once): register with the coordinator, verify + pin the trust anchor,
/// and print the resulting IP + hostname.
async fn register_once(config: Option<String>, token: Option<String>) -> anyhow::Result<()> {
    let cfg = load_config(config, token)?;

    let (wg_priv, wg_pubkey) = keys::load_or_generate_keypair(&cfg.state_dir)?;
    let possession_proof = coord::enroll_pubkey(&cfg.coordinator)
        .await
        .ok()
        .map(|ep| common::crypto::enroll_proof(&wg_priv, &ep));

    let (_resp, device) = coord::register(
        &cfg.coordinator,
        &cfg.state_dir,
        coord::CoordReq {
            wg_pubkey,
            device_name: cfg.device_name(),
            endpoint: cfg.endpoint,
            enrollment_key: cfg.enrollment_key.clone(),
            device_token: keys::load_token(&cfg.state_dir),
            possession_proof,
            since: None,
            disabled_networks: Vec::new(),
            observed: Vec::new(),
            supersede: keys::load_token(&cfg.state_dir),
            paused: false,
            peer_own_devices: true, // own-device peering: default on for the one-shot CLI paths
            relay: coord::RelayReport::default(),
            ice: Vec::new(),
            held: Vec::new(),
        },
    )
    .await?;
    // `register` pins/verifies the anchor internally (trust-on-first-use, then rotation-chain).

    match device {
        None => tracing::warn!("registered, but hold no networks (no roles)"),
        Some(d) => {
            println!("verified device:");
            println!(
                "  {:<16} {:<44} [{} · networks: {}]",
                d.wg_ip,
                d.hostname,
                d.community_name,
                d.networks.join(", ")
            );
        }
    }
    Ok(())
}

/// `uninstall [config] [--purge]` — un-enroll this device at the coordinator (so its row doesn't
/// linger until presence-timeout) and, with `--purge`, wipe all local state. Host mutations (the WG
/// interface, firewall, DNS) are reverted by the daemon's own clean shutdown, so this only needs the
/// coordinator + disk. Un-enroll is best-effort: reads the persisted token and asks the coordinator
/// to drop this device; a re-key on any later run would supersede it anyway, so a failure here just
/// leaves an orphaned row to expire.
async fn uninstall(cfg: Config, purge: bool) -> anyhow::Result<()> {
    match keys::load_token(&cfg.state_dir) {
        Some(token) => {
            let op = common::api::ManageOp::Remove {
                device_name: cfg.device_name(),
            };
            match coord::manage(&cfg.coordinator, token, op).await {
                Ok(_) => println!("Un-enrolled device at the coordinator."),
                Err(e) => eprintln!("warning: coordinator un-enroll failed (continuing): {e:#}"),
            }
        }
        None => println!("No local token — nothing to un-enroll."),
    }
    if purge {
        keys::purge_state(&cfg.state_dir)?;
        println!("Wiped local state at {}.", cfg.state_dir.display());
    } else {
        println!(
            "Kept local state (device identity) at {} — pass --purge to wipe it.",
            cfg.state_dir.display()
        );
    }
    Ok(())
}

/// Where a `-c`-less invocation looks for its config, in order: the working directory first (so a
/// dev tree and `scripts/*` keep working unchanged), then the location this platform's package
/// installs to.
///
/// Deliberately **not** searched: `$HOME`/`$XDG_CONFIG_HOME`. The engine runs as root, and `sudo`
/// commonly leaves `HOME` pointing at the invoking user — a home-dir candidate would let any local
/// unprivileged user plant a config naming their own `coordinator` and have the root daemon adopt
/// it. A per-user config buys nothing for a system daemon.
fn config_search_paths() -> Vec<std::path::PathBuf> {
    let mut paths = vec![std::path::PathBuf::from("engine.toml")];
    #[cfg(windows)]
    {
        // Canonical home: %ProgramData%\UnityLAN\engine.toml, where the service writes/migrates it.
        if let Some(pd) = std::env::var_os("ProgramData") {
            paths.push(
                std::path::Path::new(&pd)
                    .join("UnityLAN")
                    .join("engine.toml"),
            );
        }
        // Legacy: beside the exe, where installs before the ProgramData move dropped it. Searched
        // last so a migrated ProgramData config wins over a leftover next to the exe.
        if let Some(dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
        {
            paths.push(dir.join("engine.toml"));
        }
    }
    #[cfg(not(windows))]
    paths.push(std::path::PathBuf::from("/etc/unitylan/engine.toml"));
    paths
}

/// The first candidate that exists, or `None` when the search came up empty.
fn first_existing(paths: &[std::path::PathBuf]) -> Option<std::path::PathBuf> {
    paths.iter().find(|p| p.is_file()).cloned()
}

/// Peek the config (read-only, no bootstrap) for its resolved `log_file`, so the subscriber can be
/// set up before any command loads the config for real. Best-effort: an absent config on the search
/// path, or one that won't parse, simply yields no file logging.
fn config_log_file(config_arg: Option<&str>) -> Option<std::path::PathBuf> {
    let path = match config_arg {
        Some(p) => std::path::PathBuf::from(p),
        None => first_existing(&config_search_paths())?,
    };
    Config::load(&path).ok()?.log_file_path()
}

/// Resolve the config an invocation reads. An explicit `-c` is taken as-is (so a typo'd path fails
/// loudly rather than silently falling back to an unrelated deployment); otherwise the search path
/// applies. Fails with the list of places tried when nothing turned up — used by the commands that
/// need an existing deployment (`ctl`, `uninstall`) rather than the ones that bootstrap one.
fn resolve_existing_config(arg: Option<String>) -> anyhow::Result<std::path::PathBuf> {
    match arg {
        Some(p) => Ok(std::path::PathBuf::from(p)),
        None => pick_config(&config_search_paths()),
    }
}

/// The first candidate that exists, or an error naming every place that was tried.
fn pick_config(candidates: &[std::path::PathBuf]) -> anyhow::Result<std::path::PathBuf> {
    first_existing(candidates).ok_or_else(|| {
        let tried: Vec<String> = candidates.iter().map(|p| p.display().to_string()).collect();
        anyhow::anyhow!(
            "no engine.toml found (looked in: {}); pass -c <path>",
            tried.join(", ")
        )
    })
}

/// Load config from an optional CLI path. An explicit path must exist, as does one found on the
/// search path; only when the search comes up empty is `./engine.toml` created with starter values,
/// so a bare `run`/`login` in a fresh tree still bootstraps a dev config.
fn load_config(arg: Option<String>, token_override: Option<String>) -> anyhow::Result<Config> {
    let mut cfg = match arg {
        Some(p) => {
            Config::load(std::path::Path::new(&p)).with_context(|| format!("loading config {p}"))?
        }
        None => match first_existing(&config_search_paths()) {
            Some(p) => {
                // Which file an implicit lookup landed on is not obvious from the command line.
                tracing::info!(config = %p.display(), "using config");
                Config::load(&p).with_context(|| format!("loading config {}", p.display()))?
            }
            None => Config::load_or_init(std::path::Path::new("engine.toml"))
                .with_context(|| "loading config engine.toml".to_string())?,
        },
    };
    // A `--token` on the command line wins over the config file, so a headless box can enroll
    // without persisting the bearer secret to disk.
    if let Some(t) = token_override {
        cfg.enrollment_key = Some(t);
    }
    Ok(cfg)
}

/// `login <config.toml>` — interactive Discord login. Prints the authorize URL to open, then
/// polls register until the coordinator has bound this device to the authenticated user.
async fn login(cfg: Config) -> anyhow::Result<()> {
    let (wg_priv, wg_pub) = keys::load_or_generate_keypair(&cfg.state_dir)?;
    let login = oauth::begin(&cfg.coordinator, &cfg.oauth_redirect, wg_pub).await?;
    println!(
        "Open this URL in your browser to log in with Discord:\n\n  {}\n",
        login.authorize_url
    );
    println!("Waiting for authorization (up to 5 minutes)...");

    // complete() waits for the browser redirect, does the PKCE exchange, and returns once the
    // coordinator has bound our pubkey to the authenticated user.
    tokio::time::timeout(std::time::Duration::from_secs(300), login.complete())
        .await
        .map_err(|_| {
            anyhow::anyhow!("login timed out; re-run `login` and complete the browser step")
        })??;

    // The binding is now in place, so a register succeeds and confirms the device.
    let possession_proof = coord::enroll_pubkey(&cfg.coordinator)
        .await
        .ok()
        .map(|ep| common::crypto::enroll_proof(&wg_priv, &ep));
    let (_, device) = coord::register(
        &cfg.coordinator,
        &cfg.state_dir,
        coord::CoordReq {
            wg_pubkey: wg_pub,
            device_name: cfg.device_name(),
            endpoint: cfg.endpoint,
            enrollment_key: None,
            device_token: keys::load_token(&cfg.state_dir),
            possession_proof,
            since: None,
            disabled_networks: Vec::new(),
            observed: Vec::new(),
            supersede: None, // login binds a fresh identity; nothing to supersede
            paused: false,
            peer_own_devices: true, // own-device peering: default on for the one-shot CLI paths
            relay: coord::RelayReport::default(),
            ice: Vec::new(),
            held: Vec::new(),
        },
    )
    .await?;
    match device {
        Some(dev) => println!("Logged in ✓  {} — {}", dev.wg_ip, dev.hostname),
        None => println!("Logged in ✓  (no networks yet — join a role in Discord)"),
    }
    Ok(())
}

/// Talk to a running daemon over its control socket. The global `-c/--config` resolves the socket
/// for every subcommand; see [`CtlCmd`].
async fn ctl(sub: CtlCmd, config: Option<String>) -> anyhow::Result<()> {
    use common::api::ManageOp;

    // The daemon must already be configured, so an absent config is an error here rather than a
    // cue to write a starter one.
    let cfg_path = resolve_existing_config(config)?;
    let socket = Config::load(&cfg_path)
        .with_context(|| format!("loading config {}", cfg_path.display()))?
        .control_name();

    match sub {
        CtlCmd::Status => {
            let report = control::client_status(&socket).await?;
            if report.needs_login {
                println!("not logged in — run `unitylan-engine ctl login`");
            }
            if !report.connected {
                println!("mesh: disconnected — run `unitylan-engine ctl connect`");
            }
            match &report.device {
                None => println!("not joined to any network"),
                Some(d) => {
                    let primary = if d.is_primary { " [primary]" } else { "" };
                    println!("device:  {} {}{}", d.wg_ip, d.hostname, primary);
                    println!("networks: {}", d.networks.join(", "));
                }
            }
            if let Some(v) = &report.update_available {
                let staged = if report.update_ready {
                    " (staged — run `unitylan-engine ctl update`)"
                } else {
                    ""
                };
                println!("update:  v{v} available{staged}");
            }
            println!("peers ({}):", report.peers.len());
            for p in &report.peers {
                let ep = p
                    .endpoint
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "-".into());
                let nat = match p.reach {
                    common::control::PeerReach::Direct => "",
                    common::control::PeerReach::Punching => "  [hole-punching…]",
                    common::control::PeerReach::Unreachable => {
                        "  [unreachable: no direct path — symmetric NAT, a blocked UDP port, or no relay]"
                    }
                    common::control::PeerReach::Relayed => "  [relayed]",
                    common::control::PeerReach::Ice => "  [ice]",
                };
                println!("  {:<16} {:<40} {}{}", p.wg_ip, p.hostname, ep, nat);
            }
            if !report.blocked.is_empty() {
                println!("blocked ({}):", report.blocked.len());
                for b in &report.blocked {
                    println!("  {} (id {})", b.username, b.user_id);
                }
            }
            Ok(())
        }
        CtlCmd::Devices => print_devices(control::client_manage(&socket, ManageOp::List).await?),
        CtlCmd::Rename { new_name } => {
            print_devices(control::client_manage(&socket, ManageOp::Rename { new_name }).await?)
        }
        CtlCmd::SetPrimary { device } => print_devices(
            control::client_manage(
                &socket,
                ManageOp::SetPrimary {
                    device_name: device,
                },
            )
            .await?,
        ),
        CtlCmd::Remove { device } => print_devices(
            control::client_manage(
                &socket,
                ManageOp::Remove {
                    device_name: device,
                },
            )
            .await?,
        ),
        CtlCmd::Expose {
            port,
            net,
            guild,
            own_devices,
        } => {
            let (proto, port) = parse_port(&port)?;
            let scope = expose_scope(net, guild, own_devices);
            print_exposed(
                control::client_expose(
                    &socket,
                    common::control::ExposeOp::Add { proto, port, scope },
                )
                .await?,
            )
        }
        CtlCmd::Unexpose {
            port,
            net,
            guild,
            own_devices,
        } => {
            let (proto, port) = parse_port(&port)?;
            // No scope named at all still means "close every scope of this port".
            let scope = match (net, own_devices) {
                (None, false) => common::control::RemoveScope::All,
                (net, own) => common::control::RemoveScope::Exact(expose_scope(net, guild, own)),
            };
            print_exposed(
                control::client_expose(
                    &socket,
                    common::control::ExposeOp::Remove { proto, port, scope },
                )
                .await?,
            )
        }
        CtlCmd::Exposes => {
            print_exposed(control::client_expose(&socket, common::control::ExposeOp::List).await?)
        }
        CtlCmd::Login => {
            let resp = control::client_login(&socket).await?;
            println!(
                "Open this URL to log in with Discord:\n\n  {}\n",
                resp.authorize_url
            );
            println!("The daemon binds this device once you complete the browser step.");
            Ok(())
        }
        CtlCmd::Connect => {
            let resp = control::client_set_connected(&socket, true).await?;
            println!("{}", resp.message);
            Ok(())
        }
        CtlCmd::Update => {
            let resp = control::client_apply_update(&socket).await?;
            println!("{} (v{})", resp.message, resp.version);
            Ok(())
        }
        CtlCmd::Disconnect => {
            let resp = control::client_set_connected(&socket, false).await?;
            println!("{}", resp.message);
            Ok(())
        }
        CtlCmd::Net { action, network } => {
            let enabled = matches!(action, Toggle::Enable);
            let status = control::client_status(&socket).await?;
            let net = status
                .networks
                .iter()
                .find(|n| n.name == network)
                .ok_or_else(|| {
                    let names: Vec<&str> =
                        status.networks.iter().map(|n| n.name.as_str()).collect();
                    anyhow::anyhow!("no network named '{network}' (yours: {})", names.join(", "))
                })?;
            let resp =
                control::client_set_network(&socket, net.guild_id, net.role_id, enabled).await?;
            println!("{}", resp.message);
            for n in &resp.networks {
                let state = if n.enabled { "on" } else { "off" };
                println!("  {} [{}]", n.name, state);
            }
            Ok(())
        }
        CtlCmd::OwnDevices { action } => {
            let enabled = matches!(action, OnOff::On);
            let status = control::client_set_own_device_peering(&socket, enabled).await?;
            println!(
                "own-device peering {} (locally; syncs to coordinator on next refresh)",
                if status.peer_own_devices { "on" } else { "off" }
            );
            Ok(())
        }
        CtlCmd::Block { user } => {
            // Resolve the handle to a user_id from the live peer set (a block acts on the person).
            let status = control::client_status(&socket).await?;
            let peer = status
                .peers
                .iter()
                .find(|p| p.username == user)
                .ok_or_else(|| anyhow::anyhow!("no peer with handle '{user}'"))?;
            let updated =
                control::client_set_blocked(&socket, peer.user_id, Some(peer.username.clone()))
                    .await?;
            println!("blocked {user} ({} user(s) blocked)", updated.blocked.len());
            Ok(())
        }
        CtlCmd::Unblock { user } => {
            // Resolve from the blocked list, so an offline (filtered-out) user can still be un-blocked.
            let status = control::client_status(&socket).await?;
            let blocked = status
                .blocked
                .iter()
                .find(|b| b.username == user)
                .ok_or_else(|| anyhow::anyhow!("no blocked user with handle '{user}'"))?;
            control::client_set_blocked(&socket, blocked.user_id, None).await?;
            println!("un-blocked {user}");
            Ok(())
        }
    }
}

/// Parse a `ctl expose` port argument: `25565` (tcp default) or `udp/34197` / `tcp/25565`.
fn parse_port(arg: &str) -> anyhow::Result<(common::control::Proto, u16)> {
    use common::control::Proto;
    let (proto, port) = match arg.split_once('/') {
        Some((p, n)) => {
            let proto = match p.to_ascii_lowercase().as_str() {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                other => anyhow::bail!("bad protocol '{other}' (use tcp or udp)"),
            };
            (proto, n)
        }
        None => (Proto::Tcp, arg),
    };
    Ok((
        proto,
        port.parse()
            .map_err(|_| anyhow::anyhow!("bad port '{port}'"))?,
    ))
}

/// The scope named by an `expose`/`unexpose` invocation. The two flags are mutually exclusive at
/// the clap level, so `--own-devices` and a network name can't both arrive.
fn expose_scope(
    net: Option<String>,
    guild: Option<String>,
    own_devices: bool,
) -> common::control::ExposeScope {
    match (net, own_devices) {
        (_, true) => common::control::ExposeScope::OwnDevices,
        // A name, resolved to `(guild_id, role_id)` by the engine against the caller's held
        // networks — refusing if two guilds share the role name rather than guessing.
        (Some(n), false) => common::control::ExposeScope::Unresolved { guild, name: n },
        (None, false) => common::control::ExposeScope::AllPeers,
    }
}

fn print_exposed(resp: common::control::ExposeResp) -> anyhow::Result<()> {
    println!("{}", resp.message);
    for e in &resp.exposed {
        let idle = if e.active { "" } else { "  [no peers online]" };
        println!("  {}/{} ({}){}", e.proto.as_str(), e.port, e.label, idle);
    }
    Ok(())
}

fn print_devices(resp: common::api::ManageResp) -> anyhow::Result<()> {
    println!("{}", resp.message);
    for d in &resp.devices {
        let primary = if d.is_primary { " [primary]" } else { "" };
        let this = if d.is_self { " (this device)" } else { "" };
        println!("  {}{}{}", d.device_name, primary, this);
    }
    Ok(())
}

/// Bring up a WireGuard interface, add a dummy peer, tear down. Requires CAP_NET_ADMIN.
fn wg_smoke(ifname: &str) -> anyhow::Result<()> {
    use std::net::Ipv4Addr;
    use wg::{IfaceConfig, PeerConfig};

    let (priv_k, pub_k) = common::crypto::gen_wg_keypair();
    println!("wg-smoke: iface={ifname} pubkey={}", base64_std(&pub_k));

    let mut backend = wg::new_backend(ifname)?;
    let cfg = IfaceConfig {
        private_key: priv_k,
        addresses: vec![(Ipv4Addr::new(100, 64, 42, 7), 32)],
        listen_port: 51820,
    };
    println!("  up() ...");
    backend.up(&cfg)?;
    println!("  interface up. adding dummy peer ...");
    backend.set_peer(&PeerConfig {
        public_key: [2u8; 32],
        allowed_ips: vec![(Ipv4Addr::new(100, 64, 42, 1), 32)],
        endpoint: Some("203.0.113.5:51820".parse().unwrap()),
        keepalive: Some(25),
    })?;
    println!("  peer added. tearing down ...");
    backend.down()?;
    println!("  down. OK ✓");
    Ok(())
}

fn base64_std(b: &[u8]) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.encode(b)
}

fn b64_key(s: &str) -> anyhow::Result<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD
        .decode(s)?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("key is not 32 bytes"))
}

fn parse_cidr(s: &str) -> anyhow::Result<(std::net::Ipv4Addr, u8)> {
    let (ip, cidr) = s
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("bad CIDR {s}"))?;
    Ok((ip.parse()?, cidr.parse()?))
}

/// Bring up one WG node from CLI args, hold it up, then tear down. For the netns tunnel test.
#[allow(clippy::too_many_arguments)]
fn wg_node(
    iface: &str,
    priv_b64: &str,
    port: u16,
    addr: &str,
    peer_pub_b64: &str,
    peer_ep: SocketAddr,
    peer_allowed: &str,
    hold: u64,
) -> anyhow::Result<()> {
    use std::io::Write;
    use std::time::Duration;
    use wg::{IfaceConfig, PeerConfig};

    let priv_k = b64_key(priv_b64)?;
    let addr = parse_cidr(addr)?;
    let peer_pub = b64_key(peer_pub_b64)?;
    let peer_allowed = parse_cidr(peer_allowed)?;

    let mut backend = wg::new_backend(iface)?;
    backend.up(&IfaceConfig {
        private_key: priv_k,
        addresses: vec![addr],
        listen_port: port,
    })?;
    backend.set_peer(&PeerConfig {
        public_key: peer_pub,
        allowed_ips: vec![peer_allowed],
        endpoint: Some(peer_ep),
        keepalive: Some(25),
    })?;
    println!("READY {iface}");
    std::io::stdout().flush().ok();
    std::thread::sleep(Duration::from_secs(hold));
    backend.down()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    #[test]
    fn search_path_prefers_the_working_directory_then_the_installed_location() {
        let paths = config_search_paths();
        assert_eq!(paths[0], std::path::Path::new("engine.toml"));
        assert!(paths.len() > 1, "no installed location to fall back to");
        #[cfg(not(windows))]
        assert!(paths.contains(&std::path::PathBuf::from("/etc/unitylan/engine.toml")));
        #[cfg(windows)]
        {
            // The ProgramData home is canonical and must be searched before the legacy beside-exe
            // path, so a config migrated to ProgramData wins over a leftover next to the exe.
            let program_data = paths
                .iter()
                .position(|p| p.to_string_lossy().contains(r"UnityLAN\engine.toml"))
                .expect("ProgramData\\UnityLAN config on the search path");
            let exe_dir = std::env::current_exe().unwrap();
            let legacy = paths
                .iter()
                .position(|p| p.parent() == exe_dir.parent())
                .expect("legacy beside-exe config on the search path");
            assert!(
                program_data < legacy,
                "ProgramData must be searched before the legacy beside-exe path"
            );
        }
    }

    /// The engine runs as root, so a config planted in a user-writable home directory must never
    /// be picked up implicitly — it would name the coordinator the daemon trusts.
    #[test]
    fn search_path_never_reaches_into_a_home_directory() {
        for p in config_search_paths() {
            let s = p.to_string_lossy().to_lowercase();
            assert!(
                !s.contains("/home/") && !s.contains("/users/") && !s.contains(".config"),
                "home-directory candidate on the search path: {s}"
            );
        }
    }

    #[test]
    fn first_existing_skips_missing_and_takes_the_earliest_hit() {
        let dir = TempDir::new("cfg-search");
        let missing = dir.join("absent.toml");
        let first = dir.join("first.toml");
        let second = dir.join("second.toml");
        std::fs::write(&first, "").unwrap();
        std::fs::write(&second, "").unwrap();

        assert_eq!(
            first_existing(&[missing.clone(), first.clone(), second]),
            Some(first)
        );
        assert_eq!(first_existing(&[missing]), None);
    }

    /// An explicit `-c` is never second-guessed: a typo'd path must fail loudly rather than fall
    /// through to whatever deployment happens to be installed on the box.
    #[test]
    fn an_explicit_path_is_taken_as_is_even_when_it_does_not_exist() {
        let p = resolve_existing_config(Some("/nonexistent/typo.toml".into())).unwrap();
        assert_eq!(p, std::path::Path::new("/nonexistent/typo.toml"));
    }

    /// `--log-file` is a global flag, so it must parse whether it comes before or after the
    /// subcommand — the two spots a user naturally reaches for.
    #[test]
    fn log_file_is_accepted_on_either_side_of_the_subcommand() {
        let before = Cli::parse_from(["unitylan-engine", "--log-file", "/var/log/x", "run"]);
        assert_eq!(before.log_file.as_deref(), Some("/var/log/x"));
        let after = Cli::parse_from(["unitylan-engine", "run", "--log-file", "/var/log/x"]);
        assert_eq!(after.log_file.as_deref(), Some("/var/log/x"));
    }

    /// Coming up empty has to say where it looked, or the user has no idea what to fix.
    #[test]
    fn an_empty_search_lists_every_place_it_tried() {
        let dir = TempDir::new("cfg-empty");
        let candidates = vec![dir.join("a.toml"), dir.join("b.toml")];
        let msg = format!("{:#}", pick_config(&candidates).unwrap_err());
        assert!(msg.contains("a.toml") && msg.contains("b.toml"), "{msg}");
        assert!(msg.contains("-c"), "{msg}");
    }
}
