//! UnityLAN engine (M1, headless): register with the coordinator, verify the signed
//! attestations, pin the trust anchor, and print the resulting IPs + hostnames.

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
mod ping;
mod relay;
mod resolver;
#[cfg(windows)]
mod service;
mod shutdown;
mod util;
mod wg;

use std::net::{Ipv4Addr, SocketAddr};

use anyhow::Context;
use clap::{Parser, Subcommand};

use crate::config::Config;

/// UnityLAN engine — headless data-plane daemon.
#[derive(Parser)]
#[command(name = "unitylan-engine", version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
    /// Bare invocation (register-once): config path (defaults to engine.toml).
    config: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the engine daemon (console mode; Ctrl-C shuts down).
    Run { config: Option<String> },
    /// Interactive Discord login, then confirm this device.
    Login { config: Option<String> },
    /// Talk to a running daemon over its control socket.
    Ctl {
        #[command(subcommand)]
        sub: CtlCmd,
    },
    /// Print a fresh WireGuard keypair as `priv pub` (base64).
    WgKeygen,
    /// Bring a WG iface up, add a dummy peer, tear down (needs CAP_NET_ADMIN).
    WgSmoke {
        #[arg(default_value = "unl-smoke")]
        ifname: String,
    },
    /// Bring up one WG node, hold it up, then tear down (netns tunnel test).
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
    DnsServe {
        bind: SocketAddr,
        name: String,
        ip: Ipv4Addr,
    },
    /// Install this platform's OS resolver hook.
    ResolverInstall { iface: String, server: SocketAddr },
    /// Revert this platform's OS resolver hook.
    ResolverRevert { iface: String },
}

/// `ctl` subcommands. Each takes the config path first (defaults to engine.toml where the
/// subcommand has no other required argument).
#[derive(Subcommand)]
enum CtlCmd {
    Status {
        #[arg(default_value = "engine.toml")]
        config: String,
    },
    Devices {
        #[arg(default_value = "engine.toml")]
        config: String,
    },
    Rename {
        config: String,
        new_name: String,
    },
    SetPrimary {
        config: String,
        device: String,
    },
    Remove {
        config: String,
        device: String,
    },
    Expose {
        config: String,
        port: String,
        net: Option<String>,
    },
    Unexpose {
        config: String,
        port: String,
    },
    Exposes {
        #[arg(default_value = "engine.toml")]
        config: String,
    },
    Login {
        #[arg(default_value = "engine.toml")]
        config: String,
    },
    Connect {
        #[arg(default_value = "engine.toml")]
        config: String,
    },
    Disconnect {
        #[arg(default_value = "engine.toml")]
        config: String,
    },
    Net {
        config: String,
        action: String,
        network: String,
    },
    /// Locally block a peer's owner (all their devices) by handle — drops them from the mesh.
    Block {
        config: String,
        user: String,
    },
    /// Un-block a previously-blocked user by handle.
    Unblock {
        config: String,
        user: String,
    },
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

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Everything else runs on a multi-threaded runtime (as `#[tokio::main]` did before).
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building tokio runtime")?;
    rt.block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    match cli.cmd {
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
            dns::serve(bind, zone).await
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
        Some(Cmd::Run { config }) => {
            let cfg = load_config(config)?;
            // Console mode: Ctrl-C latches the shutdown signal the daemon awaits.
            let (trigger, shutdown) = shutdown::channel();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                trigger.trigger();
            });
            daemon::run(cfg, shutdown).await
        }
        Some(Cmd::Ctl { sub }) => ctl(sub).await,
        Some(Cmd::Login { config }) => login(load_config(config)?).await,
        None => register_once(cli.config).await,
    }
}

/// Bare invocation (register-once): register with the coordinator, verify + pin the trust anchor,
/// and print the resulting IP + hostname.
async fn register_once(config: Option<String>) -> anyhow::Result<()> {
    let cfg = load_config(config)?;

    let (_wg_priv, wg_pubkey) = keys::load_or_generate_keypair(&cfg.state_dir)?;

    let (resp, device) = coord::register(
        &cfg.coordinator,
        wg_pubkey,
        cfg.device_name(),
        cfg.endpoint,
        cfg.enrollment_key.clone(),
        Vec::new(),
        keys::load_token(&cfg.state_dir),
        false,
        coord::RelayReport::default(),
    )
    .await?;

    // Trust-on-first-use: pin the anchor, reject if it ever changes.
    keys::pin_anchor(&cfg.state_dir, &resp.coord_pubkey, &resp.rotation_chain)?;

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

/// Load config from an optional CLI path. An explicit path must exist; the default `engine.toml`
/// is created with starter values on first run so a bare `run`/`login` bootstraps a dev config.
fn load_config(arg: Option<String>) -> anyhow::Result<Config> {
    match arg {
        Some(p) => {
            Config::load(std::path::Path::new(&p)).with_context(|| format!("loading config {p}"))
        }
        None => Config::load_or_init(std::path::Path::new("engine.toml"))
            .with_context(|| "loading config engine.toml".to_string()),
    }
}

/// `login <config.toml>` — interactive Discord login. Prints the authorize URL to open, then
/// polls register until the coordinator has bound this device to the authenticated user.
async fn login(cfg: Config) -> anyhow::Result<()> {
    let (_wg_priv, wg_pub) = keys::load_or_generate_keypair(&cfg.state_dir)?;
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
    let (_, device) = coord::register(
        &cfg.coordinator,
        wg_pub,
        cfg.device_name(),
        cfg.endpoint,
        None,
        Vec::new(),
        None, // login binds a fresh identity; nothing to supersede
        false,
        coord::RelayReport::default(),
    )
    .await?;
    match device {
        Some(dev) => println!("Logged in ✓  {} — {}", dev.wg_ip, dev.hostname),
        None => println!("Logged in ✓  (no networks yet — join a role in Discord)"),
    }
    Ok(())
}

/// Talk to a running daemon over its control socket. Each subcommand's config path resolves the
/// socket; see [`CtlCmd`].
async fn ctl(sub: CtlCmd) -> anyhow::Result<()> {
    use common::api::ManageOp;

    // Resolve the control socket for a subcommand's config path.
    let socket_for = |cfg_path: &str| -> anyhow::Result<String> {
        Ok(Config::load(std::path::Path::new(cfg_path))
            .with_context(|| format!("loading config {cfg_path}"))?
            .control_name())
    };

    match sub {
        CtlCmd::Status { config } => {
            let socket = socket_for(&config)?;
            let report = control::client_status(&socket).await?;
            if report.needs_login {
                println!("not logged in — run `unitylan ctl login {config}`");
            }
            if !report.connected {
                println!("mesh: disconnected — run `unitylan ctl connect {config}`");
            }
            match &report.device {
                None => println!("not joined to any network"),
                Some(d) => {
                    let primary = if d.is_primary { " [primary]" } else { "" };
                    println!("device:  {} {}{}", d.wg_ip, d.hostname, primary);
                    println!("networks: {}", d.networks.join(", "));
                }
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
                    common::control::PeerReach::Unreachable => "  [unreachable: symmetric NAT?]",
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
        CtlCmd::Devices { config } => {
            print_devices(control::client_manage(&socket_for(&config)?, ManageOp::List).await?)
        }
        CtlCmd::Rename { config, new_name } => print_devices(
            control::client_manage(&socket_for(&config)?, ManageOp::Rename { new_name }).await?,
        ),
        CtlCmd::SetPrimary { config, device } => print_devices(
            control::client_manage(
                &socket_for(&config)?,
                ManageOp::SetPrimary {
                    device_name: device,
                },
            )
            .await?,
        ),
        CtlCmd::Remove { config, device } => print_devices(
            control::client_manage(
                &socket_for(&config)?,
                ManageOp::Remove {
                    device_name: device,
                },
            )
            .await?,
        ),
        CtlCmd::Expose { config, port, net } => {
            let (proto, port) = parse_port(&port)?;
            print_exposed(
                control::client_expose(
                    &socket_for(&config)?,
                    common::control::ExposeOp::Add { proto, port, net },
                )
                .await?,
            )
        }
        CtlCmd::Unexpose { config, port } => {
            let (proto, port) = parse_port(&port)?;
            print_exposed(
                control::client_expose(
                    &socket_for(&config)?,
                    common::control::ExposeOp::Remove { proto, port },
                )
                .await?,
            )
        }
        CtlCmd::Exposes { config } => print_exposed(
            control::client_expose(&socket_for(&config)?, common::control::ExposeOp::List).await?,
        ),
        CtlCmd::Login { config } => {
            let resp = control::client_login(&socket_for(&config)?).await?;
            println!(
                "Open this URL to log in with Discord:\n\n  {}\n",
                resp.authorize_url
            );
            println!("The daemon binds this device once you complete the browser step.");
            Ok(())
        }
        CtlCmd::Connect { config } => {
            let resp = control::client_set_connected(&socket_for(&config)?, true).await?;
            println!("{}", resp.message);
            Ok(())
        }
        CtlCmd::Disconnect { config } => {
            let resp = control::client_set_connected(&socket_for(&config)?, false).await?;
            println!("{}", resp.message);
            Ok(())
        }
        CtlCmd::Net {
            config,
            action,
            network,
        } => {
            let socket = socket_for(&config)?;
            let enabled = match action.as_str() {
                "enable" => true,
                "disable" => false,
                _ => anyhow::bail!("use 'enable' or 'disable'"),
            };
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
        CtlCmd::Block { config, user } => {
            let socket = socket_for(&config)?;
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
        CtlCmd::Unblock { config, user } => {
            let socket = socket_for(&config)?;
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

fn print_exposed(resp: common::control::ExposeResp) -> anyhow::Result<()> {
    println!("{}", resp.message);
    for e in &resp.exposed {
        let scope = e
            .net
            .as_deref()
            .map(|n| format!(" (net: {n})"))
            .unwrap_or_default();
        println!("  {}/{}{}", e.proto.as_str(), e.port, scope);
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
