//! UnityLAN engine (M1, headless): register with the coordinator, verify the signed
//! attestations, pin the trust anchor, and print the resulting IPs + hostnames.

mod config;
mod control;
mod coord;
mod daemon;
mod dns;
mod keys;
mod wg;

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

    let arg1 = std::env::args().nth(1).unwrap_or_default();
    if arg1 == "wg-smoke" {
        let ifname = std::env::args().nth(2).unwrap_or_else(|| "unl-smoke".to_string());
        return wg_smoke(&ifname);
    }
    if arg1 == "wg-keygen" {
        let (priv_k, pub_k) = common::crypto::gen_wg_keypair();
        println!("{} {}", base64_std(&priv_k), base64_std(&pub_k));
        return Ok(());
    }
    if arg1 == "wg-node" {
        return wg_node();
    }
    if arg1 == "run" {
        let cfg_path = std::env::args()
            .nth(2)
            .unwrap_or_else(|| "engine.toml".to_string());
        let cfg = Config::load(std::path::Path::new(&cfg_path))
            .with_context(|| format!("loading config {cfg_path}"))?;
        return daemon::run(cfg).await;
    }
    if arg1 == "ctl" {
        return ctl().await;
    }

    let config_path = if arg1.is_empty() {
        "engine.toml".to_string()
    } else {
        arg1
    };
    let cfg = Config::load(std::path::Path::new(&config_path))
        .with_context(|| format!("loading config {config_path}"))?;

    let (_wg_priv, wg_pubkey) = keys::load_or_generate_keypair(&cfg.state_dir)?;

    let (resp, device) = coord::register(
        &cfg.coordinator,
        wg_pubkey,
        cfg.device_name(),
        cfg.endpoint,
        cfg.enrollment_key.clone(),
    )
    .await?;

    // Trust-on-first-use: pin the anchor, reject if it ever changes.
    keys::pin_anchor(&cfg.state_dir, &resp.coord_pubkey)?;

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

/// `ctl <sub> <config.toml> [arg]` — talk to a running daemon over its control socket.
/// subs: `status`, `devices`, `rename <name>`, `set-primary <device>`, `remove <device>`.
async fn ctl() -> anyhow::Result<()> {
    use common::api::ManageOp;

    let sub = std::env::args().nth(2).unwrap_or_default();
    let cfg_path = std::env::args().nth(3).unwrap_or_else(|| "engine.toml".to_string());
    let arg = std::env::args().nth(4);
    let cfg = Config::load(std::path::Path::new(&cfg_path))
        .with_context(|| format!("loading config {cfg_path}"))?;
    let socket = cfg.control_socket_path();

    let need_arg = || {
        arg.clone()
            .ok_or_else(|| anyhow::anyhow!("'{sub}' needs a device/name argument"))
    };

    match sub.as_str() {
        "status" => {
            let report = control::client_status(&socket).await?;
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
                let ep = p.endpoint.map(|e| e.to_string()).unwrap_or_else(|| "-".into());
                println!("  {:<16} {:<40} {}", p.wg_ip, p.hostname, ep);
            }
            Ok(())
        }
        "devices" => print_devices(control::client_manage(&socket, ManageOp::List).await?),
        "rename" => print_devices(
            control::client_manage(&socket, ManageOp::Rename { new_name: need_arg()? }).await?,
        ),
        "set-primary" => print_devices(
            control::client_manage(&socket, ManageOp::SetPrimary { device_name: need_arg()? })
                .await?,
        ),
        "remove" => print_devices(
            control::client_manage(&socket, ManageOp::Remove { device_name: need_arg()? }).await?,
        ),
        other => anyhow::bail!(
            "unknown ctl subcommand '{other}' (try: status, devices, rename, set-primary, remove)"
        ),
    }
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
    use wg::{IfaceConfig, PeerConfig, UserspaceBackend, WgBackend};

    let (priv_k, pub_k) = common::crypto::gen_wg_keypair();
    println!("wg-smoke: iface={ifname} pubkey={}", base64_std(&pub_k));

    let mut backend = UserspaceBackend::new(ifname)?;
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
/// args: wg-node <iface> <priv_b64> <port> <addr/cidr> <peer_pub_b64> <peer_ip:port> <peer_allowed/cidr> <hold_secs>
fn wg_node() -> anyhow::Result<()> {
    use std::io::Write;
    use std::net::SocketAddr;
    use std::time::Duration;
    use wg::{IfaceConfig, PeerConfig, UserspaceBackend, WgBackend};

    let a: Vec<String> = std::env::args().collect();
    if a.len() < 10 {
        anyhow::bail!(
            "usage: wg-node <iface> <priv_b64> <port> <addr/cidr> <peer_pub_b64> <peer_ip:port> <peer_allowed/cidr> <hold_secs>"
        );
    }
    let iface = &a[2];
    let priv_k = b64_key(&a[3])?;
    let port: u16 = a[4].parse()?;
    let addr = parse_cidr(&a[5])?;
    let peer_pub = b64_key(&a[6])?;
    let peer_ep: SocketAddr = a[7].parse()?;
    let peer_allowed = parse_cidr(&a[8])?;
    let hold: u64 = a[9].parse()?;

    let mut backend = UserspaceBackend::new(iface)?;
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
