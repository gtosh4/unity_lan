//! Userspace WireGuard backend (boringtun via defguard). Portable across Linux/Windows/macOS;
//! requires CAP_NET_ADMIN (or equivalent) to create the TUN interface.

use std::net::IpAddr;

use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::net::IpAddrMask;
use defguard_wireguard_rs::peer::Peer;
use defguard_wireguard_rs::{InterfaceConfiguration, Userspace, WGApi, WireguardInterfaceApi};

use super::{IfaceConfig, PeerConfig, WgBackend};

pub struct UserspaceBackend {
    api: WGApi<Userspace>,
    name: String,
}

/// Read the endpoint WireGuard last saw each peer send from. Empty until peers handshake.
/// boringtun's userspace uapi read is racy under load and intermittently returns EAGAIN mid-parse;
/// retry a few times so a transient failure doesn't look like "no endpoints".
pub fn read_peer_endpoints(
    ifname: &str,
) -> anyhow::Result<std::collections::HashMap<[u8; 32], std::net::SocketAddr>> {
    let api = WGApi::<Userspace>::new(ifname.to_string())?;
    let mut last_err = None;
    for _ in 0..5 {
        match api.read_interface_data() {
            Ok(host) => {
                return Ok(host
                    .peers
                    .iter()
                    .filter_map(|(k, p)| p.endpoint.map(|ep| (k.as_array(), ep)))
                    .collect())
            }
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
    Err(anyhow::anyhow!("reading interface data: {last_err:?}"))
}

impl UserspaceBackend {
    pub fn new(ifname: &str) -> anyhow::Result<Self> {
        let api = WGApi::<Userspace>::new(ifname.to_string())?;
        Ok(Self {
            api,
            name: ifname.to_string(),
        })
    }
}

fn mask(ip: std::net::Ipv4Addr, cidr: u8) -> IpAddrMask {
    IpAddrMask::new(IpAddr::V4(ip), cidr)
}

/// defguard's userspace backend creates the TUN but leaves the link admin-down, so route
/// installation fails ("Network is down"). Bring it up. Linux uses `ip`; the Windows/macOS
/// native paths manage link state themselves. TODO: replace with a netlink/ioctl call.
#[cfg(target_os = "linux")]
fn bring_link_up(name: &str) -> anyhow::Result<()> {
    let status = std::process::Command::new("ip")
        .args(["link", "set", name, "up"])
        .status()
        .map_err(|e| anyhow::anyhow!("running `ip link set {name} up`: {e}"))?;
    if !status.success() {
        anyhow::bail!("`ip link set {name} up` exited with {status}");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn bring_link_up(_name: &str) -> anyhow::Result<()> {
    Ok(())
}

fn to_peer(p: &PeerConfig) -> Peer {
    let mut peer = Peer::new(Key::new(p.public_key));
    peer.allowed_ips = p.allowed_ips.iter().map(|(a, c)| mask(*a, *c)).collect();
    peer.endpoint = p.endpoint;
    peer.persistent_keepalive_interval = p.keepalive;
    peer
}

impl WgBackend for UserspaceBackend {
    fn up(&mut self, cfg: &IfaceConfig) -> anyhow::Result<()> {
        self.api.create_interface()?;
        let config = InterfaceConfiguration {
            name: self.name.clone(),
            prvkey: Key::new(cfg.private_key).to_string(), // defguard wants base64
            addresses: cfg.addresses.iter().map(|(a, c)| mask(*a, *c)).collect(),
            port: cfg.listen_port,
            peers: Vec::new(),
            mtu: None,
            fwmark: None,
        };
        self.api.configure_interface(&config)?;
        bring_link_up(&self.name)?;
        Ok(())
    }

    fn set_peer(&self, peer: &PeerConfig) -> anyhow::Result<()> {
        self.api.configure_peer(&to_peer(peer))?;
        Ok(())
    }

    fn configure_routing(&self, peers: &[PeerConfig]) -> anyhow::Result<()> {
        let peers: Vec<Peer> = peers.iter().map(to_peer).collect();
        self.api.configure_peer_routing(&peers)?;
        Ok(())
    }

    fn remove_peer(&self, public_key: &[u8; 32]) -> anyhow::Result<()> {
        self.api.remove_peer(&Key::new(*public_key))?;
        Ok(())
    }

    fn peer_endpoints(&self) -> anyhow::Result<std::collections::HashMap<[u8; 32], std::net::SocketAddr>> {
        read_peer_endpoints(&self.name)
    }

    fn down(&self) -> anyhow::Result<()> {
        self.api.remove_interface()?;
        Ok(())
    }
}
