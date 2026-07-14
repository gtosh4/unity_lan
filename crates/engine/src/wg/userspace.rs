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

/// Read per-peer stats (last-seen endpoint + last handshake time). Empty until peers handshake.
/// boringtun's userspace uapi read is racy under load and intermittently returns EAGAIN mid-parse;
/// retry a few times so a transient failure doesn't look like "no peers".
pub fn read_peer_stats(
    ifname: &str,
) -> anyhow::Result<std::collections::HashMap<[u8; 32], super::PeerStat>> {
    let api = WGApi::<Userspace>::new(ifname.to_string())?;
    let mut last_err = None;
    for _ in 0..5 {
        match api.read_interface_data() {
            Ok(host) => {
                return Ok(host
                    .peers
                    .iter()
                    .map(|(k, p)| {
                        (
                            k.as_array(),
                            super::PeerStat {
                                endpoint: p.endpoint,
                                last_handshake: p.last_handshake,
                            },
                        )
                    })
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

/// Set the link's admin state. defguard's userspace backend creates the TUN but leaves the link
/// admin-down, so route installation fails ("Network is down") until we bring it up; mesh
/// connect/disconnect also toggles it. Linux uses `ip`; the Windows/macOS native paths manage link
/// state themselves. TODO: replace with a netlink/ioctl call.
#[cfg(target_os = "linux")]
fn set_link_state(name: &str, up: bool) -> anyhow::Result<()> {
    let state = if up { "up" } else { "down" };
    let status = std::process::Command::new("ip")
        .args(["link", "set", name, state])
        .status()
        .map_err(|e| anyhow::anyhow!("running `ip link set {name} {state}`: {e}"))?;
    if !status.success() {
        anyhow::bail!("`ip link set {name} {state}` exited with {status}");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_link_state(_name: &str, _up: bool) -> anyhow::Result<()> {
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
        set_link_state(&self.name, true)?;
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

    fn peer_stats(&self) -> anyhow::Result<std::collections::HashMap<[u8; 32], super::PeerStat>> {
        read_peer_stats(&self.name)
    }

    fn down(&self) -> anyhow::Result<()> {
        self.api.remove_interface()?;
        Ok(())
    }

    fn set_link_up(&self, up: bool) -> anyhow::Result<()> {
        set_link_state(&self.name, up)
    }

    fn is_userspace(&self) -> bool {
        true // boringtun in-process — the side-socket ICE agent (M5.5) applies here
    }
}
