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

    fn down(&self) -> anyhow::Result<()> {
        self.api.remove_interface()?;
        Ok(())
    }
}
