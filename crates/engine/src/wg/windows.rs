//! Windows WireGuard backend: the wireguard-nt kernel driver via defguard's `WGApi<Kernel>`.
//!
//! defguard's *userspace* (boringtun) path is unix-only, so on Windows we drive wireguard-nt.
//! That backend has a fundamentally different shape than the userspace one: `configure_peer`,
//! `remove_peer`, and `configure_peer_routing` are all no-ops — the *only* way to set peers is
//! `configure_interface` with the **full** peer list, and it rejects the whole config if any peer
//! lacks an endpoint. So this backend keeps the desired interface + peer state and re-applies the
//! entire configuration on every mutation, rather than mutating peers incrementally.
//!
//! Runtime prerequisites: run elevated, and ship `wireguard.dll` (the wireguard-nt runtime) next to
//! the binary — the `wireguard-nt` crate loads it by name at load time.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::util::hex8;
use std::sync::Mutex;

use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::peer::Peer;
use defguard_wireguard_rs::{InterfaceConfiguration, Kernel, WGApi, WireguardInterfaceApi};

use super::{IfaceConfig, PeerConfig, PeerStat, WgBackend};

/// Interface-level config we hold so we can rebuild the full `configure_interface` payload on every
/// peer change (wireguard-nt has no incremental peer API — see the module docs).
struct StoredIface {
    private_key: [u8; 32],
    addresses: Vec<(Ipv4Addr, u8)>,
    listen_port: u16,
}

pub struct KernelBackend {
    api: Mutex<WGApi<Kernel>>,
    name: String,
    /// Set once `up` runs; `None` before that. Guards `reapply` against being called too early.
    iface: Mutex<Option<StoredIface>>,
    /// Desired peer set, keyed by pubkey. Re-materialized into a full config on each `reapply`.
    peers: Mutex<HashMap<[u8; 32], PeerConfig>>,
}

impl KernelBackend {
    pub fn new(ifname: &str) -> anyhow::Result<Self> {
        let api = WGApi::<Kernel>::new(ifname.to_string())?;
        Ok(Self {
            api: Mutex::new(api),
            name: ifname.to_string(),
            iface: Mutex::new(None),
            peers: Mutex::new(HashMap::new()),
        })
    }

    /// Rebuild the full interface configuration from the stored iface + desired peers and push it.
    /// Peers without an endpoint are skipped: wireguard-nt requires an endpoint per peer and would
    /// otherwise reject the entire config. Such a peer is added on a later refresh once we learn its
    /// endpoint (a directly dialable address or a hole-punch target).
    fn reapply(&self) -> anyhow::Result<()> {
        let iface = self.iface.lock().unwrap();
        let Some(sc) = iface.as_ref() else {
            anyhow::bail!("interface not up");
        };
        let peers: Vec<Peer> = self
            .peers
            .lock()
            .unwrap()
            .values()
            .filter_map(|p| {
                if p.endpoint.is_none() {
                    tracing::warn!(
                        peer = %hex8(&p.public_key),
                        "windows wg: skipping endpoint-less peer (wireguard-nt requires an endpoint)"
                    );
                    None
                } else {
                    Some(super::to_peer(p))
                }
            })
            .collect();
        let config = InterfaceConfiguration {
            name: self.name.clone(),
            prvkey: Key::new(sc.private_key).to_string(), // defguard wants base64
            addresses: sc
                .addresses
                .iter()
                .map(|(a, c)| super::mask(*a, *c))
                .collect(),
            port: sc.listen_port,
            peers,
            mtu: None,
            fwmark: None,
        };
        self.api.lock().unwrap().configure_interface(&config)?;
        Ok(())
    }
}

impl WgBackend for KernelBackend {
    fn up(&mut self, cfg: &IfaceConfig) -> anyhow::Result<()> {
        *self.iface.lock().unwrap() = Some(StoredIface {
            private_key: cfg.private_key,
            addresses: cfg.addresses.clone(),
            listen_port: cfg.listen_port,
        });
        self.api.lock().unwrap().create_interface()?;
        self.reapply()
    }

    fn set_peer(&self, peer: &PeerConfig) -> anyhow::Result<()> {
        self.peers
            .lock()
            .unwrap()
            .insert(peer.public_key, peer.clone());
        self.reapply()
    }

    fn configure_routing(&self, _peers: &[PeerConfig]) -> anyhow::Result<()> {
        // wireguard-nt installs allowed-IP routes inside `configure_interface`, so a re-apply from
        // the current desired set is all that's needed (peers were already staged via `set_peer`).
        self.reapply()
    }

    fn remove_peer(&self, public_key: &[u8; 32]) -> anyhow::Result<()> {
        self.peers.lock().unwrap().remove(public_key);
        self.reapply()
    }

    fn peer_stats(&self) -> anyhow::Result<HashMap<[u8; 32], PeerStat>> {
        let host = self.api.lock().unwrap().read_interface_data()?;
        Ok(super::peer_stats_from_host(&host))
    }

    fn down(&self) -> anyhow::Result<()> {
        self.api.lock().unwrap().remove_interface()?;
        Ok(())
    }

    fn set_link_up(&self, _up: bool) -> anyhow::Result<()> {
        // wireguard-nt manages the adapter's link state itself; a mesh disconnect still drops every
        // peer (via the empty seed set), so no admin-toggle is wired here. No-op.
        Ok(())
    }

    fn is_userspace(&self) -> bool {
        false // wireguard-nt owns the UDP socket — no side-socket ICE; keeps M5.2 punch + M5.4 relay
    }
}
