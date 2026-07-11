//! WireGuard backend abstraction (design.md §7.3). Userspace-portable primary via defguard;
//! native kernel backends are a later optimization (M8).

mod userspace;
pub use userspace::UserspaceBackend;

use std::net::{Ipv4Addr, SocketAddr};

/// Interface-level configuration for the single UnityLAN interface (`unl0`).
/// The interface name is set when the backend is constructed.
pub struct IfaceConfig {
    pub private_key: [u8; 32],
    /// The client's own `/32`(s) across all its networks.
    pub addresses: Vec<(Ipv4Addr, u8)>,
    pub listen_port: u16,
}

/// A single peer in the mesh.
pub struct PeerConfig {
    pub public_key: [u8; 32],
    pub allowed_ips: Vec<(Ipv4Addr, u8)>,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: Option<u16>,
}

/// Kernel/userspace-agnostic WireGuard control surface.
pub trait WgBackend {
    /// Create the interface and apply interface-level config (key, addresses, port).
    fn up(&mut self, cfg: &IfaceConfig) -> anyhow::Result<()>;
    /// Add or update a peer.
    fn set_peer(&self, peer: &PeerConfig) -> anyhow::Result<()>;
    /// Install routes for the peers' allowed IPs (so tunnel traffic is routed to the iface).
    fn configure_routing(&self, peers: &[PeerConfig]) -> anyhow::Result<()>;
    /// Remove a peer by public key. (Used by gossip reconciliation.)
    #[allow(dead_code)]
    fn remove_peer(&self, public_key: &[u8; 32]) -> anyhow::Result<()>;
    /// Tear the interface down.
    fn down(&self) -> anyhow::Result<()>;
}
