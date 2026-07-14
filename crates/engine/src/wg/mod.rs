//! WireGuard backend abstraction (design.md §7.3). Userspace-portable primary via defguard on
//! unix; on Windows defguard's userspace path is unavailable, so we drive the wireguard-nt kernel
//! driver (`WGApi<Kernel>`) instead. Native Linux kernel backend is a later optimization (M8).

#[cfg(unix)]
mod userspace;
#[cfg(unix)]
pub use userspace::UserspaceBackend;

#[cfg(windows)]
mod windows;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::SystemTime;

/// Construct the platform's WireGuard backend: defguard userspace (boringtun) on unix, the
/// wireguard-nt kernel driver on Windows. Both implement [`WgBackend`], so callers stay OS-agnostic.
pub fn new_backend(ifname: &str) -> anyhow::Result<Box<dyn WgBackend>> {
    #[cfg(unix)]
    {
        Ok(Box::new(UserspaceBackend::new(ifname)?))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(windows::KernelBackend::new(ifname)?))
    }
}

/// Interface-level configuration for the single UnityLAN interface (`unl0`).
/// The interface name is set when the backend is constructed.
pub struct IfaceConfig {
    pub private_key: [u8; 32],
    /// The client's own `/32`(s) across all its networks.
    pub addresses: Vec<(Ipv4Addr, u8)>,
    pub listen_port: u16,
}

/// Live per-peer stats read back from the WG backend.
pub struct PeerStat {
    pub endpoint: Option<SocketAddr>,
    pub last_handshake: Option<SystemTime>,
}

/// A single peer in the mesh.
#[derive(Clone)]
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
    /// Remove a peer by public key. (Used to prune revoked / departed co-members.)
    fn remove_peer(&self, public_key: &[u8; 32]) -> anyhow::Result<()>;
    /// Per-peer live stats from the WG backend: the endpoint it was last seen sending from (its
    /// reflexive NAT mapping, reported to the coordinator for hole punching §7.2) and the time of
    /// its last completed handshake (for reachability/NAT diagnostics).
    fn peer_stats(&self) -> anyhow::Result<HashMap<[u8; 32], PeerStat>>;
    /// Tear the interface down.
    fn down(&self) -> anyhow::Result<()>;
    /// Bring the interface's link administratively up or down *without* destroying the device — the
    /// device, its uapi socket and addresses persist. Used for mesh connect/disconnect. Idempotent.
    fn set_link_up(&self, up: bool) -> anyhow::Result<()>;
    /// Whether this backend owns its UDP socket in-process (userspace/boringtun). Only such backends
    /// can run the side-socket ICE agent (M5.5); kernel backends keep the M5.2 punch + M5.4 relay.
    fn is_userspace(&self) -> bool;
}
