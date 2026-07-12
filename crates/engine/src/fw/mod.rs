//! Host firewall (design.md §M7): the port-ACL layer that sits *above* the WireGuard backend.
//!
//! Peering already decides *who* can reach us (WG crypto-routing drops non-peers); the firewall
//! decides *which ports* those peers reach. Default-deny new inbound on the wg interface, allow
//! established/related + ICMP echo, and open only the ports the owner `expose`s. A port may be
//! scoped to one network (`--net`), reachable only from that network's peers (source-IP filtered).
//!
//! Backend-agnostic on purpose: decrypted packets traverse the OS stack from the wg adapter for
//! both kernel and userspace WireGuard, so the same rules apply. Linux nftables now; Windows WFP
//! and macOS pf drop in behind [`FirewallBackend`] later.

mod nftables;
pub use nftables::NftBackend;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

use common::control::{ExposedPort, Proto};

/// A port opened to peers. `net = Some(name)` scopes it to that network's peers (source-IP
/// filtered); `None` opens it to every peer (safe: only peers can deliver to the wg interface).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exposed {
    pub proto: Proto,
    pub port: u16,
    pub net: Option<String>,
}

/// Current peer IPs grouped by shared-network name — the source sets for `--net`-scoped exposes.
pub type PeersByNet = HashMap<String, Vec<Ipv4Addr>>;

/// OS firewall control surface. `apply` installs the full ruleset (idempotent replace); `reset`
/// removes it.
pub trait FirewallBackend: Send + Sync {
    /// Replace the ruleset: default-deny new inbound on `iface`, allow established/related + ICMP
    /// echo, accept the exposed ports (scoped exposes matched against `peers_by_net`).
    fn apply(&self, iface: &str, exposed: &[Exposed], peers_by_net: &PeersByNet)
        -> anyhow::Result<()>;
    /// Remove all UnityLAN firewall rules.
    fn reset(&self) -> anyhow::Result<()>;
}

/// Live firewall state shared by the daemon (init + membership updates) and the control socket
/// (expose/unexpose). Every change reconciles the full ruleset, so the backend stays a pure
/// function of (exposed set, peer-IP sets).
pub struct Firewall {
    backend: Box<dyn FirewallBackend>,
    iface: String,
    exposed: Mutex<Vec<Exposed>>,
    peers_by_net: Mutex<PeersByNet>,
}

impl Firewall {
    pub fn new(backend: Box<dyn FirewallBackend>, iface: String, seeds: Vec<Exposed>) -> Self {
        Self {
            backend,
            iface,
            exposed: Mutex::new(seeds),
            peers_by_net: Mutex::new(HashMap::new()),
        }
    }

    /// Install the base policy + any seeded exposures. Call once at startup.
    pub fn init(&self) -> anyhow::Result<()> {
        self.reconcile()
    }

    /// Refresh the per-network peer sets (called on every membership change). Rescopes any
    /// `--net` exposes to the current peers of their network.
    pub fn update_peers(&self, peers_by_net: PeersByNet) -> anyhow::Result<()> {
        *self.peers_by_net.lock().unwrap() = peers_by_net;
        self.reconcile()
    }

    /// Open a port (idempotent). Returns the resulting exposed set.
    pub fn expose(
        &self,
        proto: Proto,
        port: u16,
        net: Option<String>,
    ) -> anyhow::Result<Vec<ExposedPort>> {
        {
            let mut set = self.exposed.lock().unwrap();
            if !set.iter().any(|e| e.proto == proto && e.port == port && e.net == net) {
                set.push(Exposed { proto, port, net });
            }
        }
        self.reconcile()?;
        Ok(self.list())
    }

    /// Close a port on all protocols/scopes matching (proto, port). Returns the exposed set.
    pub fn unexpose(&self, proto: Proto, port: u16) -> anyhow::Result<Vec<ExposedPort>> {
        self.exposed
            .lock()
            .unwrap()
            .retain(|e| !(e.proto == proto && e.port == port));
        self.reconcile()?;
        Ok(self.list())
    }

    pub fn list(&self) -> Vec<ExposedPort> {
        self.exposed
            .lock()
            .unwrap()
            .iter()
            .map(|e| ExposedPort {
                proto: e.proto,
                port: e.port,
                net: e.net.clone(),
            })
            .collect()
    }

    /// Tear down all firewall rules (clean shutdown).
    pub fn reset(&self) -> anyhow::Result<()> {
        self.backend.reset()
    }

    fn reconcile(&self) -> anyhow::Result<()> {
        let exposed = self.exposed.lock().unwrap().clone();
        let peers = self.peers_by_net.lock().unwrap().clone();
        self.backend.apply(&self.iface, &exposed, &peers)
    }
}
