//! Host firewall (design.md §M7): the port-ACL layer that sits *above* the WireGuard backend.
//!
//! Peering already decides *who* can reach us (WG crypto-routing drops non-peers); the firewall
//! decides *which ports* those peers reach. Default-deny new inbound on the wg interface, allow
//! established/related + ICMP echo, and open only the ports the owner `expose`s.
//!
//! Backend-agnostic on purpose: decrypted packets traverse the OS stack from the wg adapter for
//! both kernel and userspace WireGuard, so the same rules apply. Linux nftables now; Windows WFP
//! and macOS pf drop in behind [`FirewallBackend`] later.

mod nftables;
pub use nftables::NftBackend;

use std::sync::Mutex;

use common::control::{ExposedPort, Proto};

/// A port opened to peers. `net` (source-network scoping) is reserved for the `--net` slice; the
/// current backend opens to all peers (safe: only peers can deliver to the wg interface).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exposed {
    pub proto: Proto,
    pub port: u16,
}

/// OS firewall control surface. `apply` installs the full ruleset (idempotent replace); `reset`
/// removes it.
pub trait FirewallBackend: Send + Sync {
    /// Replace the ruleset: default-deny new inbound on `iface`, allow established/related + ICMP
    /// echo, accept the given exposed ports (from any peer).
    fn apply(&self, iface: &str, exposed: &[Exposed]) -> anyhow::Result<()>;
    /// Remove all UnityLAN firewall rules.
    fn reset(&self) -> anyhow::Result<()>;
}

/// Live firewall state shared by the daemon (init) and the control socket (expose/unexpose).
/// Every change reconciles the full ruleset, so the backend stays a pure function of `exposed`.
pub struct Firewall {
    backend: Box<dyn FirewallBackend>,
    iface: String,
    exposed: Mutex<Vec<Exposed>>,
}

impl Firewall {
    pub fn new(backend: Box<dyn FirewallBackend>, iface: String, seeds: Vec<Exposed>) -> Self {
        Self {
            backend,
            iface,
            exposed: Mutex::new(seeds),
        }
    }

    /// Install the base policy + any seeded exposures. Call once at startup.
    pub fn init(&self) -> anyhow::Result<()> {
        self.reconcile()
    }

    /// Open a port (idempotent). Returns the resulting exposed set.
    pub fn expose(&self, proto: Proto, port: u16) -> anyhow::Result<Vec<ExposedPort>> {
        {
            let mut set = self.exposed.lock().unwrap();
            if !set.iter().any(|e| e.proto == proto && e.port == port) {
                set.push(Exposed { proto, port });
            }
        }
        self.reconcile()?;
        Ok(self.list())
    }

    /// Close a port (idempotent). Returns the resulting exposed set.
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
                net: None,
            })
            .collect()
    }

    /// Tear down all firewall rules (clean shutdown).
    pub fn reset(&self) -> anyhow::Result<()> {
        self.backend.reset()
    }

    fn reconcile(&self) -> anyhow::Result<()> {
        let set = self.exposed.lock().unwrap().clone();
        self.backend.apply(&self.iface, &set)
    }
}
