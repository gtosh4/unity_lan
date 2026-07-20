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

#[cfg(not(windows))]
mod nftables;
#[cfg(not(windows))]
pub use nftables::NftBackend;

#[cfg(windows)]
mod windows;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use common::control::{ExposedPort, Proto, RemoveScope};
use serde::{Deserialize, Serialize};

/// The host-firewall backend for this platform: Linux/other-unix nftables, Windows Defender
/// Firewall (via PowerShell). Both enforce the same port-ACL policy behind [`FirewallBackend`].
pub fn default_backend() -> Box<dyn FirewallBackend> {
    #[cfg(not(windows))]
    {
        Box::new(NftBackend)
    }
    #[cfg(windows)]
    {
        Box::new(windows::WindowsFwBackend)
    }
}

/// A port opened to peers. `net = Some(name)` scopes it to that network's peers (source-IP
/// filtered); `None` opens it to every peer (safe: only peers can deliver to the wg interface).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    fn apply(
        &self,
        iface: &str,
        exposed: &[Exposed],
        peers_by_net: &PeersByNet,
    ) -> anyhow::Result<()>;
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
    /// `<state_dir>/exposed.json` — the exposed set is owner intent, so it must outlive the
    /// process. Without it a restart silently reverts to the config seeds and every port the
    /// owner opened at runtime falls through to the default `drop`.
    path: PathBuf,
    /// Auto-exempt the mesh interface from a foreign CGNAT drop (see `Config::tailscale_compat`).
    tailscale_compat: bool,
}

impl Firewall {
    /// Load the exposed set from `<state_dir>/exposed.json`, falling back to the config `seeds` on
    /// first run — so config sets the initial posture and runtime `expose`/`unexpose` override it
    /// thereafter (same precedence as the local network opt-out in [`crate::netcfg`]). A later
    /// edit to the config's `expose` list therefore only takes effect on a state dir that has
    /// never had an exposure applied.
    pub fn load(
        backend: Box<dyn FirewallBackend>,
        iface: String,
        seeds: Vec<Exposed>,
        state_dir: &Path,
        tailscale_compat: bool,
    ) -> Self {
        let path = state_dir.join("exposed.json");
        let exposed = std::fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<Exposed>>(&b).ok())
            .unwrap_or(seeds);
        Self {
            backend,
            iface,
            exposed: Mutex::new(exposed),
            peers_by_net: Mutex::new(HashMap::new()),
            path,
            tailscale_compat,
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
            if !set
                .iter()
                .any(|e| e.proto == proto && e.port == port && e.net == net)
            {
                set.push(Exposed { proto, port, net });
            }
        }
        self.persist()?;
        self.reconcile()?;
        Ok(self.list())
    }

    /// Close a port: every scope matching (proto, port) for [`RemoveScope::All`], or just the one
    /// whose network matches for [`RemoveScope::Exact`]. Returns the exposed set.
    pub fn unexpose(
        &self,
        proto: Proto,
        port: u16,
        scope: RemoveScope,
    ) -> anyhow::Result<Vec<ExposedPort>> {
        self.exposed.lock().unwrap().retain(|e| {
            let hit = e.proto == proto
                && e.port == port
                && match &scope {
                    RemoveScope::All => true,
                    RemoveScope::Exact(net) => &e.net == net,
                };
            !hit
        });
        self.persist()?;
        self.reconcile()?;
        Ok(self.list())
    }

    /// The exposed set, each entry tagged with whether it's currently reachable — a `--net` scope
    /// with no online peers installs an empty source set, so the port is exposed but unreachable.
    pub fn list(&self) -> Vec<ExposedPort> {
        let peers = self.peers_by_net.lock().unwrap();
        self.exposed
            .lock()
            .unwrap()
            .iter()
            .map(|e| ExposedPort {
                proto: e.proto,
                port: e.port,
                net: e.net.clone(),
                active: match &e.net {
                    None => true,
                    Some(n) => peers.get(n).is_some_and(|ips| !ips.is_empty()),
                },
            })
            .collect()
    }

    /// Write the exposed set through to `exposed.json`. Errors propagate to the caller: a rule we
    /// can't persist is one that silently disappears on the next restart, which is exactly the
    /// failure the file exists to prevent.
    fn persist(&self) -> anyhow::Result<()> {
        let set = self.exposed.lock().unwrap().clone();
        std::fs::write(&self.path, serde_json::to_vec(&set)?)?;
        Ok(())
    }

    /// Tear down all firewall rules (clean shutdown). Includes the CGNAT exemption, which lives in a
    /// *foreign* chain and so is not covered by the backend's own table teardown.
    pub fn reset(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        nftables::remove_cgnat_compat(&self.iface);
        self.backend.reset()
    }

    fn reconcile(&self) -> anyhow::Result<()> {
        // Re-checked on every reconcile, not just at startup: the owner of that chain (Tailscale)
        // rebuilds it on restart, silently dropping our exemption. Idempotent.
        #[cfg(target_os = "linux")]
        nftables::ensure_cgnat_compat(&self.iface, self.tailscale_compat);
        let exposed = self.exposed.lock().unwrap().clone();
        let peers = self.peers_by_net.lock().unwrap().clone();
        self.backend.apply(&self.iface, &exposed, &peers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;

    /// A backend that installs nothing, so the tests exercise `Firewall`'s own bookkeeping.
    struct NullBackend;
    impl FirewallBackend for NullBackend {
        fn apply(&self, _: &str, _: &[Exposed], _: &PeersByNet) -> anyhow::Result<()> {
            Ok(())
        }
        fn reset(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn fw(dir: &Path, seeds: Vec<Exposed>) -> Firewall {
        // `false`: these run on a dev machine that may have a live Tailscale, and the unit tests have
        // no business mutating its chain.
        Firewall::load(Box::new(NullBackend), "unl0".into(), seeds, dir, false)
    }

    fn seed(port: u16) -> Exposed {
        Exposed {
            proto: Proto::Tcp,
            port,
            net: None,
        }
    }

    #[test]
    fn exposed_ports_survive_a_restart() {
        let dir = TempDir::new("fw-persist");

        // First run: config seeds 25565, the owner opens 8082 at runtime.
        let f = fw(&dir, vec![seed(25565)]);
        f.expose(Proto::Tcp, 8082, None).unwrap();

        // A restart reloads both from disk — not just the config seed.
        let reloaded = fw(&dir, vec![seed(25565)]);
        let ports: Vec<u16> = reloaded.list().iter().map(|e| e.port).collect();
        assert_eq!(ports, vec![25565, 8082]);

        // ...and an unexpose sticks too, even for a config-seeded port.
        reloaded
            .unexpose(Proto::Tcp, 25565, RemoveScope::All)
            .unwrap();
        let ports: Vec<u16> = fw(&dir, vec![seed(25565)])
            .list()
            .iter()
            .map(|e| e.port)
            .collect();
        assert_eq!(ports, vec![8082], "persisted set wins over the config seed");
    }

    #[test]
    fn exact_scope_removal_leaves_siblings() {
        let dir = TempDir::new("fw-scope");
        let f = fw(&dir, Vec::new());
        f.expose(Proto::Tcp, 8082, None).unwrap();
        f.expose(Proto::Tcp, 8082, Some("minecraft".into()))
            .unwrap();

        // Closing the scoped row leaves the all-peers exposure of the same port alone.
        let left = f
            .unexpose(
                Proto::Tcp,
                8082,
                RemoveScope::Exact(Some("minecraft".into())),
            )
            .unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].net, None);

        // `All` still closes every scope at once.
        f.expose(Proto::Tcp, 8082, Some("minecraft".into()))
            .unwrap();
        assert!(f
            .unexpose(Proto::Tcp, 8082, RemoveScope::All)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn scoped_expose_reports_inactive_without_peers() {
        let dir = TempDir::new("fw-active");
        let f = fw(&dir, Vec::new());
        f.expose(Proto::Tcp, 8082, None).unwrap();
        f.expose(Proto::Tcp, 25565, Some("minecraft".into()))
            .unwrap();

        // No peers yet: the scoped port is exposed but unreachable; the unscoped one is fine.
        let listed = f.list();
        assert!(listed[0].active, "unscoped exposures are always active");
        assert!(
            !listed[1].active,
            "no peers in 'minecraft' -> empty source set"
        );

        // A peer joining the network makes it reachable...
        f.update_peers(PeersByNet::from([(
            "minecraft".to_string(),
            vec![Ipv4Addr::new(100, 64, 0, 2)],
        )]))
        .unwrap();
        assert!(f.list()[1].active);

        // ...and a logout (peers cleared) takes it back out without dropping the exposure.
        f.update_peers(PeersByNet::new()).unwrap();
        let listed = f.list();
        assert_eq!(listed.len(), 2, "exposure kept across a peer-set rebuild");
        assert!(!listed[1].active);
    }
}
