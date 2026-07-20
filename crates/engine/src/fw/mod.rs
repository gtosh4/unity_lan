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

use common::control::{ExposeScope, ExposedPort, Proto, RemoveScope};
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

/// A port opened to peers, and to whom. A scoped exposure is source-IP filtered to that scope's
/// peers; [`ExposeScope::AllPeers`] opens it to every peer (safe: only peers can deliver to the wg
/// interface).
///
/// Serialized into `<state_dir>/exposed.json`, so the field keeps its old `net` name on disk —
/// [`ExposeScope`]'s codec reads what earlier versions wrote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Exposed {
    pub proto: Proto,
    pub port: u16,
    #[serde(rename = "net")]
    pub scope: ExposeScope,
}

/// The current source sets a scoped exposure can be filtered against: peer IPs grouped by network,
/// plus the owner's own devices (which are not a network — the daemon derives them from peer
/// identity, see [`crate::daemon`]).
///
/// Networks are keyed by `(guild, role)`, not role name: role names are Discord display names in
/// independent guilds, so two guilds may each have an `Engineering`, and keying on the name alone
/// would merge them into one source set — letting a port scoped to one guild's role be reached by
/// the other's members.
#[derive(Clone, Debug, Default)]
pub struct PeerSets {
    pub by_net: HashMap<(String, String), Vec<Ipv4Addr>>,
    pub own_devices: Vec<Ipv4Addr>,
}

impl PeerSets {
    /// The addresses a scope admits, or `None` when the scope isn't source-filtered at all.
    ///
    /// The distinction matters to the backends: `None` means "no source restriction", while
    /// `Some(&[])` means "restricted to nobody" — a scope whose peers are all offline, which must
    /// stay closed rather than fall open.
    pub fn sources(&self, scope: &ExposeScope) -> Option<&[Ipv4Addr]> {
        match scope {
            ExposeScope::AllPeers => None,
            ExposeScope::OwnDevices => Some(&self.own_devices),
            ExposeScope::Net { guild, name } => Some(
                self.by_net
                    .get(&(guild.clone(), name.clone()))
                    .map_or(&[], Vec::as_slice),
            ),
            // Stored before scopes carried a guild. It means *the* network with this name while
            // exactly one matches; once two do, there is no way to tell which was meant, so it
            // admits nobody rather than both. See `unqualified_matches`.
            ExposeScope::NetUnqualified(name) => {
                Some(match self.unqualified_matches(name).as_slice() {
                    [only] => self.by_net.get(*only).map_or(&[], Vec::as_slice),
                    _ => &[],
                })
            }
        }
    }

    /// Every known network whose role name is `name` — one entry unless two guilds share a role
    /// name, which is the ambiguity a legacy unqualified scope can no longer resolve.
    pub fn unqualified_matches(&self, name: &str) -> Vec<&(String, String)> {
        let mut hits: Vec<&(String, String)> =
            self.by_net.keys().filter(|(_, n)| n == name).collect();
        hits.sort();
        hits
    }
}

/// OS firewall control surface. `apply` installs the full ruleset (idempotent replace); `reset`
/// removes it.
pub trait FirewallBackend: Send + Sync {
    /// Replace the ruleset: default-deny new inbound on `iface`, allow established/related + ICMP
    /// echo, accept the exposed ports (scoped exposes matched against `peers`).
    fn apply(&self, iface: &str, exposed: &[Exposed], peers: &PeerSets) -> anyhow::Result<()>;
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
    peers: Mutex<PeerSets>,
    /// `<state_dir>/exposed.json` — the exposed set is owner intent, so it must outlive the
    /// process. Without it a restart silently reverts to the config seeds and every port the
    /// owner opened at runtime falls through to the default `drop`.
    path: PathBuf,
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
            peers: Mutex::new(PeerSets::default()),
            path,
        }
    }

    /// Install the base policy + any seeded exposures. Call once at startup.
    pub fn init(&self) -> anyhow::Result<()> {
        // Warn if another firewall (e.g. Tailscale) blackholes our CGNAT range on the wg interface.
        #[cfg(target_os = "linux")]
        nftables::warn_on_cgnat_conflict(&self.iface);
        self.reconcile()
    }

    /// Refresh the peer source sets (called on every membership change). Rescopes any scoped
    /// exposure to the current peers of its scope.
    pub fn update_peers(&self, peers: PeerSets) -> anyhow::Result<()> {
        *self.peers.lock().unwrap() = peers;
        self.reconcile()
    }

    /// Open a port (idempotent). Returns the resulting exposed set.
    pub fn expose(
        &self,
        proto: Proto,
        port: u16,
        scope: ExposeScope,
    ) -> anyhow::Result<Vec<ExposedPort>> {
        {
            let mut set = self.exposed.lock().unwrap();
            if !set
                .iter()
                .any(|e| e.proto == proto && e.port == port && e.scope == scope)
            {
                set.push(Exposed { proto, port, scope });
            }
        }
        self.persist()?;
        self.reconcile()?;
        Ok(self.list())
    }

    /// Close a port: every scope matching (proto, port) for [`RemoveScope::All`], or just the one
    /// whose scope matches for [`RemoveScope::Exact`]. Returns the exposed set.
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
                    RemoveScope::Exact(scope) => &e.scope == scope,
                };
            !hit
        });
        self.persist()?;
        self.reconcile()?;
        Ok(self.list())
    }

    /// The exposed set, each entry tagged with whether it's currently reachable — a scope with no
    /// online peers installs an empty source set, so the port is exposed but unreachable.
    pub fn list(&self) -> Vec<ExposedPort> {
        let peers = self.peers.lock().unwrap();
        self.exposed
            .lock()
            .unwrap()
            .iter()
            .map(|e| ExposedPort {
                proto: e.proto,
                port: e.port,
                scope: e.scope.clone(),
                // Unscoped is always reachable; a scope is reachable only while it has peers.
                active: peers.sources(&e.scope).is_none_or(|ips| !ips.is_empty()),
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

    /// Tear down all firewall rules (clean shutdown).
    pub fn reset(&self) -> anyhow::Result<()> {
        self.backend.reset()
    }

    fn reconcile(&self) -> anyhow::Result<()> {
        let exposed = self.exposed.lock().unwrap().clone();
        let peers = self.peers.lock().unwrap().clone();
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
        fn apply(&self, _: &str, _: &[Exposed], _: &PeerSets) -> anyhow::Result<()> {
            Ok(())
        }
        fn reset(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn fw(dir: &Path, seeds: Vec<Exposed>) -> Firewall {
        Firewall::load(Box::new(NullBackend), "unl0".into(), seeds, dir)
    }

    fn seed(port: u16) -> Exposed {
        Exposed {
            proto: Proto::Tcp,
            port,
            scope: ExposeScope::AllPeers,
        }
    }

    fn net(name: &str) -> ExposeScope {
        ExposeScope::Net {
            guild: "acme".into(),
            name: name.into(),
        }
    }

    fn by_net(name: &str, ips: Vec<Ipv4Addr>) -> PeerSets {
        PeerSets {
            by_net: HashMap::from([(("acme".to_string(), name.to_string()), ips)]),
            own_devices: Vec::new(),
        }
    }

    #[test]
    fn exposed_ports_survive_a_restart() {
        let dir = TempDir::new("fw-persist");

        // First run: config seeds 25565, the owner opens 8082 at runtime.
        let f = fw(&dir, vec![seed(25565)]);
        f.expose(Proto::Tcp, 8082, ExposeScope::AllPeers).unwrap();

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
        f.expose(Proto::Tcp, 8082, ExposeScope::AllPeers).unwrap();
        f.expose(Proto::Tcp, 8082, net("minecraft")).unwrap();
        f.expose(Proto::Tcp, 8082, ExposeScope::OwnDevices).unwrap();

        // Closing one scope leaves the other exposures of the same port alone.
        let left = f
            .unexpose(Proto::Tcp, 8082, RemoveScope::Exact(net("minecraft")))
            .unwrap();
        assert_eq!(left.len(), 2);
        assert_eq!(
            left.iter().map(|e| e.scope.clone()).collect::<Vec<_>>(),
            vec![ExposeScope::AllPeers, ExposeScope::OwnDevices],
        );

        // `All` still closes every scope at once.
        f.expose(Proto::Tcp, 8082, net("minecraft")).unwrap();
        assert!(f
            .unexpose(Proto::Tcp, 8082, RemoveScope::All)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn scoped_expose_reports_inactive_without_peers() {
        let dir = TempDir::new("fw-active");
        let f = fw(&dir, Vec::new());
        f.expose(Proto::Tcp, 8082, ExposeScope::AllPeers).unwrap();
        f.expose(Proto::Tcp, 25565, net("minecraft")).unwrap();

        // No peers yet: the scoped port is exposed but unreachable; the unscoped one is fine.
        let listed = f.list();
        assert!(listed[0].active, "unscoped exposures are always active");
        assert!(
            !listed[1].active,
            "no peers in 'minecraft' -> empty source set"
        );

        // A peer joining the network makes it reachable...
        f.update_peers(by_net("minecraft", vec![Ipv4Addr::new(100, 64, 0, 2)]))
            .unwrap();
        assert!(f.list()[1].active);

        // ...and a logout (peers cleared) takes it back out without dropping the exposure.
        f.update_peers(PeerSets::default()).unwrap();
        let listed = f.list();
        assert_eq!(listed.len(), 2, "exposure kept across a peer-set rebuild");
        assert!(!listed[1].active);
    }

    /// The own-device scope draws from its own source set, not from any network — so a port scoped
    /// to it is unreachable while the owner has only this device, and reachable once a second one
    /// comes online, regardless of what networks are in play.
    #[test]
    fn own_device_scope_tracks_the_owners_devices_not_a_network() {
        let dir = TempDir::new("fw-own");
        let f = fw(&dir, Vec::new());
        f.expose(Proto::Tcp, 8082, ExposeScope::OwnDevices).unwrap();

        assert!(!f.list()[0].active, "sole device -> nobody to reach it");

        // Peers in a network don't grant the own-device scope anything.
        f.update_peers(by_net("minecraft", vec![Ipv4Addr::new(100, 64, 0, 2)]))
            .unwrap();
        assert!(
            !f.list()[0].active,
            "a network peer must not satisfy the own-device scope",
        );

        f.update_peers(PeerSets {
            own_devices: vec![Ipv4Addr::new(100, 64, 0, 3)],
            ..PeerSets::default()
        })
        .unwrap();
        assert!(f.list()[0].active);
    }

    /// `exposed.json` outlives upgrades, so a file written before the scope existed has to keep
    /// loading — and keep meaning what it meant.
    #[test]
    fn a_pre_upgrade_state_file_still_loads() {
        let dir = TempDir::new("fw-legacy");
        std::fs::write(
            dir.join("exposed.json"),
            r#"[{"proto":"Tcp","port":25565,"net":null},
                {"proto":"Udp","port":34197,"net":"factorio"}]"#,
        )
        .unwrap();

        let listed = fw(&dir, Vec::new()).list();
        assert_eq!(
            listed.iter().map(|e| e.scope.clone()).collect::<Vec<_>>(),
            vec![
                ExposeScope::AllPeers,
                ExposeScope::NetUnqualified("factorio".into()),
            ],
            "a bare name stays unqualified until it can be resolved against held networks",
        );
    }

    /// The reason scopes carry a guild. Two guilds may each have a role named `Engineering`; they
    /// are different networks with different members, so a port scoped to one must not admit the
    /// other's peers.
    #[test]
    fn same_role_name_in_two_guilds_are_separate_source_sets() {
        let acme = Ipv4Addr::new(100, 64, 0, 2);
        let playhouse = Ipv4Addr::new(100, 64, 0, 3);
        let peers = PeerSets {
            by_net: HashMap::from([
                (("acme".to_string(), "Engineering".to_string()), vec![acme]),
                (
                    ("playhouse".to_string(), "Engineering".to_string()),
                    vec![playhouse],
                ),
            ]),
            own_devices: Vec::new(),
        };

        let scoped = |guild: &str| ExposeScope::Net {
            guild: guild.into(),
            name: "Engineering".into(),
        };
        assert_eq!(peers.sources(&scoped("acme")), Some(&[acme][..]));
        assert_eq!(peers.sources(&scoped("playhouse")), Some(&[playhouse][..]));
    }

    /// A scope stored before guilds were carried names only the role. It resolves while exactly one
    /// guild has that role — and once two do, there is no way to tell which was meant, so it admits
    /// nobody rather than both.
    #[test]
    fn an_unqualified_scope_resolves_alone_and_fails_closed_when_ambiguous() {
        let acme = Ipv4Addr::new(100, 64, 0, 2);
        let scope = ExposeScope::NetUnqualified("Engineering".into());

        let mut by_net =
            HashMap::from([(("acme".to_string(), "Engineering".to_string()), vec![acme])]);
        let one = PeerSets {
            by_net: by_net.clone(),
            own_devices: Vec::new(),
        };
        assert_eq!(
            one.sources(&scope),
            Some(&[acme][..]),
            "sole match resolves"
        );

        by_net.insert(
            ("playhouse".to_string(), "Engineering".to_string()),
            vec![Ipv4Addr::new(100, 64, 0, 3)],
        );
        let ambiguous = PeerSets {
            by_net,
            own_devices: Vec::new(),
        };
        assert_eq!(
            ambiguous.sources(&scope),
            Some(&[][..]),
            "ambiguous must admit nobody, never both guilds",
        );
    }
}
