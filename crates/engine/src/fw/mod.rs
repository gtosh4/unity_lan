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

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use common::control::{ExposeScope, ExposedPort, Proto, RemoveScope};
use serde::{Deserialize, Serialize};

/// The host-firewall backend for this platform: Linux/other-unix nftables, Windows Defender
/// Firewall (via PowerShell). Both enforce the same port-ACL policy behind [`FirewallBackend`].
///
/// `listen_port` is the WireGuard UDP port. Only the Windows backend needs it — it opens that port
/// on the host interfaces so inbound handshakes arrive (Defender default-denies it otherwise). The
/// nftables backend already leaves non-wg interfaces untouched, so it ignores the argument; a Linux
/// host that runs its own firewall (firewalld/ufw) must permit the port there.
pub fn default_backend(listen_port: u16) -> Box<dyn FirewallBackend> {
    #[cfg(not(windows))]
    {
        let _ = listen_port;
        Box::new(NftBackend)
    }
    #[cfg(windows)]
    {
        Box::new(windows::WindowsFwBackend { listen_port })
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

/// The networks currently visible to this device and who is in them, plus the owner's own devices.
/// Rebuilt from the seeds on every membership change.
///
/// Networks are identified by `(guild_id, role_id)`, never by name: role names are user-chosen and
/// mutable, two guilds may each have an `Engineering`, and keying on the name merged them into one
/// source set — letting a port scoped to one guild's role be reached by the other's members. The
/// labels are carried alongside purely so a name a person typed can be resolved to ids, and so the
/// engine can render an exposure.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerSets {
    pub nets: Vec<NetInfo>,
    pub own_devices: Vec<Ipv4Addr>,
}

/// One network's identity, display labels, and current members.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NetInfo {
    pub guild_id: u64,
    pub role_id: u64,
    /// Guild community label — display, and what `--guild` matches against.
    pub guild: String,
    /// Role display name — display, and what a bare `<role>` matches against.
    pub name: String,
    pub ips: Vec<Ipv4Addr>,
}

impl NetInfo {
    /// `role @ guild`, or just the role when the coordinator sent no community label.
    pub fn label(&self) -> String {
        if self.guild.is_empty() {
            self.name.clone()
        } else {
            format!("{} @ {}", self.name, self.guild)
        }
    }
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
            ExposeScope::Net { guild_id, role_id } => Some(
                self.nets
                    .iter()
                    .find(|n| n.guild_id == *guild_id && n.role_id == *role_id)
                    .map_or(&[], |n| n.ips.as_slice()),
            ),
            // A name that was never resolved to ids — a scope stored before id-scoping, or one
            // whose network is no longer visible. It stands for *the* matching network while
            // exactly one matches; once two do there is no way to tell which was meant, so it
            // admits nobody rather than both.
            ExposeScope::Unresolved { guild, name } => {
                Some(match self.matching(guild.as_deref(), name).as_slice() {
                    [only] => only.ips.as_slice(),
                    _ => &[],
                })
            }
        }
    }

    /// The networks a human-typed scope could mean: role name must match, and the guild label too
    /// when one was given. More than one hit is the ambiguity that must not be guessed at.
    pub fn matching(&self, guild: Option<&str>, name: &str) -> Vec<&NetInfo> {
        self.nets
            .iter()
            .filter(|n| n.name == name && guild.is_none_or(|g| n.guild == g))
            .collect()
    }

    /// The label for a scope, resolved against the current networks. Falls back to the scope's own
    /// rendering when the network isn't visible (offline, or left).
    pub fn label(&self, scope: &ExposeScope) -> String {
        match scope {
            ExposeScope::Net { guild_id, role_id } => self
                .nets
                .iter()
                .find(|n| n.guild_id == *guild_id && n.role_id == *role_id)
                .map_or_else(|| scope.fallback_label(), NetInfo::label),
            other => other.fallback_label(),
        }
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
    /// Auto-exempt the mesh interface from a foreign CGNAT drop (see `Config::tailscale_compat`).
    tailscale_compat: bool,
    /// This host's mesh address, once assigned — see [`Firewall::set_mesh_addr`].
    mesh_addr: Mutex<Option<std::net::Ipv4Addr>>,
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
        // A file that exists but won't parse is a real signal, not a missing file: it means a
        // rollback met a state file a newer version wrote (scopes it has no variant for). Falling
        // back to the config seeds is right — never guess at intent — but do it loudly, or every
        // runtime exposure vanishes with no trace of why.
        let exposed = match std::fs::read(&path) {
            Ok(b) => serde_json::from_slice::<Vec<Exposed>>(&b).unwrap_or_else(|e| {
                tracing::warn!(
                    path = %path.display(),
                    "could not read the exposed-port state ({e}); falling back to the config \
                     `expose` list. Ports opened at runtime are closed until re-exposed"
                );
                seeds.clone()
            }),
            Err(_) => seeds.clone(),
        };
        Self {
            backend,
            iface,
            exposed: Mutex::new(exposed),
            peers: Mutex::new(PeerSets::default()),
            path,
            tailscale_compat,
            mesh_addr: Mutex::new(None),
        }
    }

    /// Install the base policy + any seeded exposures. Call once at startup.
    pub fn init(&self) -> anyhow::Result<()> {
        self.reconcile()
    }

    /// Refresh the peer source sets (called on every membership change). Rescopes any scoped
    /// exposure to the current peers of its scope. Returns whether the sets changed — an identical
    /// refresh (the coordinator re-sending the same membership each hold) skips the nftables
    /// reconcile rather than rewriting the same ruleset every couple of seconds.
    pub fn update_peers(&self, peers: PeerSets) -> anyhow::Result<bool> {
        if *self.peers.lock().unwrap() == peers {
            return Ok(false);
        }
        self.warn_on_ambiguous(&peers);
        *self.peers.lock().unwrap() = peers;
        self.reconcile()?;
        Ok(true)
    }

    /// Warn about an exposure that names a role two networks carry. It admits nobody by design —
    /// there is no way to tell which was meant — but a port that never opens needs to say why.
    ///
    /// Only ambiguity is reported, never "no match": before the first refresh, and for a network
    /// whose members are all offline, zero matches is the normal case and would cry wolf every
    /// reconcile. A scope added through the control socket is resolved to ids up front, so this
    /// only ever fires for a config-seeded `net =` or a state file written before ids.
    fn warn_on_ambiguous(&self, peers: &PeerSets) {
        for e in self.exposed.lock().unwrap().iter() {
            let ExposeScope::Unresolved { guild, name } = &e.scope else {
                continue;
            };
            let hits = peers.matching(guild.as_deref(), name);
            if hits.len() > 1 {
                tracing::warn!(
                    port = e.port,
                    proto = e.proto.as_str(),
                    network = %name,
                    communities = ?hits.iter().map(|n| n.guild.as_str()).collect::<Vec<_>>(),
                    "this port names a network that exists in more than one community, so it is \
                     open to nobody; name one (config `guild = `, or `ctl expose --guild`)"
                );
            }
        }
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
                label: peers.label(&e.scope),
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

    /// Tear down all firewall rules (clean shutdown). Includes the CGNAT exemption, which lives in a
    /// *foreign* chain and so is not covered by the backend's own table teardown.
    pub fn reset(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        nftables::remove_cgnat_compat();
        self.backend.reset()
    }

    /// Tell the firewall this host's mesh address, once the interface has one. Needed for the
    /// loopback half of the CGNAT exemption — traffic to our own mesh address (the `.internal`
    /// resolver) comes back on `lo`, which an interface-scoped rule can't match.
    pub fn set_mesh_addr(&self, addr: std::net::Ipv4Addr) -> anyhow::Result<()> {
        let changed = { self.mesh_addr.lock().unwrap().replace(addr) != Some(addr) };
        if changed {
            self.reconcile()?;
        }
        Ok(())
    }

    fn reconcile(&self) -> anyhow::Result<()> {
        // Re-checked on every reconcile, not just at startup: the owner of that chain (Tailscale)
        // rebuilds it on restart, silently dropping our exemption. Idempotent.
        #[cfg(target_os = "linux")]
        nftables::ensure_cgnat_compat(
            &self.iface,
            *self.mesh_addr.lock().unwrap(),
            self.tailscale_compat,
        );
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
        // `false`: these run on a dev machine that may have a live Tailscale, and the unit tests have
        // no business mutating its chain.
        Firewall::load(Box::new(NullBackend), "unl0".into(), seeds, dir, false)
    }

    fn seed(port: u16) -> Exposed {
        Exposed {
            proto: Proto::Tcp,
            port,
            scope: ExposeScope::AllPeers,
        }
    }

    /// A resolved network scope. Fixture ids are derived from the name so two helpers agree.
    fn net(name: &str) -> ExposeScope {
        let (guild_id, role_id) = fixture_ids(name);
        ExposeScope::Net { guild_id, role_id }
    }

    fn fixture_ids(name: &str) -> (u64, u64) {
        match name {
            "minecraft" => (900_100, 7001),
            "factorio" => (900_200, 7002),
            "mesh" => (900_100, 7003),
            other => panic!("unknown fixture network {other}"),
        }
    }

    fn info(guild: &str, name: &str, ips: Vec<Ipv4Addr>) -> NetInfo {
        let (guild_id, role_id) = fixture_ids(name);
        NetInfo {
            guild_id,
            role_id,
            guild: guild.into(),
            name: name.into(),
            ips,
        }
    }

    fn by_net(name: &str, ips: Vec<Ipv4Addr>) -> PeerSets {
        PeerSets {
            nets: vec![info("acme", name, ips)],
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
                ExposeScope::Unresolved {
                    guild: None,
                    name: "factorio".into(),
                },
            ],
            "a bare name stays unqualified until it can be resolved against held networks",
        );
    }

    /// The reason a scope carries ids. Two guilds may each have a role named `Engineering`; they
    /// are different networks with different members, so a port scoped to one must not admit the
    /// other's peers — and their names are identical, so only the ids tell them apart.
    #[test]
    fn same_role_name_in_two_guilds_are_separate_source_sets() {
        let acme_ip = Ipv4Addr::new(100, 64, 0, 2);
        let play_ip = Ipv4Addr::new(100, 64, 0, 3);
        let peers = PeerSets {
            nets: vec![
                NetInfo {
                    guild_id: 900_100,
                    role_id: 7001,
                    guild: "acme".into(),
                    name: "Engineering".into(),
                    ips: vec![acme_ip],
                },
                NetInfo {
                    guild_id: 900_200,
                    role_id: 7002,
                    guild: "playhouse".into(),
                    name: "Engineering".into(),
                    ips: vec![play_ip],
                },
            ],
            own_devices: Vec::new(),
        };

        assert_eq!(
            peers.sources(&ExposeScope::Net {
                guild_id: 900_100,
                role_id: 7001
            }),
            Some(&[acme_ip][..]),
        );
        assert_eq!(
            peers.sources(&ExposeScope::Net {
                guild_id: 900_200,
                role_id: 7002
            }),
            Some(&[play_ip][..]),
        );

        // Both render distinctly, so the two are told apart wherever they're listed.
        assert_eq!(
            peers.label(&ExposeScope::Net {
                guild_id: 900_100,
                role_id: 7001
            }),
            "Engineering @ acme",
        );
    }

    /// A scope stored before ids, or one whose network has gone, names only a role. It resolves
    /// while exactly one network matches — and once two do, there is no way to tell which was
    /// meant, so it admits nobody rather than both.
    #[test]
    fn an_unqualified_scope_resolves_alone_and_fails_closed_when_ambiguous() {
        let acme_ip = Ipv4Addr::new(100, 64, 0, 2);
        let scope = ExposeScope::Unresolved {
            guild: None,
            name: "Engineering".into(),
        };
        let acme = NetInfo {
            guild_id: 900_100,
            role_id: 7001,
            guild: "acme".into(),
            name: "Engineering".into(),
            ips: vec![acme_ip],
        };

        let one = PeerSets {
            nets: vec![acme.clone()],
            own_devices: Vec::new(),
        };
        assert_eq!(
            one.sources(&scope),
            Some(&[acme_ip][..]),
            "sole match resolves"
        );

        let ambiguous = PeerSets {
            nets: vec![
                acme,
                NetInfo {
                    guild_id: 900_200,
                    role_id: 7002,
                    guild: "playhouse".into(),
                    name: "Engineering".into(),
                    ips: vec![Ipv4Addr::new(100, 64, 0, 3)],
                },
            ],
            own_devices: Vec::new(),
        };
        assert_eq!(
            ambiguous.sources(&scope),
            Some(&[][..]),
            "ambiguous must admit nobody, never both guilds",
        );

        // Naming the guild disambiguates it again.
        assert_eq!(
            ambiguous.sources(&ExposeScope::Unresolved {
                guild: Some("acme".into()),
                name: "Engineering".into(),
            }),
            Some(&[acme_ip][..]),
        );
    }
}
