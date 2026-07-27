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
/// `listen_port` is the WireGuard UDP port; `beacon_port` is the LAN discovery beacon's UDP port
/// (`None` when the beacon is disabled). Only the Windows backend needs them — it opens both on the
/// host interfaces so inbound handshakes and beacons arrive (Defender default-denies them
/// otherwise). The nftables backend already leaves non-wg interfaces untouched, so it ignores both;
/// a Linux host that runs its own firewall (firewalld/ufw) must permit the ports there.
pub fn default_backend(listen_port: u16, beacon_port: Option<u16>) -> Box<dyn FirewallBackend> {
    #[cfg(not(windows))]
    {
        let _ = (listen_port, beacon_port);
        Box::new(NftBackend)
    }
    #[cfg(windows)]
    {
        Box::new(windows::WindowsFwBackend {
            listen_port,
            beacon_port,
        })
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
    /// The service name this port answers to, if the owner named it. Absent on every exposure
    /// written before names existed, which is exactly right: those stay bare ports until named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Whether this is something a browser opens, which is what decides if the name goes into a
    /// certificate — and therefore into public Certificate Transparency logs, permanently.
    #[serde(default, skip_serializing_if = "is_default_kind")]
    pub kind: common::service::ServiceKind,
}

fn is_default_kind(kind: &common::service::ServiceKind) -> bool {
    *kind == common::service::ServiceKind::default()
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
    /// echo, accept the exposed ports (scoped exposes matched against `peers`). `mesh_addr` is this
    /// host's mesh address once assigned, so the backend can drop packets addressed to it that
    /// arrive on the wrong interface (the Linux weak-host bypass).
    fn apply(
        &self,
        iface: &str,
        mesh_addr: Option<std::net::Ipv4Addr>,
        exposed: &[Exposed],
        peers: &PeerSets,
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
    peers: Mutex<PeerSets>,
    /// `<state_dir>/exposed.json` — the exposed set is owner intent, so it must outlive the
    /// process. Without it a restart silently reverts to the config seeds and every port the
    /// owner opened at runtime falls through to the default `drop`.
    path: PathBuf,
    /// Auto-exempt the mesh interface from a foreign CGNAT drop (see `Config::tailscale_compat`).
    /// Only read on Linux (the nftables CGNAT-conflict path); stored on every platform so the field
    /// is `dead_code` off Linux.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
        name: Option<String>,
        kind: common::service::ServiceKind,
    ) -> anyhow::Result<Vec<ExposedPort>> {
        if let Some(name) = &name {
            if !common::service::valid_label(name) {
                anyhow::bail!("{}", common::service::label_error(name));
            }
            let distinct = {
                let set = self.exposed.lock().unwrap();
                let mut names: Vec<&str> = set.iter().filter_map(|e| e.name.as_deref()).collect();
                names.push(name);
                names.sort_unstable();
                names.dedup();
                names.len()
            };
            // Bounded because every peer holds our list in memory and answers DNS from it. The cap
            // counts *names*, not exposures: one service on tcp and udp is one name.
            if distinct > common::service::MAX_SERVICES_PER_DEVICE {
                anyhow::bail!(
                    "this device already serves {} named services, the most one device may announce",
                    common::service::MAX_SERVICES_PER_DEVICE
                );
            }
        }
        {
            let mut set = self.exposed.lock().unwrap();
            match set
                .iter_mut()
                .find(|e| e.proto == proto && e.port == port && e.scope == scope)
            {
                // Re-exposing the same port with a name is how a bare port gets named, and how a
                // name is changed — not a no-op, or an existing port could never be labelled.
                Some(existing) if name.is_some() => {
                    existing.name = name;
                    existing.kind = kind;
                }
                Some(_) => {}
                None => set.push(Exposed {
                    proto,
                    port,
                    scope,
                    name,
                    kind,
                }),
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

    /// Close every port carrying `name`. Returns the exposed set and how many were closed, so the
    /// caller can tell "deleted" from "no such service" rather than reporting success either way.
    pub fn unexpose_named(&self, name: &str) -> anyhow::Result<(usize, Vec<ExposedPort>)> {
        let before = self.exposed.lock().unwrap().len();
        self.exposed
            .lock()
            .unwrap()
            .retain(|e| e.name.as_deref() != Some(name));
        let removed = before - self.exposed.lock().unwrap().len();
        if removed > 0 {
            self.persist()?;
            self.reconcile()?;
        }
        Ok((removed, self.list()))
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
                name: e.name.clone(),
                kind: e.kind,
                // Unscoped is always reachable; a scope is reachable only while it has peers.
                active: peers.sources(&e.scope).is_none_or(|ips| !ips.is_empty()),
            })
            .collect()
    }

    /// The named services `peer` may reach, deduplicated — what we answer a peer's
    /// [`common::p2p::ReqBody::GetServices`] with.
    ///
    /// Scope is enforced *here*, against the same source sets the firewall installs, rather than
    /// announced to every peer to filter for itself: a peer that cannot reach the port must not
    /// learn the name either, and the two decisions must not be able to disagree.
    pub fn services_for(&self, peer: Ipv4Addr) -> Vec<common::service::MeshService> {
        let peers = self.peers.lock().unwrap();
        let mut out: Vec<common::service::MeshService> = Vec::new();
        for e in self.exposed.lock().unwrap().iter() {
            let Some(name) = &e.name else { continue };
            // `None` sources means the scope restricts nobody — every peer, which is anyone who can
            // deliver to the wg interface at all.
            if !peers
                .sources(&e.scope)
                .is_none_or(|ips| ips.contains(&peer))
            {
                continue;
            }
            let svc = common::service::MeshService {
                name: name.clone(),
                proto: e.proto,
                port: e.port,
                kind: e.kind,
            };
            if !out.contains(&svc) {
                out.push(svc);
            }
        }
        out.truncate(common::service::MAX_SERVICES_PER_DEVICE);
        out
    }

    /// The labels of our **web** services — the names a certificate should cover, and the only
    /// service state the coordinator is ever told about.
    pub fn web_service_labels(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .exposed
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.kind == common::service::ServiceKind::Web)
            .filter_map(|e| e.name.clone())
            .collect();
        out.sort_unstable();
        out.dedup();
        out.truncate(common::api::MAX_WEB_SERVICES_PER_DEVICE);
        out
    }

    /// Our own services, whoever is asking — for local display and for the names we resolve
    /// ourselves. Unlike [`Self::services_for`] this is not scoped: it is our own list.
    pub fn own_services(&self) -> Vec<common::service::MeshService> {
        let mut out: Vec<common::service::MeshService> = Vec::new();
        for e in self.exposed.lock().unwrap().iter() {
            let Some(name) = &e.name else { continue };
            let svc = common::service::MeshService {
                name: name.clone(),
                proto: e.proto,
                port: e.port,
                kind: e.kind,
            };
            if !out.contains(&svc) {
                out.push(svc);
            }
        }
        out
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
        let mesh_addr = *self.mesh_addr.lock().unwrap();
        let exposed = self.exposed.lock().unwrap().clone();
        let peers = self.peers.lock().unwrap().clone();
        self.backend.apply(&self.iface, mesh_addr, &exposed, &peers)
    }
}

/// The firewall is what the p2p listener announces services from — the same object that decides who
/// may *reach* a port decides who may learn its name, so the two cannot drift apart.
impl crate::p2p::ServiceSource for Firewall {
    fn services_for(&self, peer: Ipv4Addr) -> Vec<common::service::MeshService> {
        Firewall::services_for(self, peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TempDir;
    use common::service::ServiceKind;

    /// A backend that installs nothing, so the tests exercise `Firewall`'s own bookkeeping.
    struct NullBackend;
    impl FirewallBackend for NullBackend {
        fn apply(
            &self,
            _: &str,
            _: Option<std::net::Ipv4Addr>,
            _: &[Exposed],
            _: &PeerSets,
        ) -> anyhow::Result<()> {
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
            name: None,
            kind: common::service::ServiceKind::Port,
        }
    }

    /// A peer set where `minecraft` has one member and `own_devices` another, so a scoped service
    /// can be asked about from inside and outside its scope.
    fn peers_with(minecraft: &[Ipv4Addr], own: &[Ipv4Addr]) -> PeerSets {
        let (guild_id, role_id) = crate::testutil::network_ids("minecraft");
        PeerSets {
            nets: vec![NetInfo {
                guild_id,
                role_id,
                guild: "g".into(),
                name: "minecraft".into(),
                ips: minecraft.to_vec(),
            }],
            own_devices: own.to_vec(),
        }
    }

    /// The name is scoped exactly like the port. A peer that cannot reach a service must not learn
    /// it exists — otherwise the announcement leaks what the firewall is there to withhold.
    #[test]
    fn a_peer_outside_a_services_scope_is_not_told_the_name() {
        let d = TempDir::new("svc-scope");
        let f = fw(&d, vec![]);
        let inside = Ipv4Addr::new(100, 64, 0, 5);
        let outside = Ipv4Addr::new(100, 64, 0, 6);
        f.update_peers(peers_with(&[inside], &[])).unwrap();
        f.expose(
            Proto::Tcp,
            25565,
            net("minecraft"),
            Some("mc".into()),
            ServiceKind::Port,
        )
        .unwrap();

        assert_eq!(f.services_for(inside).len(), 1);
        assert_eq!(f.services_for(inside)[0].name, "mc");
        assert!(
            f.services_for(outside).is_empty(),
            "a peer outside the scope learns nothing"
        );
        // Our own list is not scoped — it is what *we* serve, for our own display and resolver.
        assert_eq!(f.own_services().len(), 1);
    }

    /// An unscoped service is announced to every peer, matching a port that is open to every peer.
    #[test]
    fn an_unscoped_service_is_announced_to_anyone() {
        let d = TempDir::new("svc-unscoped");
        let f = fw(&d, vec![]);
        f.update_peers(peers_with(&[], &[])).unwrap();
        f.expose(
            Proto::Tcp,
            8096,
            ExposeScope::AllPeers,
            Some("jellyfin".into()),
            ServiceKind::Port,
        )
        .unwrap();
        assert_eq!(f.services_for(Ipv4Addr::new(100, 64, 0, 9)).len(), 1);
    }

    /// One service on two ports is one name, and closing it by name closes both — otherwise
    /// deleting a service would mean recalling which ports it was assembled from.
    #[test]
    fn a_service_spanning_two_ports_is_named_once_and_closed_once() {
        let d = TempDir::new("svc-two-ports");
        let f = fw(&d, vec![]);
        f.expose(
            Proto::Tcp,
            25565,
            ExposeScope::AllPeers,
            Some("mc".into()),
            ServiceKind::Port,
        )
        .unwrap();
        f.expose(
            Proto::Udp,
            25565,
            ExposeScope::AllPeers,
            Some("mc".into()),
            ServiceKind::Port,
        )
        .unwrap();
        assert_eq!(f.own_services().len(), 2, "two ports");
        assert_eq!(f.services_for(Ipv4Addr::new(100, 64, 0, 9)).len(), 2);

        let (removed, left) = f.unexpose_named("mc").unwrap();
        assert_eq!(removed, 2);
        assert!(left.is_empty());
        assert_eq!(f.unexpose_named("mc").unwrap().0, 0, "already gone");
    }

    /// Naming an already-open port is how an existing exposure gets a name — the alternative is
    /// closing and reopening it, which drops traffic for no reason.
    #[test]
    fn re_exposing_a_port_with_a_name_names_it_in_place() {
        let d = TempDir::new("svc-rename");
        let f = fw(&d, vec![]);
        f.expose(
            Proto::Tcp,
            8096,
            ExposeScope::AllPeers,
            None,
            ServiceKind::Port,
        )
        .unwrap();
        assert!(f.own_services().is_empty());
        let listed = f
            .expose(
                Proto::Tcp,
                8096,
                ExposeScope::AllPeers,
                Some("jellyfin".into()),
                ServiceKind::Port,
            )
            .unwrap();
        assert_eq!(listed.len(), 1, "still one exposure, now named");
        assert_eq!(listed[0].name.as_deref(), Some("jellyfin"));
    }

    #[test]
    fn a_bad_label_is_refused_and_the_count_is_capped() {
        let d = TempDir::new("svc-cap");
        let f = fw(&d, vec![]);
        assert!(f
            .expose(
                Proto::Tcp,
                1,
                ExposeScope::AllPeers,
                Some("NOPE".into()),
                ServiceKind::Port
            )
            .is_err());
        for i in 0..common::service::MAX_SERVICES_PER_DEVICE {
            f.expose(
                Proto::Tcp,
                1000 + i as u16,
                ExposeScope::AllPeers,
                Some(format!("s{i}")),
                ServiceKind::Port,
            )
            .unwrap();
        }
        assert!(
            f.expose(
                Proto::Tcp,
                2000,
                ExposeScope::AllPeers,
                Some("extra".into()),
                ServiceKind::Port,
            )
            .is_err(),
            "the cap counts names, and this would be one too many"
        );
        // ...but re-naming an existing one is not a new name, so it still goes through.
        f.expose(
            Proto::Tcp,
            3000,
            ExposeScope::AllPeers,
            Some("s0".into()),
            ServiceKind::Port,
        )
        .unwrap();
    }

    /// Only web services reach the coordinator. A plain port service is announced peer-to-peer and
    /// the coordinator never learns it exists — which is what keeps that the narrow exception it is.
    #[test]
    fn only_web_services_are_offered_to_the_coordinator() {
        let d = TempDir::new("svc-web");
        let f = fw(&d, vec![]);
        f.expose(
            Proto::Tcp,
            8096,
            ExposeScope::AllPeers,
            Some("jellyfin".into()),
            ServiceKind::Web,
        )
        .unwrap();
        f.expose(
            Proto::Tcp,
            25565,
            ExposeScope::AllPeers,
            Some("mc".into()),
            ServiceKind::Port,
        )
        .unwrap();

        assert_eq!(f.web_service_labels(), vec!["jellyfin".to_string()]);
        // ...while both are announced to peers, which is where a game server belongs.
        assert_eq!(f.own_services().len(), 2);
    }

    /// A state file written before names existed must still load, with its ports unnamed.
    #[test]
    fn an_exposure_written_before_names_loads_as_an_unnamed_port() {
        let d = TempDir::new("svc-legacy");
        std::fs::write(
            d.join("exposed.json"),
            br#"[{"proto":"Tcp","port":8080,"net":null}]"#,
        )
        .unwrap();
        let f = fw(&d, vec![]);
        assert_eq!(f.list().len(), 1);
        assert_eq!(f.list()[0].name, None);
        assert!(f.own_services().is_empty());
    }

    /// A resolved network scope, addressed by the shared fixture ids so a scope built here matches
    /// a seed built from the same name elsewhere — see [`crate::testutil::network_ids`].
    fn net(name: &str) -> ExposeScope {
        let (guild_id, role_id) = crate::testutil::network_ids(name);
        ExposeScope::Net { guild_id, role_id }
    }

    fn info(guild: &str, name: &str, ips: Vec<Ipv4Addr>) -> NetInfo {
        let (guild_id, role_id) = crate::testutil::network_ids(name);
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
        f.expose(
            Proto::Tcp,
            8082,
            ExposeScope::AllPeers,
            None,
            ServiceKind::Port,
        )
        .unwrap();

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
        f.expose(
            Proto::Tcp,
            8082,
            ExposeScope::AllPeers,
            None,
            ServiceKind::Port,
        )
        .unwrap();
        f.expose(Proto::Tcp, 8082, net("minecraft"), None, ServiceKind::Port)
            .unwrap();
        f.expose(
            Proto::Tcp,
            8082,
            ExposeScope::OwnDevices,
            None,
            ServiceKind::Port,
        )
        .unwrap();

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
        f.expose(Proto::Tcp, 8082, net("minecraft"), None, ServiceKind::Port)
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
        f.expose(
            Proto::Tcp,
            8082,
            ExposeScope::AllPeers,
            None,
            ServiceKind::Port,
        )
        .unwrap();
        f.expose(Proto::Tcp, 25565, net("minecraft"), None, ServiceKind::Port)
            .unwrap();

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
        f.expose(
            Proto::Tcp,
            8082,
            ExposeScope::OwnDevices,
            None,
            ServiceKind::Port,
        )
        .unwrap();

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
