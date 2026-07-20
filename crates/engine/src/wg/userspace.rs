//! Userspace WireGuard backend (boringtun via defguard). Portable across Linux/Windows/macOS;
//! requires CAP_NET_ADMIN (or equivalent) to create the TUN interface.

use anyhow::Context;
use defguard_wireguard_rs::key::Key;
use defguard_wireguard_rs::peer::Peer;
use defguard_wireguard_rs::{InterfaceConfiguration, Userspace, WGApi, WireguardInterfaceApi};

use super::{IfaceConfig, PeerConfig, WgBackend};

pub struct UserspaceBackend {
    api: WGApi<Userspace>,
    name: String,
}

/// Read per-peer stats (last-seen endpoint + last handshake time). Empty until peers handshake.
/// boringtun's userspace uapi read is racy under load and intermittently returns EAGAIN mid-parse;
/// retry a few times so a transient failure doesn't look like "no peers".
pub fn read_peer_stats(
    ifname: &str,
) -> anyhow::Result<std::collections::HashMap<[u8; 32], super::PeerStat>> {
    let api = WGApi::<Userspace>::new(ifname.to_string())?;
    let mut last_err = None;
    for _ in 0..5 {
        match api.read_interface_data() {
            Ok(host) => return Ok(normalize_handshake(super::peer_stats_from_host(&host))),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
    Err(anyhow::anyhow!("reading interface data: {last_err:?}"))
}

/// Re-anchor boringtun's last-handshake to a real wall-clock timestamp.
///
/// boringtun's uapi writes the *time since* the last handshake into `last_handshake_time_sec` (a
/// relative duration), whereas the kernel writes an absolute wall-clock time. defguard parses the
/// field as seconds-since-epoch either way, so a userspace peer's `last_handshake` comes back as
/// `UNIX_EPOCH + age` — decades ago, which reads as "never handshaked" and pins the peer to `down`.
/// Undo it: recover the age (`t - UNIX_EPOCH`) and re-anchor to `now - age` so the rest of the
/// engine's liveness math (and the GUI's up/down + last-seen hover) works with a genuine timestamp.
fn normalize_handshake(
    mut stats: std::collections::HashMap<[u8; 32], super::PeerStat>,
) -> std::collections::HashMap<[u8; 32], super::PeerStat> {
    let now = std::time::SystemTime::now();
    for s in stats.values_mut() {
        if let Some(t) = s.last_handshake {
            let age = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            s.last_handshake = now.checked_sub(age);
        }
    }
    stats
}

/// Where boringtun puts an interface's uapi socket. `/var/run` is a symlink to `/run` on any
/// systemd host, so the two candidates are usually the same file — check both regardless, since
/// which one the library picked depends on its own probing.
#[cfg(unix)]
fn api_socket_paths(ifname: &str) -> [std::path::PathBuf; 2] {
    [
        std::path::PathBuf::from(format!("/run/wireguard/{ifname}.sock")),
        std::path::PathBuf::from(format!("/var/run/wireguard/{ifname}.sock")),
    ]
}

/// Delete an orphaned uapi socket, returning whether anything was removed.
///
/// Only ever removes a socket that refuses a connection: if something is listening, another engine
/// owns this interface and deleting the file would hijack a *live* mesh. `ECONNREFUSED` is the
/// kernel telling us the file outlived its process, which is the only case we act on.
#[cfg(unix)]
fn reap_stale_api_socket(ifname: &str) -> anyhow::Result<bool> {
    let mut removed = false;
    for path in api_socket_paths(ifname) {
        if !path.exists() {
            continue;
        }
        match std::os::unix::net::UnixStream::connect(&path) {
            // Someone answered — a live engine holds this interface. Leave it alone.
            Ok(_) => return Ok(false),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing stale api socket {}", path.display()))?;
                removed = true;
            }
            // Anything else (EACCES, ENOTSOCK, …) is not ours to interpret — don't delete blind.
            Err(_) => return Ok(false),
        }
    }
    Ok(removed)
}

/// Explain a uapi-socket bind failure in terms of the thing the operator has to change.
///
/// The raw error is `Permission denied (os error 13)` with no path, which is doubly opaque here: the
/// engine runs as root, so a permission error looks impossible — until you remember the unit drops
/// everything but `CAP_NET_ADMIN`/`CAP_NET_BIND_SERVICE`, and root without `CAP_DAC_OVERRIDE` obeys
/// ordinary file modes. Running the engine once as a normal user is enough to leave
/// `/run/wireguard` owned by that user, and every subsequent service start then fails.
#[cfg(unix)]
fn api_socket_hint(ifname: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    for path in api_socket_paths(ifname) {
        let Some(dir) = path.parent() else { continue };
        let Ok(md) = std::fs::metadata(dir) else {
            continue;
        };
        if md.uid() != 0 {
            return format!(
                "{} is owned by uid {}, not root — the engine runs without CAP_DAC_OVERRIDE, so it \
                 cannot write there. It was likely created by running the engine as a normal user. \
                 Remove it (`rm -rf {}`) and restart; the service recreates it as root",
                dir.display(),
                md.uid(),
                dir.display()
            );
        }
    }
    format!("creating the boringtun uapi socket for {ifname}")
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

/// Set the link's admin state. defguard's userspace backend creates the TUN but leaves the link
/// admin-down, so route installation fails ("Network is down") until we bring it up; mesh
/// connect/disconnect also toggles it. Linux uses `ip`; the Windows/macOS native paths manage link
/// state themselves. TODO: replace with a netlink/ioctl call.
#[cfg(target_os = "linux")]
fn set_link_state(name: &str, up: bool) -> anyhow::Result<()> {
    let state = if up { "up" } else { "down" };
    let status = std::process::Command::new("ip")
        .args(["link", "set", name, state])
        .status()
        .map_err(|e| anyhow::anyhow!("running `ip link set {name} {state}`: {e}"))?;
    if !status.success() {
        anyhow::bail!("`ip link set {name} {state}` exited with {status}");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn set_link_state(_name: &str, _up: bool) -> anyhow::Result<()> {
    Ok(())
}

impl WgBackend for UserspaceBackend {
    fn up(&mut self, cfg: &IfaceConfig) -> anyhow::Result<()> {
        if let Err(e) = self.api.create_interface() {
            // An engine killed before it could tear down (systemd SIGKILL after a hung stop) leaves
            // its boringtun uapi socket behind, and the bind then fails for the life of the machine
            // until someone deletes the file by hand — a headless box just restart-loops. Treat a
            // socket nobody is listening on as the orphan it is.
            #[cfg(unix)]
            if reap_stale_api_socket(&self.name)? {
                tracing::warn!(
                    iface = %self.name,
                    "wg: removed a stale boringtun api socket left by a previous engine; retrying"
                );
                self.api.create_interface()?;
            } else {
                return Err(anyhow::Error::from(e).context(api_socket_hint(&self.name)));
            }
            #[cfg(not(unix))]
            return Err(e.into());
        }
        let config = InterfaceConfiguration {
            name: self.name.clone(),
            prvkey: Key::new(cfg.private_key).to_string(), // defguard wants base64
            addresses: cfg
                .addresses
                .iter()
                .map(|(a, c)| super::mask(*a, *c))
                .collect(),
            port: cfg.listen_port,
            peers: Vec::new(),
            mtu: None,
            fwmark: None,
        };
        self.api.configure_interface(&config)?;
        set_link_state(&self.name, true)?;
        Ok(())
    }

    fn set_peer(&self, peer: &PeerConfig) -> anyhow::Result<()> {
        self.api.configure_peer(&super::to_peer(peer))?;
        Ok(())
    }

    fn configure_routing(&self, peers: &[PeerConfig]) -> anyhow::Result<()> {
        let peers: Vec<Peer> = peers.iter().map(super::to_peer).collect();
        self.api.configure_peer_routing(&peers)?;
        Ok(())
    }

    fn remove_peer(&self, public_key: &[u8; 32]) -> anyhow::Result<()> {
        self.api.remove_peer(&Key::new(*public_key))?;
        Ok(())
    }

    fn peer_stats(&self) -> anyhow::Result<std::collections::HashMap<[u8; 32], super::PeerStat>> {
        read_peer_stats(&self.name)
    }

    fn down(&self) -> anyhow::Result<()> {
        self.api.remove_interface()?;
        Ok(())
    }

    fn set_link_up(&self, up: bool) -> anyhow::Result<()> {
        set_link_state(&self.name, up)
    }

    fn is_userspace(&self) -> bool {
        true // boringtun in-process — the side-socket ICE agent (M5.5) applies here
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    fn stat(last_handshake: Option<SystemTime>) -> super::super::PeerStat {
        super::super::PeerStat {
            endpoint: None,
            last_handshake,
            rx_bytes: 0,
            tx_bytes: 0,
        }
    }

    /// A boringtun peer that handshaked `age` ago comes back from defguard as `UNIX_EPOCH + age`.
    /// `normalize_handshake` must turn that into `now - age`, i.e. a fresh timestamp — otherwise a
    /// live peer reads as decades stale and the GUI pins it to `down`.
    #[test]
    fn normalize_reanchors_boringtun_relative_handshake() {
        let age = Duration::from_secs(105);
        let mut m = std::collections::HashMap::new();
        m.insert([1u8; 32], stat(Some(UNIX_EPOCH + age)));
        let out = normalize_handshake(m);
        let t = out[&[1u8; 32]].last_handshake.expect("handshake preserved");
        let elapsed = t.elapsed().expect("timestamp is in the past");
        // Re-anchored to ~now-105s: elapsed is the original age, not ~56 years.
        assert!(
            elapsed >= age && elapsed < age + Duration::from_secs(5),
            "elapsed {elapsed:?} should be ~{age:?}"
        );
    }

    /// A peer that never handshaked (no uapi handshake line) stays `None`, not a bogus "just now".
    #[test]
    fn normalize_leaves_missing_handshake_none() {
        let mut m = std::collections::HashMap::new();
        m.insert([2u8; 32], stat(None));
        let out = normalize_handshake(m);
        assert!(out[&[2u8; 32]].last_handshake.is_none());
    }

    /// The reaper deletes a socket file, so the one thing it must never do is delete a socket some
    /// *live* engine is serving — that would hijack a running mesh. Only a refused connection counts.
    #[cfg(unix)]
    #[test]
    fn reaper_spares_a_socket_that_still_has_a_listener() {
        use std::os::unix::net::{UnixListener, UnixStream};

        let dir = crate::testutil::TempDir::new("wg-reaper");
        let path = dir.join("live.sock");
        let _listener = UnixListener::bind(&path).expect("bind");

        // Someone answers → this is a live engine, leave the file alone.
        assert!(UnixStream::connect(&path).is_ok());
        assert!(path.exists());

        // With the listener gone the file remains but refuses connections — that is the orphan.
        drop(_listener);
        std::fs::remove_file(&path).expect("cleanup");
        let stale = dir.join("stale.sock");
        let l = UnixListener::bind(&stale).expect("bind");
        drop(l);
        // A bound-then-dropped path either vanishes or refuses; both are safe to remove.
        if stale.exists() {
            assert_eq!(
                UnixStream::connect(&stale).unwrap_err().kind(),
                std::io::ErrorKind::ConnectionRefused
            );
        }
    }
}
