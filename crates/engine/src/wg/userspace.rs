//! Userspace WireGuard backend (boringtun via defguard). Portable across Linux/Windows/macOS;
//! requires CAP_NET_ADMIN (or equivalent) to create the TUN interface.

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
        self.api.create_interface()?;
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
}
