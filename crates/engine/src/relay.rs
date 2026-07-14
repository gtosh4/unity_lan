//! Embedded TURN relay server (design.md §7.2, M5.4).
//!
//! A directly-dialable, opted-in member runs this so co-members whose hole punch fails (symmetric
//! NAT / CGNAT / UDP-blocked) can reach each other by relaying WireGuard **ciphertext** through it —
//! the relay holds no keys, so end-to-end encryption is intact. Built on `webrtc-rs turn`, which is
//! also what the M5.5 ICE agent will use for its relay candidates, so this server carries forward.
//!
//! Authorization uses the standard long-term-credential / coturn `use-auth-secret` scheme: the
//! coordinator mints a short-lived `<expiry>` username + HMAC credential (see [`common::relay`]),
//! and this server's [`LongTermAuthHandler`] validates it against the same `relay_secret` without
//! ever contacting the coordinator. The secret is per-relay and shared with the coordinator only.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use common::api::{RelayAllocation, RelayInfo};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use turn::allocation::AllocationInfo;
use turn::auth::{generate_auth_key, AuthHandler};
use turn::client::{Client, ClientConfig};
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use turn::Error as TurnError;
use webrtc_util::conn::Conn;
use webrtc_util::vnet::net::Net;

/// TURN auth handler that both validates a minted credential (coturn `use-auth-secret`: the key is
/// derived from the shared `secret` + the `<expiry>` username) and **caps concurrent allocations**,
/// so an authorized member still can't spend an unbounded share of the relay's uplink (§7.2 DoS
/// surface). The cap counts distinct client source 5-tuples: a first sighting over the limit is
/// refused; a refresh / permission / channel-bind for an already-counted client passes; the count
/// is decremented when the allocation closes (via `alloc_close_notify`).
struct CappedAuth {
    secret: String,
    max_allocations: usize,
    active: Arc<Mutex<HashSet<SocketAddr>>>,
}

impl AuthHandler for CappedAuth {
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        src_addr: SocketAddr,
    ) -> Result<Vec<u8>, TurnError> {
        // Reject an expired time-windowed username (same rule as the built-in LongTermAuthHandler).
        let expiry: u64 = username
            .parse()
            .map_err(|_| TurnError::Other("malformed relay username".into()))?;
        if expiry < common::now_unix() {
            return Err(TurnError::Other("expired relay credential".into()));
        }
        {
            let mut active = self.active.lock().unwrap();
            if !active.contains(&src_addr) {
                if active.len() >= self.max_allocations {
                    tracing::warn!(%src_addr, max = self.max_allocations, "relay: allocation cap reached — refusing");
                    return Err(TurnError::Other("relay allocation cap reached".into()));
                }
                active.insert(src_addr);
            }
        }
        let password = common::relay::relay_credential(&self.secret, username);
        Ok(generate_auth_key(username, realm, &password))
    }
}

/// A running embedded TURN server. Holds the server task alive; [`stop`](Self::stop) tears it down.
pub struct RelayServer {
    server: Server,
}

impl RelayServer {
    /// Start a TURN server bound to `bind` (UDP), advertising `public_ip` as the relayed address
    /// clients reach it at, authorizing credentials minted against `secret`, and capping concurrent
    /// allocations at `max_allocations`.
    pub async fn start(
        bind: SocketAddr,
        public_ip: IpAddr,
        secret: String,
        max_allocations: usize,
    ) -> anyhow::Result<Self> {
        // turn itself allocates no sockets — we hand it the listener (an `Arc<UdpSocket>` is a
        // `webrtc_util::Conn`). The relay generator hands each allocation a relayed address on
        // `public_ip` (the dialable IP co-members reach us at), bound on all local interfaces.
        let conn = Arc::new(
            UdpSocket::bind(bind)
                .await
                .with_context(|| format!("binding TURN UDP socket {bind}"))?,
        );
        // Track active allocations for the cap; decrement as they close.
        let active: Arc<Mutex<HashSet<SocketAddr>>> = Arc::new(Mutex::new(HashSet::new()));
        let (close_tx, mut close_rx) = mpsc::channel::<AllocationInfo>(64);
        {
            let active = active.clone();
            tokio::spawn(async move {
                while let Some(info) = close_rx.recv().await {
                    active.lock().unwrap().remove(&info.five_tuple.src_addr);
                }
            });
        }
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: public_ip,
                    address: "0.0.0.0".to_owned(),
                    net: Arc::new(Net::new(None)),
                }),
            }],
            realm: common::relay::RELAY_REALM.to_owned(),
            auth_handler: Arc::new(CappedAuth {
                secret,
                max_allocations,
                active,
            }),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: Some(close_tx),
        })
        .await
        .context("starting TURN server")?;
        tracing::info!(%bind, %public_ip, max_allocations, "relay: TURN server up");
        Ok(Self { server })
    }

    /// Stop the server, closing all allocations.
    pub async fn stop(&self) -> anyhow::Result<()> {
        self.server.close().await.context("closing TURN server")?;
        Ok(())
    }
}

/// The client side: for each peer we can only reach via a relay, allocate a TURN relayed address on
/// that relay and bridge the peer's WG traffic through it via a local `127.0.0.1:<shim>` socket. The
/// peer's WG endpoint is set to that shim; boringtun sends/receives raw UDP there and the pump
/// forwards it, TURN-encapsulated, to/from the peer's own relayed address.
#[derive(Default)]
pub struct RelayManager {
    sessions: HashMap<[u8; 32], RelaySession>,
}

struct RelaySession {
    /// `127.0.0.1:<port>` — set as the peer's WG endpoint; boringtun talks to this.
    shim_addr: SocketAddr,
    /// Our TURN relayed address for this peer — reported so the peer learns where to send to us.
    relayed: SocketAddr,
    /// Pushes the peer's relayed address to the pump once the coordinator has learned it.
    peer_relayed_tx: watch::Sender<Option<SocketAddr>>,
    /// The bridge task; dropping it (session removed) aborts the forward and frees the allocation.
    _task: JoinHandle<()>,
}

impl RelayManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ensure a relay session exists for `peer` (allocating on first sight) and push the peer's
    /// latest relayed address to the pump. Returns the local shim address to use as the peer's WG
    /// endpoint, or `None` if allocation failed (retried on the next refresh).
    #[allow(clippy::map_entry)] // the branch does async allocation the entry API can't express
    pub async fn ensure(&mut self, peer: [u8; 32], info: &RelayInfo) -> Option<SocketAddr> {
        if !self.sessions.contains_key(&peer) {
            match RelaySession::start(info).await {
                Ok(s) => {
                    tracing::info!(relayed = %s.relayed, turn = %info.turn_addr, "relay: allocated");
                    self.sessions.insert(peer, s);
                }
                Err(e) => {
                    tracing::warn!(turn = %info.turn_addr, "relay: allocation failed ({e:#})");
                    return None;
                }
            }
        }
        let s = &self.sessions[&peer];
        // Ignore send errors: a closed receiver means the pump died and the session will be pruned.
        let _ = s.peer_relayed_tx.send(info.peer_relayed);
        Some(s.shim_addr)
    }

    /// Drop sessions for peers no longer relayed (pruned, or now directly/punch reachable), freeing
    /// their allocations.
    pub fn retain(&mut self, keep: &std::collections::HashSet<[u8; 32]>) {
        self.sessions.retain(|pk, _| keep.contains(pk));
    }

    /// True if we hold an active relay session for `peer` (used to keep `need_relay` asserted and to
    /// mark the peer `Relayed` — otherwise the working relay tunnel looks "connected", drops out of
    /// `need_relay`, and the coordinator would withdraw the relay, flapping it).
    pub fn is_relaying(&self, peer: &[u8; 32]) -> bool {
        self.sessions.contains_key(peer)
    }

    /// Our relayed addresses per peer, to report to the coordinator (relayed-candidate exchange).
    pub fn allocations(&self) -> Vec<RelayAllocation> {
        self.sessions
            .iter()
            .map(|(pk, s)| RelayAllocation {
                peer: *pk,
                relayed: s.relayed,
            })
            .collect()
    }
}

impl RelaySession {
    async fn start(info: &RelayInfo) -> anyhow::Result<Self> {
        // Local socket the TURN client uses to reach the relay's server.
        let turn_conn = Arc::new(
            UdpSocket::bind("0.0.0.0:0")
                .await
                .context("binding TURN client socket")?,
        );
        let client = Client::new(ClientConfig {
            stun_serv_addr: String::new(),
            turn_serv_addr: info.turn_addr.to_string(),
            username: info.username.clone(),
            password: info.credential.clone(),
            realm: info.realm.clone(),
            software: String::new(),
            rto_in_ms: 0,
            conn: turn_conn,
            vnet: None,
        })
        .await
        .context("creating TURN client")?;
        client.listen().await.context("TURN client listen")?;
        let relay_conn = client.allocate().await.context("TURN allocate")?;
        let relayed = relay_conn.local_addr().context("relayed local_addr")?;

        // Loopback socket boringtun talks to (the peer's WG endpoint points here).
        let shim = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .context("binding relay shim socket")?,
        );
        let shim_addr = shim.local_addr().context("shim local_addr")?;

        let (peer_relayed_tx, mut rx) = watch::channel(info.peer_relayed);
        let task = tokio::spawn(async move {
            let _client = client; // hold the client so the allocation stays refreshed
            let mut peer_relayed = *rx.borrow();
            let mut bt: Option<SocketAddr> = None; // boringtun's source, learned on first packet
            let mut egress = vec![0u8; 1600]; // boringtun → peer
            let mut ingress = vec![0u8; 1600]; // peer → boringtun
            loop {
                tokio::select! {
                    changed = rx.changed() => {
                        if changed.is_err() { break; } // manager dropped the session
                        peer_relayed = *rx.borrow_and_update();
                    }
                    // boringtun → peer: forward through our allocation to the peer's relayed address.
                    r = shim.recv_from(&mut egress) => {
                        let Ok((n, from)) = r else { break };
                        bt = Some(from);
                        if let Some(dst) = peer_relayed {
                            let _ = relay_conn.send_to(&egress[..n], dst).await;
                        }
                    }
                    // peer → boringtun: deliver relayed packets back to boringtun's endpoint.
                    r = relay_conn.recv_from(&mut ingress) => {
                        let Ok((n, _)) = r else { break };
                        if let Some(dst) = bt {
                            let _ = shim.send_to(&ingress[..n], dst).await;
                        }
                    }
                }
            }
        });

        Ok(Self {
            shim_addr,
            relayed,
            peer_relayed_tx,
            _task: task,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler(max: usize) -> CappedAuth {
        CappedAuth {
            secret: "s3cret".into(),
            max_allocations: max,
            active: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    #[test]
    fn cap_limits_distinct_clients_but_allows_refresh() {
        let h = handler(2);
        let u = (common::now_unix() + 3600).to_string();
        let a: SocketAddr = "10.0.0.2:1".parse().unwrap();
        let b: SocketAddr = "10.0.0.3:1".parse().unwrap();
        let c: SocketAddr = "10.0.0.4:1".parse().unwrap();
        assert!(h.auth_handle(&u, "unitylan", a).is_ok());
        assert!(h.auth_handle(&u, "unitylan", b).is_ok());
        // A refresh from an already-counted client still passes even at the cap.
        assert!(h.auth_handle(&u, "unitylan", a).is_ok());
        // A new client over the cap is refused.
        assert!(h.auth_handle(&u, "unitylan", c).is_err());
    }

    #[test]
    fn expired_credential_refused() {
        let h = handler(8);
        let past = (common::now_unix() - 1).to_string();
        let a: SocketAddr = "10.0.0.2:1".parse().unwrap();
        assert!(h.auth_handle(&past, "unitylan", a).is_err());
    }
}
