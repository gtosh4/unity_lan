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

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::net::UdpSocket;
use turn::auth::LongTermAuthHandler;
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use webrtc_util::vnet::net::Net;

/// A running embedded TURN server. Holds the server task alive; [`stop`](Self::stop) tears it down.
pub struct RelayServer {
    server: Server,
}

impl RelayServer {
    /// Start a TURN server bound to `bind` (UDP), advertising `public_ip` as the relayed address
    /// clients reach it at, authorizing credentials minted against `secret`.
    pub async fn start(
        bind: SocketAddr,
        public_ip: IpAddr,
        secret: String,
    ) -> anyhow::Result<Self> {
        // turn itself allocates no sockets — we hand it the listener (an `Arc<UdpSocket>` is a
        // `webrtc_util::Conn`). The relay generator hands each allocation a relayed address on
        // `public_ip` (the dialable IP co-members reach us at), bound on all local interfaces.
        let conn = Arc::new(
            UdpSocket::bind(bind)
                .await
                .with_context(|| format!("binding TURN UDP socket {bind}"))?,
        );
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
            auth_handler: Arc::new(LongTermAuthHandler::new(secret)),
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await
        .context("starting TURN server")?;
        tracing::info!(%bind, %public_ip, "relay: TURN server up");
        Ok(Self { server })
    }

    /// Stop the server, closing all allocations.
    pub async fn stop(&self) -> anyhow::Result<()> {
        self.server.close().await.context("closing TURN server")?;
        Ok(())
    }
}
