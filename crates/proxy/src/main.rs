//! UnityLAN TLS proxy: serves this device's **web** services on the mesh, so a browser reaches
//! `https://jellyfin.alice.mesh.unitylan.com` with no warning page and the service behind it needs
//! no TLS configuration of its own.
//!
//! **A separate, unprivileged process on purpose.** The engine is root (Linux) / LocalSystem
//! (Windows) because it drives WireGuard, the firewall and the resolver. Parsing HTTP from mesh
//! peers is exactly the kind of work that should not happen there, so this runs as its own user with
//! no privileges: it reads the certificate and key through the group the engine grants them to
//! (`[cert] group`), talks only to loopback backends, and holds nothing else.
//!
//! It is a **client of the engine**, not a peer of it: the whole configuration — which names to
//! serve, which loopback port each is, who may reach it, where the certificate lives — arrives over
//! the engine's control channel on the same `Watch` subscription the GUI uses, and updates live. So
//! a renewed certificate or a newly-named service needs no restart, and there is no config file to
//! drift.
//!
//! Specifically the engine's **read-only** endpoint (`control-ro.sock`, `unitylan-control-ro`),
//! which answers `Status` and `Watch` and refuses every mutation. The full socket grants authority
//! over the whole device — expose a port, log out, apply an update — and this process must not hold
//! it: that is the same reason it runs unprivileged at all.
//!
//! Two independent gates decide who gets in, and both fail closed. The engine's firewall opens 443
//! to the union of everyone allowed *any* web service; this process then narrows that to the one
//! service actually asked for — a distinction the packet filter cannot make once every service
//! shares a port.

mod route;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use common::control::{ControlRequest, ControlResponse, StatusReport};
use http_body_util::BodyExt;
use hyper::header::{HeaderValue, HOST};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use interprocess::local_socket::tokio::prelude::*;
use interprocess::local_socket::tokio::Stream as LocalStream;
#[cfg(not(windows))]
use interprocess::local_socket::GenericFilePath;
#[cfg(windows)]
use interprocess::local_socket::GenericNamespaced;
use interprocess::local_socket::Name;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use route::{Decision, Routes};

/// How long to wait before reconnecting to the control socket. The engine restarting (an update, a
/// crash) is the common case, and it comes back in seconds.
const RECONNECT: Duration = Duration::from_secs(2);

/// Everything needed to serve, as of the engine's last word. `None` fields mean "not yet" rather
/// than "never" — the engine may not have a mesh address or a certificate at the moment we ask.
#[derive(Clone, Default, PartialEq)]
struct Live {
    /// This device's mesh address; we bind only there, never `0.0.0.0`. Binding every interface
    /// would publish every mesh service to whatever LAN the machine happens to sit on.
    bind: Option<Ipv4Addr>,
    cert_path: Option<String>,
    key_path: Option<String>,
    /// The certificate's expiry, used purely as a change signal: it moves exactly when a renewal
    /// lands, which is when the files on disk are worth re-reading.
    cert_expires_at: u64,
    routes: Vec<common::control::ProxyRoute>,
}

impl Live {
    fn from(report: &StatusReport) -> Self {
        Self {
            bind: report.device.as_ref().map(|d| d.wg_ip),
            cert_path: report.cert.cert_path.clone(),
            key_path: report.cert.key_path.clone(),
            cert_expires_at: report.cert.expires_at,
            routes: report.proxy_routes.clone(),
        }
    }

    /// Whether there is anything to serve: a place to bind, a certificate to serve it with, and at
    /// least one route. Missing any of them means we hold no port at all, rather than listening and
    /// refusing everything.
    fn servable(&self) -> Option<(Ipv4Addr, &str, &str)> {
        if self.routes.is_empty() {
            return None;
        }
        Some((
            self.bind?,
            self.cert_path.as_deref()?,
            self.key_path.as_deref()?,
        ))
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().expect("a valid default filter")),
        )
        .init();
    let socket = PathBuf::from(
        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "control-ro.sock".to_string()),
    );
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run(socket))
}

async fn run(socket: PathBuf) -> anyhow::Result<()> {
    // The ring provider is the one this binary is built with; installing it explicitly means a
    // future default-provider change is a compile error rather than a runtime panic on first
    // connection.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("installing the rustls crypto provider"))?;

    let (tx, rx) = watch::channel(Live::default());
    tokio::spawn(serve_loop(rx));
    subscribe(socket, tx).await
}

/// Follow the engine's status forever, republishing what it implies for us.
///
/// Reconnects rather than exiting: the engine restarting is routine (an auto-update swaps it), and a
/// proxy that died with it would leave every service down until something noticed.
async fn subscribe(socket: PathBuf, tx: watch::Sender<Live>) -> anyhow::Result<()> {
    loop {
        match watch_once(&socket, &tx).await {
            Ok(()) => tracing::warn!("the engine closed the status stream; reconnecting"),
            Err(e) => tracing::warn!("control socket: {e:#}; retrying"),
        }
        // Serve nothing while the engine is unreachable. Its last word may already be stale — a
        // service withdrawn, a scope narrowed — and serving on a stale allow-list is exactly the
        // failure this is here to prevent.
        tx.send_if_modified(|live| std::mem::take(live) != Live::default());
        tokio::time::sleep(RECONNECT).await;
    }
}

async fn watch_once(socket: &std::path::Path, tx: &watch::Sender<Live>) -> anyhow::Result<()> {
    let stream = LocalStream::connect(to_name(socket.to_path_buf())?)
        .await
        .context("connecting to the engine control socket")?;
    let mut reader = BufReader::new(stream);
    let mut req = serde_json::to_vec(&ControlRequest::Watch)?;
    req.push(b'\n');
    reader.get_mut().write_all(&req).await?;
    reader.get_mut().flush().await?;

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(()); // engine closed the stream
        }
        let resp: ControlResponse =
            serde_json::from_str(line.trim()).context("decoding a status line")?;
        let ControlResponse::Status(report) = resp else {
            continue;
        };
        let live = Live::from(&report);
        tx.send_if_modified(|held| {
            if *held == live {
                return false;
            }
            *held = live;
            true
        });
    }
}

fn to_name(path: PathBuf) -> std::io::Result<Name<'static>> {
    #[cfg(windows)]
    {
        common::control::pipe_name(Some(&path)).to_ns_name::<GenericNamespaced>()
    }
    #[cfg(not(windows))]
    {
        path.to_fs_name::<GenericFilePath>()
    }
}

/// What a connection is served with right now. Swapped as the engine's word changes; `None` means
/// there is nothing to serve, and connections are closed rather than answered.
type Serving = Option<(TlsAcceptor, Routes)>;

/// Follow the configuration, republishing what each connection should be served with.
///
/// The **listener is taken once and kept**, not rebuilt per change: it is usually a socket the
/// engine bound and handed over — 443 is privileged and this process deliberately cannot take it —
/// so dropping it would mean never getting it back. Only what is served on it changes.
async fn serve_loop(mut rx: watch::Receiver<Live>) {
    let (serving_tx, serving_rx) = watch::channel(Serving::None);
    let mut listener: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        let live = rx.borrow_and_update().clone();
        let next = match live.servable() {
            Some((bind, cert, key)) => match load_tls(cert, key) {
                Ok(acceptor) => Some((
                    SocketAddr::from((bind, common::control::HTTPS_PORT)),
                    acceptor,
                )),
                Err(e) => {
                    // Not fatal: the engine may be mid-renewal, or the key's group may not have
                    // reached us yet. Keep serving what we already were rather than dropping it.
                    tracing::warn!("certificate not usable ({e:#}); keeping the previous one");
                    None
                }
            },
            None => None,
        };

        match next {
            Some((addr, acceptor)) => {
                let count = live.routes.len();
                serving_tx.send_replace(Some((acceptor, Routes::new(live.routes))));
                if listener.is_none() {
                    let rx = serving_rx.clone();
                    listener = Some(tokio::spawn(async move {
                        if let Err(e) = listen(addr, rx).await {
                            tracing::error!("listener on {addr} stopped: {e:#}");
                        }
                    }));
                    tracing::info!(%addr, services = count, "serving web services");
                } else {
                    tracing::info!(services = count, "configuration updated");
                }
            }
            // The listener stays up holding its port; with nothing to serve it closes what arrives.
            // The engine stops us outright when there is nothing left, so this is a brief state.
            None => {
                serving_tx.send_replace(None);
                tracing::info!("nothing to serve");
            }
        }

        if rx.changed().await.is_err() {
            return; // the subscriber is gone; nothing left to follow
        }
    }
}

fn load_tls(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
        std::fs::File::open(cert_path).with_context(|| format!("opening {cert_path}"))?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .context("reading the certificate chain")?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
        std::fs::File::open(key_path).with_context(|| format!("opening {key_path}"))?,
    ))
    .context("reading the private key")?
    .context("the key file holds no private key")?;

    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("building the TLS configuration")?;
    // Advertise only what we serve. Negotiating h2 we cannot speak would break every request that
    // took it up, and the backends are plain HTTP/1.1 anyway.
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

/// The listener to serve on: the one the engine handed over, or a freshly bound one.
///
/// The engine binds 443 because it can and we deliberately cannot — a process that dropped to an
/// unprivileged user has no capability to take a privileged port, which is exactly the property
/// worth having. Binding ourselves is the standalone path (a developer, a test) where we were
/// started with enough privilege to do it — and on Windows it is the *only* path: there is no
/// privileged-port concept there, so the engine hands nothing over and this service binds 443 as
/// `NT AUTHORITY\LocalService`.
fn listener_for(addr: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
    #[cfg(unix)]
    if let Ok(fd) = std::env::var(common::control::PROXY_LISTEN_FD_VAR) {
        let fd: i32 = fd
            .parse()
            .context("the handed-over listener is not a descriptor")?;
        // SAFETY: the engine `dup2`'d a bound, listening TCP socket onto exactly this descriptor
        // before exec'ing us, and nothing in this process has touched it since — we are the only
        // owner, so taking it is sound.
        return Ok(unsafe { <std::net::TcpListener as std::os::fd::FromRawFd>::from_raw_fd(fd) });
    }
    std::net::TcpListener::bind(addr).with_context(|| format!("binding {addr}"))
}

async fn listen(addr: SocketAddr, serving: watch::Receiver<Serving>) -> anyhow::Result<()> {
    let std_listener = listener_for(addr)?;
    std_listener
        .set_nonblocking(true)
        .context("making the listener non-blocking")?;
    let listener = TcpListener::from_std(std_listener).context("adopting the listener")?;
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Per-connection errors (a peer vanishing mid-handshake) must not take the listener
                // down with them — that would drop every service until the next config change.
                tracing::debug!("accept: {e}");
                continue;
            }
        };
        // Read the configuration per connection, so a renewal or a changed service set applies to
        // the next request without the port ever being let go.
        let Some((acceptor, routes)) = serving.borrow().clone() else {
            continue; // nothing to serve right now
        };
        tokio::spawn(async move {
            let SocketAddr::V4(peer_v4) = peer else {
                return; // we bind an IPv4 mesh address; anything else is not a mesh peer
            };
            let peer_ip = *peer_v4.ip();
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => return tracing::debug!(%peer, "tls handshake: {e}"),
            };
            let service = service_fn(move |req| handle(req, routes.clone(), peer_ip));
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .with_upgrades()
                .await
            {
                tracing::debug!(%peer, "connection: {e}");
            }
        });
    }
}

type Body = hyper::body::Incoming;

/// The **only** refusal this proxy ever gives a caller — one status, one body, for a name it may not
/// reach and for a name nothing answers to alike.
///
/// A single constant rather than a branch, because the property is that there is nothing to branch
/// on. Peer discovery deliberately withholds a scoped service from everyone outside its scope, so a
/// distinguishable 403 would hand that back to anyone willing to guess labels: a member could
/// enumerate which services its neighbours run without ever being allowed to reach one. 404 is the
/// honest answer to give someone for whom the name may as well not exist.
const REFUSAL: (StatusCode, &str) = (StatusCode::NOT_FOUND, "no such service here");

/// Route one request and forward it, or refuse it.
async fn handle(
    mut req: Request<Body>,
    routes: Routes,
    peer: Ipv4Addr,
) -> Result<
    Response<http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>>,
    hyper::Error,
> {
    let host = req
        .headers()
        .get(HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let port = match routes.resolve(&host, peer) {
        Decision::Forward(port) => port,
        refused => {
            // Which one it was goes to the local log and nowhere else.
            match refused {
                Decision::Forbidden => {
                    tracing::debug!(%peer, %host, "refused: outside this service's scope")
                }
                _ => tracing::debug!(%peer, %host, "refused: no service answers to this name"),
            }
            let (code, body) = REFUSAL;
            return Ok(status(code, body));
        }
    };

    // Take the upgrade future *before* the request is consumed, so a WebSocket (which Jellyfin and
    // most dashboards need) can be spliced once the backend agrees to it.
    let upgrade = hyper::upgrade::on(&mut req);
    let is_upgrade = req.headers().contains_key(hyper::header::UPGRADE);

    // Forwarding facts about the caller. Set, never appended to: an inbound `X-Forwarded-For` is
    // whatever the *client* chose to claim, and passing it through would let a peer forge its own
    // apparent address to the backend.
    let headers = req.headers_mut();
    headers.remove("x-forwarded-for");
    headers.remove("x-forwarded-proto");
    headers.remove("x-forwarded-host");
    if let Ok(v) = HeaderValue::from_str(&peer.to_string()) {
        headers.insert("x-forwarded-for", v);
    }
    headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    if let Ok(v) = HeaderValue::from_str(&host) {
        headers.insert("x-forwarded-host", v);
    }

    match forward(req, port, upgrade, is_upgrade).await {
        Ok(res) => Ok(res),
        Err(e) => {
            tracing::warn!(%host, port, "backend: {e:#}");
            Ok(status(
                StatusCode::BAD_GATEWAY,
                "the service is not answering",
            ))
        }
    }
}

/// Send the request to a loopback backend and return its response.
///
/// **Loopback only.** The address is built here from a port the engine supplied, never from
/// anything in the request — a proxy that can be pointed at an arbitrary host by its caller is an
/// open relay into whatever the backend's network can reach.
///
/// One connection per request rather than a pool: a home server's traffic does not need the pooling,
/// and a pool is state that can serve one caller's request on a connection opened for another.
async fn forward(
    req: Request<Body>,
    port: u16,
    upgrade: hyper::upgrade::OnUpgrade,
    is_upgrade: bool,
) -> anyhow::Result<Response<http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>>>
{
    let stream = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("connecting to 127.0.0.1:{port}"))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .context("http handshake with the backend")?;
    // `with_upgrades` so a 101 hands back the raw stream rather than ending the connection. The
    // task has to outlive `send_request`: the response *body* is still read off this connection
    // after the headers arrive, so ending it early truncates the response into an EOF the client
    // reports as a broken connection. It finishes on its own once the body is done.
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            tracing::debug!("backend connection: {e}");
        }
    });

    let mut res = sender.send_request(req).await.context("sending upstream")?;

    if is_upgrade && res.status() == StatusCode::SWITCHING_PROTOCOLS {
        let backend = hyper::upgrade::on(&mut res);
        tokio::spawn(async move {
            match tokio::try_join!(upgrade, backend) {
                Ok((client, backend)) => {
                    let (mut client, mut backend) = (TokioIo::new(client), TokioIo::new(backend));
                    // Both halves are opaque bytes from here — a WebSocket, or whatever else the two
                    // ends agreed on. Copy until either side hangs up.
                    if let Err(e) = tokio::io::copy_bidirectional(&mut client, &mut backend).await {
                        tracing::debug!("upgraded connection ended: {e}");
                    }
                }
                Err(e) => tracing::debug!("upgrade did not complete: {e}"),
            }
        });
        // The response itself (the 101) still goes back to the client to complete the handshake.
    }
    let (parts, body) = res.into_parts();
    Ok(Response::from_parts(parts, body.boxed()))
}

fn status(
    code: StatusCode,
    msg: &'static str,
) -> Response<http_body_util::combinators::BoxBody<hyper::body::Bytes, hyper::Error>> {
    let body = http_body_util::Full::new(hyper::body::Bytes::from_static(msg.as_bytes()))
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed();
    Response::builder()
        .status(code)
        .body(body)
        .expect("a status response with a static body is always well-formed")
}
