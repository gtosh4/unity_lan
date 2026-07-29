# Proxy crate

Terminates TLS for this device's **web services** so the app behind one needs no certificate
configuration of its own. Root `CLAUDE.md` has the project-wide rules.

**It is a separate process for one reason: privilege.** The engine is root (Linux) / LocalSystem
(Windows) because it drives WireGuard, the firewall and the resolver. Parsing HTTP sent by mesh peers
is the archetypal work that must not happen there. Anything that moves request handling back into the
engine gives that away — a root engine with no `[proxy] user` **refuses** to start this
(`engine/src/proxy.rs::run_as`) rather than running it privileged, and that refusal is the feature,
not an inconvenience to route around.

**It is a client of the engine, not a peer of it.** The whole configuration — names to serve, the
loopback port behind each, who may reach it, where the certificate is — arrives on the engine's
existing `Watch` push (`common::control::StatusReport`), and there is no config file. Two
consequences to preserve: a renewal or a newly-named service needs no restart, and when the engine is
unreachable this serves **nothing** — its last word may already be stale, and serving on a narrowed
allow-list is the failure the whole design is arranged to avoid.

**It connects to the engine's read-only endpoint** — `control-ro.sock` / `unitylan-control-ro`,
derived by `common::control::readonly_endpoint`, bound with `control::server::Access::ReadOnly`. That
endpoint answers `Status` and `Watch` and refuses everything else *at the socket*; the full one
grants device authority (`Expose`, `Logout`, `ApplyUpdate`) and is the control group's / SYSTEM's
alone. Keep it that way: pointing this process at the full socket, or granting its account the
control group, undoes the isolation the separate process exists for — a compromised HTTP parser would
then be able to open ports and apply updates. On unix the read-only socket is owned by the proxy
account's own primary group; on Windows `NT AUTHORITY\LocalService` is granted on that pipe only.

**Two gates, both fail closed.** The engine's firewall opens 443 to the union of everyone allowed
*some* web service; `route.rs` narrows that to the one actually asked for, which the packet filter
cannot distinguish once they share a port. An empty allow-list is nobody, not everybody. A name no
service answers to gets a 404 — never a default backend, which is how a proxy quietly serves the
wrong thing.

**Forwarding is loopback-only by construction.** The destination is built from a port the engine
supplied, never from anything in the request. A proxy a caller can aim is an open relay into whatever
the backend's network reaches.

**The listener is handed over, not bound — on unix.** 443 is privileged and this process
deliberately cannot take it, so the engine binds it and `dup2`s it onto the descriptor named by
`common::control::PROXY_LISTEN_FD_VAR`. So: take that socket **once** and keep it for the process's
life, swapping only what is served on it. Rebuilding the listener per config change works exactly
once with a handed-over descriptor. Windows has no privileged-port concept — the service binds 443
itself and this does not apply.

**Windows is unverified.** The `#[cfg(windows)]` paths (a second SCM service under
`NT AUTHORITY\LocalService`, started and stopped by the engine) have never been compiled: cross-checking
`x86_64-pc-windows-msvc` from Linux stops in ring's build script. Build on real Windows before
trusting any change to them.

Behaviour is covered end-to-end by `scripts/cert-test.sh`, which runs this binary against a
pebble-issued certificate with a plain-HTTP backend. `route.rs`'s access decision is a pure function
and unit-tested — keep it that way; it is where a mistake hands one member another member's service.
