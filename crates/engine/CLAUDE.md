# Engine crate

Data plane, privileged daemon: WireGuard, host firewall, DNS resolver, control socket. Root
`CLAUDE.md` has the project-wide rules (trust model, wire-type ladder, CI gates) — this file is the
engine-specific part.

**Platform split.** OS-specific code = separate modules selected at runtime:
`wg/{userspace,windows}.rs`, `fw/{nftables,windows}.rs`, `resolver/{linux,windows}.rs`. Userspace
WireGuard (boringtun) is the portable primary; kernel drivers (Linux netlink, Windows wireguard-nt via
`wireguard.dll`) are per-OS optimizations. Windows is a first-class target — keep both sides of every
platform split in mind. `cargo test` is platform-aware too: Windows runs the `fw/windows.rs` +
`resolver/windows.rs` arg-construction tests, Linux the nftables/resolved ones.

**Upgrade steps go in the *new* binary's startup, not the apply path.** An update is applied by the
version you're coming *from*: `selfupdate::apply*` and the GUI's relaunch are the **old** release's
code during the very transition that ships them, so a fix placed there doesn't take effect until the
release *after* — and on-disk state an older version left behind never gets repaired at all. Split of
duties: **apply** puts the new bytes on disk; **startup** reconciles whatever the old version left. So
anything reconciling such state goes in a startup hook, which always runs new code: `daemon::run`
(beside `selfupdate::reconcile_update_marker` — e.g. the Windows `selfupdate::promote_staged_gui`,
which finishes a GUI a previous engine only half-staged) or `service::ensure_config` (config bootstrap
+ migration). Two Windows facts the promotion path leans on: a *running* image can't be overwritten but
**can** be renamed aside (how `self_replace` works), and `current_exe()` keeps reporting the
**load-time** path after such a rename — so an old GUI relaunching the canonical path still lands on the
new bytes. Install-dir writes must come from the **engine** (LocalSystem); the unprivileged GUI has
read+execute only under `%ProgramFiles%`.

**NAT traversal.** Direct P2P isn't free behind NAT. The engine runs a userspace **ICE** agent
(`ice.rs`, `nat.rs`): STUN candidate gathering (the coordinator answers STUN binding requests,
`coordinator/src/stun.rs`) plus UDP hole-punching, with a ciphertext-only **TURN relay** fallback
(`relay.rs`) for pairs a punch can't connect. The coordinator only **brokers** — exchanges ICE
candidates over long-poll, pairs a relay peer with a stuck client — and stays **off the traffic path**:
a relay is another *peer*, never the coordinator.

**Named services.** `mesh_services.rs` (not `service.rs` — that is the Windows SCM/config module) holds
what peers announce they serve and resolves a contested name. Two rules that must not drift: a
coordinator-allocated **device name always outranks** a self-asserted service label, and among service
claims the **lowest public key wins** — arbitrary but total, so every device on the mesh reaches the
same answer for a name it cannot arbitrate remotely. Announcement is peer-direct (`p2p.rs`), scoped at
the *announcer* by `fw::Firewall::services_for`, so a peer that cannot reach a port is never told the
name exists. `proxy.rs` supervises the TLS proxy — see `crates/proxy/CLAUDE.md`; the refusal to run it
as root lives there and is deliberate.

**Certificates.** `cert.rs` runs the whole ACME DNS-01 conversation on the device: it makes the
keypair, talks to the CA, keeps the private key. The coordinator only publishes the challenge TXT it
derives from our own allocation. CA rate limits shape the module more than anything else — the account
key is created once per device lifetime and persisted, issuance is refused while a valid certificate
exists, and failures are recorded so retries back off. Burning a limit locks the device, or the whole
deployment, out for the window.

Debugging a running daemon over its control socket: use the `debug-engine` skill.
