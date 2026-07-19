# Changelog

All notable changes to UnityLAN are documented here. Versions follow [Semantic
Versioning](https://semver.org/); while on `0.x`, minor bumps may carry breaking changes.

## v0.1.0 — first release

The first tagged release of UnityLAN: a WireGuard mesh VPN whose membership is defined by **Discord
roles**. An admin registers a role as a network with `/unitylan network add`; everyone holding that
role forms direct, peer-to-peer WireGuard tunnels with everyone else. Lose the role, lose access.

This is pre-1.0 software. It works end to end on Linux and Windows, but treat it as young.

### Highlights

- **Discord roles are the membership source.** A *network* is a Discord role (never `@everyone`).
  Role changes propagate to the mesh within seconds — live gateway events evict a revoked member
  immediately, even if they're offline.
- **Direct P2P WireGuard data plane.** The coordinator carries no traffic and holds no peer private
  keys. Once tunnels are up, the mesh keeps running with the coordinator barely involved.
- **Short-lived signed attestations.** One Ed25519 signing key per Discord guild is the trust
  anchor; clients pin it on first contact (TOFU) and verify every peer against it, so a compromised
  guild key's blast radius is one guild. Attestations bind user + device + IP + WireGuard key and
  expire on a configurable TTL, making revocation self-enforcing.
- **Human-readable names.** `<device>.<user>.unity.internal`, plus a bare `<user>.unity.internal`
  alias for a member's primary device. An authoritative in-engine resolver serves the zone; the OS
  is wired to it per-link via systemd-resolved (Linux) or NRPT (Windows), leaving global DNS alone.
- **Default-deny host firewall.** Joining a network exposes nothing. Inbound on the mesh interface
  is dropped except ICMP echo and ports you `expose` — optionally scoped to a single network's
  members. Regular LAN and localhost traffic is untouched. nftables on Linux, Windows Defender
  Firewall on Windows.
- **Desktop GUI + CLI.** An unprivileged iced app (peers, networks, exposed ports, connect/disconnect,
  system tray) driving a privileged engine over a local control socket; `ctl` covers the same
  surface headlessly.

### NAT traversal

- UPnP-IGD port mapping and explicit-endpoint configuration for directly dialable nodes.
- Coordinator-mediated UDP hole punching using peer-observed reflexive addresses.
- A userspace **ICE** agent (STUN candidate gathering + checks) on the userspace WireGuard backend,
  with the coordinator answering STUN binding requests as a fallback when no relay peer is online.
- A **ciphertext-only TURN relay** fallback for pairs a punch structurally can't connect
  (symmetric NAT / CGNAT). A relay is another *peer*, never the coordinator; it holds no keys.
  Opt-in (`relay = false` by default) with a concurrent-allocation cap.
- Per-peer reachability shown in the GUI and `ctl status`: direct, hole-punching, ICE, relayed, or
  unreachable.

### Coordinator

- Discord OAuth2 auth-code + **PKCE** login (the client is a public client — no secret on devices),
  plus one-time enrollment keys for headless game servers.
- Slash commands for networks, enrollment, and primary-device management; gateway events drive live
  revocation.
- Long-poll discovery (`/register` + `/refresh`) instead of gossip flood: clients park until
  membership changes or the hold elapses. Membership versions are scoped per guild so a change in
  one guild never wakes another.
- Scale work on the fan-in/fan-out path: cached signed attestations across snapshots, jittered herd
  wakes, targeted wakeups for pair-specific NAT updates, client-assisted delta sync, and
  **peer-direct attestation refresh** — peers keep each other fresh over their own tunnels, so an
  established mesh survives a coordinator outage.
- Operator **admin dashboard** with an anonymized network↔user graph and Prometheus `/metrics`,
  behind a token gate.
- Offline **key rotation** with signed `prev → new` rotation certs, so clients re-pin automatically
  across one or many rotations without manual steps.
- Per-deployment mesh CIDR (signed and overlap-checked), and single-container Docker deployment.

### Client / engine

- Portable **userspace WireGuard** (boringtun) as the primary backend; **wireguard-nt** on Windows
  as a kernel optimization.
- Runs as a systemd service (Linux) or a Windows service; the GUI never manages the process
  lifecycle — its on/off is a mesh connect/disconnect that works even when the coordinator is
  unreachable.
- Per-network peering toggles and a global pause, both persisted client-side and enforced locally.
- Signed **auto-update**: the coordinator serves a manifest signed with the deployment anchor; the
  engine verifies before applying. Off unless configured; the manual manifest + SIGHUP reload keeps
  a human in the loop.
- Clean uninstall — full host teardown (interface, firewall, resolver hooks) on stop, plus a purge
  path.

### Packaging

- Linux `.deb` / `.rpm`: `unitylan` (engine + CLI, headless) and `unitylan-desktop` (adds the GUI).
  Installation creates a `unitylan` group so the desktop GUI can reach the engine socket.
- Windows `.msi`: engine + GUI, bundles the WireGuard driver (pinned by SHA-256), registers the
  service.
- Coordinator container image (Alpine).
- CI gates every change on `cargo fmt`, `clippy -D warnings`, the full test suite, and `cargo audit`.

### Known limitations

- **Release artifacts are unsigned.** The MSI in particular will trigger SmartScreen "unknown
  publisher". Verify `SHA256SUMS` before installing.
- **Windows is compile- and unit-test-verified, not yet validated on real hardware** — the wg-nt
  backend, NRPT resolver, firewall, service, tray, and MSI self-update apply path have not been run
  on a live Windows box. Treat Windows as beta.
- **macOS and mobile are not supported yet.** The data plane is portable userspace WireGuard by
  design, so they're planned, not present.
- **NAT traversal is young.** Direct, punched, ICE, and relayed paths all work, but they haven't
  been hardened across every network shape. Restricted-cone direct-pair selection and pure-bootstrap
  (no relay peer online) cases can't be faithfully emulated in the test harness.
- The engine runs as root with no in-process privilege separation, mitigated by systemd capability
  bounding and sandboxing.
- Single coordinator per client: a client trusts one deployment at a time. Multi-coordinator
  (federated meshes) is planned.
- No arm64 builds, no apt/dnf repository, and the coordinator image is single-arch.

### Security

Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).

### License

AGPL-3.0-or-later. Running a modified coordinator as a service obliges you to offer users the
corresponding source.
