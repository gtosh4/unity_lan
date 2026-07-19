# Changelog

All notable changes to UnityLAN are documented here. Versions follow [Semantic
Versioning](https://semver.org/); while on `0.x`, minor bumps may carry breaking changes.

## Unreleased

### Added

- **`unitylan ctl update`** applies a staged auto-update from the command line, and `ctl status` now
  reports whether one is available and staged. Only the GUI could trigger an update before, which
  left a headless install able to see a release but not take it.

### Fixed

- **A quiet mesh could sit half an attestation TTL on an old version.** A published release was
  staged only when a `/refresh` long-poll returned — but a device whose membership never changes
  (a solo install, or any idle mesh) parks that request for the full hold, ~15 minutes at the
  default TTL, so no update offer appeared until then. The register response carries the same
  signed manifest, so it is staged from there too and an offer now appears at startup.

## v0.3.0

**Wire protocol 4 → 5, and versioning that actually does something.** `PROTOCOL_VERSION` was
advertised but never enforced: the coordinator logged a warning and served the request anyway, and
the engine never read the coordinator's version at all — so a bump was a comment, not a gate. (The
note under v0.2.0 below claimed a mismatch was rejected; it never was. Corrected there.)

Clients now advertise a **range** and the coordinator picks the highest version both speak,
refusing only a non-overlapping one with `426 Upgrade Required` — naming both ranges and which side
is stale. The support window is **current + one previous**, so a client has a full release cycle to
auto-update before a coordinator stops answering it, and coordinator and clients no longer have to
be upgraded in lockstep. Features that need no break ride **capability flags** instead of a bump.

The 4 → 5 bump itself is the P2P response envelope gaining an unknown-variant fallback (below).

### Added

- **Fleet version visibility.** The admin dashboard and `/metrics`
  (`unitylan_devices_online_by_version`) now show how many online devices run each release — so an
  operator can confirm the fleet is fully updated before retiring a phased wire change.
- **Admin per-network counts split users from devices** — a user with three devices in a network
  reads as one user, three devices, instead of a single ambiguous number.
- **`unitylan-engine --token` flag** for scripted/headless enrollment.

### Changed

- **The GUI update flow is actionable.** The dead "update available" notice is gone; when a newer
  engine is staged (or already running under an older GUI process) the window offers a one-click
  relaunch instead of leaving the user to restart by hand.
- **Windows MSI starts the service and launches the GUI on install**, so a fresh install comes up
  without a manual service start.
- **Enrollment keys now expire**, bounding the window a leaked one-time key can be redeemed.
- **Linux auto-update ships engine + GUI together** (`.tar.gz`, was the bare engine binary). The
  GUI↔engine control protocol carries no version, so updating only the engine left an older GUI
  talking to a newer daemon. Windows already did this via the MSI's `MajorUpgrade`. A bare artifact
  is still accepted, so manifests published before this change keep working.
- The engine treats a protocol refusal as terminal rather than transient: a 5-minute backoff instead
  of hammering at `refresh_secs`, and a red banner in the GUI carrying the coordinator's message.

### Fixed

- **Exposed ports survive a restart**, and `unexpose` now closes the exact scope it was given (an
  all-peers rule and a per-network rule on the same port no longer clobber each other).
- **A newer peer's P2P reply broke older peers.** The request envelope degraded an unknown type to
  `Unsupported`, but the *response* envelope had no such fallback, so a future reply variant was a
  decode failure on an older caller. Extensibility now runs both directions.
- **One unverifiable peer could deny the whole mesh.** Seed verification failed the entire batch on a
  single bad attestation; it now skips that peer (still fail-closed — never routed) and logs at error
  level only when *every* seed fails, which is the signature of a substitution attack rather than
  version skew.
- **Attestation layouts are now versioned — compatibly.** They're signed as postcard, which is
  positional and not self-describing, so a layout change could decode to wrong values rather than
  erroring, and a client handed a layout it doesn't know can't even tell. The layout a blob is in is
  now named in the JSON envelope (`GuildAttestation.att_schema`), which — unlike the signed bytes —
  can gain a field compatibly. Clients from this release read both the original layout and the new
  `schema`-tagged one; the coordinator keeps emitting the original to any client that hasn't
  advertised the `attestation-v2` capability, so **every existing v0.2.0 client keeps working
  unchanged**. Emission switches over in a later release once the support floor covers the
  capability. `RotationCert` stays frozen — its chains are walked forever.

## v0.2.0

**Wire protocol 3 → 4.** The bump covered the STUN change below — a coordinator that advertises
`stun_port` where a v0.1.0 client expects `stun_addr`, which degrades to "no STUN" rather than
breaking. Nothing enforced the version in this release; see Unreleased above.

### Changed

- **STUN: the coordinator advertises a port, not an address.** It can't know its own
  client-reachable address behind a container bridge or a cloud NAT, so `stun_bind` doing double
  duty as both the UDP bind and the advertised address left no working value. The coordinator now
  sends only the port (`RegisterResp.stun_port`), and the client pairs it with the coordinator
  hostname it already dials — reachable by construction, and the right host regardless since STUN
  is UDP and no HTTP proxy can front it.

### Fixed

- **Engine on non-domain Windows hosts.** Secret ACL restriction granted access to the process
  account by name; as a LocalSystem service that's `WORKGROUP\<HOST>$`, which `icacls` can't
  resolve on a workgroup machine — so every secret write (`wg.key`, token, relay secret) failed
  and the daemon exited right after login. The redundant machine-account grant is gone; the
  service reads its secrets via the already-granted SYSTEM SID.
- **Admin dashboard graph labels.** Network nodes labelled with the bare role name collided when
  the same name was registered in more than one guild; they now read `guild: role`. The role table
  drops its separate id column, moving the id into a chip beside the name.
- **Release CI.** The announce job read a webhook secret under the wrong name and exited 3.

### Internal

- Coordinator container image builds with BuildKit cache mounts for dependency compilation.
- The engine logs the STUN bootstrap address it resolved, and `scripts/dev-run.sh` forwards
  `RUST_LOG` through `sudo env` so debug logging is reachable on the normal dev path.

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
- Windows `.msi`: engine + GUI, bundles the WireGuard driver (pinned by SHA-256), registers **and
  starts** the service, and offers a "Launch UnityLAN now" checkbox on the final wizard page so a
  first install lands the user straight in the app to log in. (The silent auto-update path stays
  quiet — swaps files and restarts the service without popping the GUI.)
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
