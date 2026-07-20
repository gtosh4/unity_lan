# Changelog

All notable changes to UnityLAN are documented here. Versions follow [Semantic
Versioning](https://semver.org/); while on `0.x`, minor bumps may carry breaking changes.

## Unreleased

### Added

- **Ports can be exposed to just your own devices.** A new scope sits alongside "all peers" and the
  per-network ones, and it goes by identity rather than membership: only your other devices reach
  the port, no matter what networks you and everyone else share. Useful for the things you run for
  yourself — a syncthing instance, an SSH port on a home server — that until now had to be opened to
  every co-member of a network to be reachable at all. In the GUI it's a checkbox in the new scope
  picker; from the command line it's `unitylan-engine ctl expose <port> --own-devices`
  (and `ctl unexpose … --own-devices` to close it again). Startup exposures in `engine.toml` can
  name a scope too — `net = "<name>"` or `own_devices = true` on an `[[expose]]` entry — where
  before they could only ever open a port to every peer.
- **One port can be exposed to several networks at once.** Tick as many as apply and each becomes
  its own exposure, so you can close one later without disturbing the rest.

### Changed

- **The config file moved out of the middle of every command.** It used to be a positional argument
  wedged between the verb and what you were acting on — `ctl expose /etc/unitylan/engine.toml 25565
  minecraft` — and it was mandatory on some subcommands but optional on others, with no way to tell
  which from `--help`. It's now a single `-c/--config` option that defaults to `engine.toml` in the
  working directory, so the common case is just `unitylan-engine ctl status` and the argument you
  care about comes first: `unitylan-engine ctl expose 25565 minecraft`. When `-c` is absent the
  config is looked up in the working directory first and then where the package installed it
  (`/etc/unitylan/engine.toml`; beside the exe or under `%ProgramData%\UnityLAN` on Windows), so on
  an installed system the flag is usually unnecessary — `sudo unitylan-engine ctl status` works from
  any directory. A path given with `-c` is never second-guessed: a typo fails loudly instead of
  silently resolving to a different deployment, and when the search finds nothing the error lists
  every location it tried. **This breaks existing
  scripts and unit files**, which need the path moved ahead of the subcommand as `-c <path>`; the
  packaged systemd unit is updated for you. Alongside it, `--help` now documents every `ctl`
  subcommand and its arguments (most had no description at all), `ctl net` and `ctl own-devices`
  list their valid actions instead of failing at runtime, and the WireGuard/DNS/resolver commands
  meant only for the test scripts no longer clutter the top-level command list.

### Fixed

- **One interrupted shutdown could leave the engine unable to start ever again.** If tearing down the
  interface wedged, systemd eventually killed the engine outright, and the killed process left its
  WireGuard control socket behind — after which every start failed with `Address already in use` and
  the service simply restart-looped until someone deleted the file by hand. A socket with nothing
  behind it is now recognised as the leftover it is and cleared automatically; one that is still
  answering is left strictly alone, since that means another engine is running. Shutdown also now
  reverts the firewall and DNS settings *before* the interface, so the changes that outlive the
  process are undone even when that last step is what hangs, and it gives up after fifteen seconds
  instead of holding a stop — or a reboot — for a minute and a half.
- **Running the engine once by hand could break the service afterwards.** Doing so leaves the
  WireGuard runtime directory owned by your user, and the service, which deliberately runs with
  almost no privileges, then can't write there. The failure surfaced as a bare `Permission denied`
  that made no sense for a daemon running as root; it now says which directory is wrong, who owns
  it, and how to fix it.
- **Two devices on the same network could never reach each other if the router wouldn't hairpin.**
  Both got handed the router's public address, dialed it, and the handshake quietly never landed —
  yet status kept reporting them as `Direct`, so nothing ever escalated to ICE and there was nothing
  in the log to explain it. A peer that never completes a handshake is now treated as stuck no
  matter how it was reached, which both tells the truth in `ctl status` and lets ICE take over,
  where the local addresses the two devices already share can be used directly.
- **A stalled ICE attempt hung forever instead of retrying.** Waiting on a peer that never answered,
  or a negotiation that failed outright, parked the agent silently for the life of the process — the
  only trace was an `ice: agent started` line with nothing after it. A failed negotiation now ends
  as soon as it fails, the agent is replaced (with a growing delay, so a peer that has actually gone
  away isn't retried at full tilt), and the reason it gave up is logged.
- **A connected ICE path sat unused for up to a full refresh cycle.** Once ICE found a working route
  to a peer, nothing told the tunnel to start using it — the new path was only picked up the next
  time the engine heard from the coordinator, which for an otherwise-idle mesh could be many minutes
  of a peer staying unreachable after it had become reachable. The engine now notices within seconds.
- **A port scoped to one community's network could be reached from another community's.** Networks
  were matched by role name alone, so if two of your Discord servers each had a role with the same
  name — an `Engineering` in both — a port you opened to one was reachable by the *other* server's
  members too. Scopes now carry the community as well as the role, and are listed and labelled as
  `role @ community` so you can tell them apart. If you had exposed a port to a role name that
  exists in two of your communities, that exposure now admits **nobody** until you re-open it
  against the community you meant: the old setting cannot say which one it was, and guessing is how
  the wrong people got in. Exposures naming a role unique to one community keep working untouched,
  and `ctl expose <port> <role>` still takes a bare name — it resolves on its own unless the name is
  ambiguous, in which case it now refuses and asks for `--guild`.

  Networks are now identified internally by their Discord guild and role ids rather than by their
  names, so renaming a role or a community no longer changes what a port is exposed to, and two
  identically-named roles can never be confused. **This needs a coordinator running this release or
  newer**: an older one doesn't send those ids, and rather than guess, the client treats such a
  network as un-exposable — a port scoped to one stays closed until the coordinator is updated.
  Upgrade the coordinator before, or together with, the clients.

### Changed

- **Name lookups stayed broken on hosts running Tailscale even once traffic flowed.** Clearing
  Tailscale's block let peers reach each other, but `.unity.internal` names still failed: a lookup
  goes to this machine's *own* mesh address, and the kernel loops that back on the loopback
  interface, where an exemption written for the mesh interface never applies. Both paths are now
  exempt — the loopback one scoped to just this host's own address.
- **Tailscale's mesh-range block is now cleared automatically.** Tailscale installs a firewall rule
  that drops UnityLAN's `100.64.0.0/10` addresses on any interface that isn't its own, which
  blackholes the entire mesh while peers still look perfectly reachable. The engine already spotted
  this and told you the command to run; it now inserts the exemption itself, re-checks it whenever
  the firewall reconciles (Tailscale rebuilds its rules on restart, discarding it), and removes it
  on shutdown. Set `tailscale_compat = false` to go back to being told rather than fixed. Linux only.

||||||| 11d81f8
- **The exposed-ports list now shows who can actually reach each port.** Every port is one row with
  a labelled chip per scope that can reach it, instead of one look-alike row per scope; a chip whose
  peers are all offline is marked, since the port is open but nothing can currently connect. Each
  chip closes just that scope, and the row closes all of them.
- **Exposing a port no longer means typing the network name.** The scope is a picker built from the
  networks you're actually in, TCP/UDP is a toggle rather than a `udp/34197` prefix, and the port
  field reports a bad value as you type instead of after you submit.

## v0.3.1

### Added

- **`unitylan ctl update`** applies a staged auto-update from the command line, and `ctl status` now
  reports whether one is available and staged. Only the GUI could trigger an update before, which
  left a headless install able to see a release but not take it.

### Fixed

- **A failed Windows install could leave the machine unable to install UnityLAN again.** Registering
  the engine service was all-or-nothing: if the service name was already taken, or was still held by
  a just-deleted service the SCM hadn't finished releasing, `service install` failed — and because
  the MSI treats that step as fatal, the whole install rolled back (error 1722 → 1603). An
  interrupted uninstall was enough to trigger it, and the half-removed product it left behind then
  broke every later attempt, including the auto-update's. Both states are now expected: an existing
  service is stopped and repointed at the new install, and a name still being released is waited out.
- **The Windows installer put a 64-bit build under `C:\Program Files (x86)`.** The MSI was being
  built as a 32-bit package despite its `-x64.msi` name, so the engine, GUI, and wireguard-nt driver
  DLL all installed into the 32-bit program folder. Fresh installs now land in `C:\Program Files\
  UnityLAN`; an existing install is moved there on upgrade — see the note below if you edited
  `engine.toml`.
- **A quiet mesh could sit half an attestation TTL on an old version.** A published release was
  staged only when a `/refresh` long-poll returned — but a device whose membership never changes
  (a solo install, or any idle mesh) parks that request for the full hold, ~15 minutes at the
  default TTL, so no update offer appeared until then. The register response carries the same
  signed manifest, so it is staged from there too and an offer now appears at startup.

### Upgrade note (Windows)

Because the install folder moves from `C:\Program Files (x86)\UnityLAN` to
`C:\Program Files\UnityLAN`, this upgrade replaces the old installation rather than updating it in
place — **a hand-edited `engine.toml` is not carried across**, and the new location gets the shipped
default. If you self-host a coordinator, re-apply your `coordinator` (and `enrollment_key`) settings
in the new folder and restart the service:

```powershell
notepad "$env:ProgramFiles\UnityLAN\engine.toml"
sc.exe stop UnityLANEngine; sc.exe start UnityLANEngine
```

Device identity is unaffected — keys, token, and pinned anchors live in `%ProgramData%\UnityLAN`,
which this does not touch, so the device keeps its IP and hostname.

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
