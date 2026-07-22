# Changelog

All notable changes to UnityLAN are documented here. Versions follow [Semantic
Versioning](https://semver.org/); while on `0.x`, minor bumps may carry breaking changes.

## v0.4.1

### Security

- Binary auto-updates can now be signed by a **dedicated release key** whose private half is held
  offline in the release pipeline, never on a coordinator — so a leaked *guild* signing key can forge
  attestations but can no longer sign a malicious engine update and push root code to every member of
  that guild. Clients built with the release public key baked in (`UNITYLAN_RELEASE_PUBKEY`) verify
  updates against it alone and won't downgrade to the old guild-signed path once a coordinator offers
  a release-key-signed manifest. Generate the key with `unitylan-coordinator gen-release-key`, sign a
  release with `sign-release`, and paste the resulting blob into `[release] signed_blob`. Existing
  guild-signed updates keep working during the transition, so coordinators and clients can upgrade on
  their own schedules; the guild-signed path can be retired once the fleet has the release key baked
  in.
- Enrolling a device now proves it holds the WireGuard private key it registers, so someone who
  merely learned your (not-yet-enrolled) public key can no longer bind it to their own account and
  block you from joining. This release ships the check in **observe-only** mode: the coordinator
  verifies a proof when one is sent and logs any enrollment that omits one, but still lets it
  through, so a coordinator can upgrade ahead of its clients without breaking new-device enrollment.
  Watch `unitylan_enrollments_unproven_total` in `/metrics`; once it stops climbing your fleet is
  proof-clean and you can set `require_proof = true` under `[enrollment]` to reject proof-less
  enrollments outright. A future release will make that the default.
- Engine keys and bearer credentials are now created owner-only and installed atomically, closing
  the write-before-chmod window and preventing a pre-existing symlink from redirecting a secret
  write. The coordinator likewise creates its signing-key database privately before SQLite opens it.
- A coordinator now caps how many client long-polls it holds at once (`max_longpolls`, default 4096)
  and allows only one parked request per device, so a single account can no longer tie up every
  connection slot and starve everyone else's refreshes. A device turned away at the ceiling gets a
  `429` and retries normally. Raise the limit only alongside the coordinator's and the reverse
  proxy's open-file limits — see `docs/coordinator-setup.md`.
- Coordinators now refuse unsafe security settings at startup, including weak admin tokens,
  unreasonable attestation lifetimes, and malformed, non-HTTPS, duplicate, or oversized update
  artifacts.

### Changed

- Installing an auto-update is far less disruptive to the mesh. The engine used to announce its
  departure before restarting onto the new binary, so every peer dropped you and then had to
  rediscover you and punch a fresh path through NAT — often tens of seconds of dead tunnels for an
  update that took one. It now stays registered across the restart and keeps its firewall and DNS
  setup in place, so peers see nothing worse than a missed handshake and traffic resumes within
  seconds. (Tunnels still briefly drop; the engine and the WireGuard data plane share a process
  today, so nothing can survive the swap. A truly seamless upgrade needs them split apart.)
- The coordinator now caches each guild's name briefly instead of asking Discord for it on every
  client refresh. Under a membership-change herd — when many clients wake and rebuild their
  snapshots at once — this collapses what was one Discord request per client into one per guild,
  so a large mesh no longer risks tripping Discord's per-guild rate limit on that lookup.

## v0.4.0

### Added

- **Two devices on the same network now connect directly instead of flapping.** Peers behind the
  same router used to tunnel through the router's public address (a "hairpin"), which many home
  routers do unreliably — so the link kept dropping. Each engine now announces itself on the local
  segment (this device's WireGuard key and port only, nothing else, and it never leaves the segment)
  so same-network peers use each other's direct address, falling back to the old route if the direct
  path doesn't work. On by default; `beacon = false` in `engine.toml` to disable, `beacon_port` to
  change the port.
- **A peer changing reachability is now logged.** When a peer goes down or comes back — or shifts
  between direct, ICE, relayed, and unreachable — the engine logs the transition with the peer and
  time since its last handshake, so an intermittently-dropping peer leaves a timestamped trail
  instead of only a fluctuating `ctl status`.
- **The engine can also write its logs to a file.** Logs still print to the console; now they can
  additionally be appended (plain text, no colour codes) to a file, so a foreground
  `unitylan-engine run` isn't lost when its output scrolls away. Set `log_file = "engine.log"` in
  `engine.toml` (a relative path lands in the state directory) or `--log-file <path>` per-invocation,
  which overrides the config.
- **Ports can be exposed to just your own devices.** A new scope alongside "all peers" and the
  per-network ones, keyed by identity rather than membership: only your other devices reach the port,
  no matter what networks you share. Useful for things you run for yourself — a syncthing instance,
  an SSH port on a home server — that until now had to be opened to every co-member to be reachable
  at all. In the GUI it's a checkbox in the new scope picker; from the CLI it's
  `unitylan-engine ctl expose <port> --own-devices` (and `ctl unexpose … --own-devices`). Startup
  `[[expose]]` entries in `engine.toml` can name a scope too — `net = "<name>"` or
  `own_devices = true`.
- **One port can be exposed to several networks at once.** Tick as many as apply and each becomes
  its own exposure, so you can close one later without disturbing the rest.
- **The admin dashboard now counts devices that are online but on no network.** A device with all
  its networks toggled off is still live — it long-polls the coordinator and stays reachable to its
  owner's other devices — but it used to be missing from the "devices online" total and the
  per-version fleet breakdown, so a client on no network was invisible when checking whether the
  fleet had finished updating. Such devices now count, with a new **off-network devices** card
  (`devices_off_network` field / `unitylan_devices_off_network` metric).

### Changed

- **An auto-update now switches to the new version on its own, without help from a service manager.**
  On Linux, applying an update used to swap the engine on disk and then exit, relying on systemd's
  `Restart=always` to bring the new version back up. An engine started any other way — foreground,
  a container entrypoint, a supervisor that doesn't restart on a clean exit — would swap the binary
  and simply stop. The engine now tears down tunnel, firewall, and DNS cleanly and relaunches itself
  in place, so the update completes however it was started (and systemd still sees one continuously-
  running process, no restart gap).

- **Windows auto-updates are now a lightweight file swap instead of a full installer upgrade.**
  Applying an update used to re-run the whole MSI installer over itself — stopping and re-registering
  the service, re-laying every file — the fragile part that could roll back and wedge a machine. The
  engine now downloads a small bundle, swaps its program file in place (staging the new app so an open
  window updates too), tears down tunnel/firewall/DNS cleanly, and lets Windows restart the service —
  the same swap-in-place Linux already uses. A still-published `.msi` keeps working exactly as before,
  now with an install log at `%ProgramData%\UnityLAN\update-msi.log`. A failed update is reported in
  the log on the next start instead of silently staying on the old version.

- **The mesh now leans on peer-to-peer attestation refresh far longer before falling back to the
  coordinator.** With peer-direct refresh (gossip) on, a credential is renewed straight from that
  peer over the tunnel; only when peer-direct can't refresh it and it's within two minutes of
  expiring does the client pull a full renewal from the coordinator. Before, that concession window
  was a full long-poll hold (~15 min) overlapping the entire peer-direct window, so the coordinator
  re-signed and re-sent every attestation on most renewals even when the peers could have carried it.
  The coordinator now does that work only for credentials the mesh genuinely couldn't refresh — no
  change to how quickly an offline or revoked peer drops (still on attestation expiry).

- **The config file moved out of the middle of every command.** It used to be a positional argument
  wedged between the verb and its target — `ctl expose /etc/unitylan/engine.toml 25565 minecraft` —
  mandatory on some subcommands but optional on others, with no way to tell which from `--help`. It's
  now a single `-c/--config` option defaulting to `engine.toml` in the working directory, so the
  common case is just `unitylan-engine ctl status` and the argument you care about comes first:
  `ctl expose 25565 minecraft`. Without `-c` the config is looked up in the working directory first,
  then where the package installed it (`/etc/unitylan/engine.toml`; beside the exe or under
  `%ProgramData%\UnityLAN` on Windows), so on an installed system the flag is usually unnecessary. A
  path given with `-c` is never second-guessed: a typo fails loudly instead of silently resolving to
  a different deployment, and a failed search lists every location it tried. **This breaks existing
  scripts and unit files**, which need the path moved ahead of the subcommand as `-c <path>`; the
  packaged systemd unit is updated for you. Alongside it, `--help` now documents every `ctl`
  subcommand (most had no description at all), `ctl net` and `ctl own-devices` list their valid
  actions instead of failing at runtime, and the test-only WireGuard/DNS/resolver commands no longer
  clutter the top-level command list.
- **The peer list stops reshuffling on every latency update.** Peers are still ordered by ping, but
  now by a smoothed (rolling-average) latency instead of the raw reading, so normal probe-to-probe
  jitter no longer swaps near-equal peers back and forth each poll. The number on each row is still
  the latest measured round-trip — only the list order is damped.
- **Tailscale's mesh-range block is now cleared automatically.** Tailscale installs a firewall rule
  dropping UnityLAN's `100.64.0.0/10` addresses on any interface that isn't its own, blackholing the
  entire mesh while peers still look perfectly reachable. The engine already spotted this and told
  you the command to run; it now inserts the exemption itself, re-checks it whenever the firewall
  reconciles (Tailscale rebuilds its rules on restart, discarding it), and removes it on shutdown.
  Name lookups needed a second exemption: a `.unity.internal` lookup goes to this machine's *own*
  mesh address, which the kernel loops back on the loopback interface, where a rule scoped to the
  mesh interface never applies — so the loopback path is now exempt too, scoped to just this host's
  own address. Set `tailscale_compat = false` to be told rather than fixed. Linux only.
- **The exposed-ports list now shows who can actually reach each port.** Every port is one row with
  a labelled chip per scope, instead of one look-alike row per scope; a chip whose peers are all
  offline is marked. Each chip closes just that scope, and the row closes all of them.
- **Exposing a port no longer means typing the network name.** The scope is a picker built from the
  networks you're actually in, TCP/UDP is a toggle rather than a `udp/34197` prefix, and a bad port
  is reported as you type instead of after you submit.

### Fixed

- **Windows devices now refresh their credentials directly from peers, not only through the
  coordinator.** Peer-direct refresh (co-members renewing each other's short-lived attestations over
  the tunnel, sparing the coordinator) never worked toward a Windows peer: the Windows firewall
  backend opened the WireGuard and beacon ports but not the peer-direct port, so every such request
  was silently dropped and those peers fell back to the coordinator for every renewal (logging
  repeated failures). The port is now opened on the mesh interface, matching the Linux backend.

- **Peers no longer flash offline in the GUI when another member comes online.** Every refresh
  rebuilt the status snapshot with all peers momentarily marked down, restoring their real state a
  beat later — invisible normally, but a member coming online triggers a burst of refreshes, so the
  whole peer list would blink. The engine now carries each peer's last-known liveness across the
  rebuild. Always cosmetic — the tunnels never dropped.

- **A member coming online no longer floods the log with firewall churn.** When a device joined,
  every other member re-logged an `apply_state` line and rewrote its firewall rules several times a
  second for a few seconds — the coordinator sends each refresh's peers in a different order, and the
  engine treated the reordering as a real membership change. It now sorts members before comparing,
  so unchanged membership does no work. Always cosmetic — no tunnel was touched.

- **Upgrading UnityLAN on Windows wiped your config and failed the install.** Every in-place upgrade
  (and the auto-update) deleted `engine.toml` mid-install and never restored it, so the service
  couldn't be registered and the installer rolled back — leaving the old files on disk but no running
  service, and your coordinator/enrollment settings gone. The config now lives at
  `%ProgramData%\UnityLAN\engine.toml`, created and owned by the engine rather than the installer, so
  an upgrade or uninstall never touches it. A config from an older install (kept next to the program
  files) is migrated automatically, and the installer writes a working default when the config is
  briefly absent, so a fresh install or recovery always comes up running. Upgrading *from* a pre-fix
  version (0.3.1 or earlier) still resets the config that one time — the old installer deletes its own
  copy before the new engine can rescue it — but the upgrade now completes and the service starts
  (re-enter coordinator/enrollment once via the GUI); every upgrade after that keeps your edits.
- **A Windows upgrade no longer risks wedging on the service itself.** The installer used to delete
  and recreate the engine service on every upgrade; if anything held the old service open (an open
  Services console was enough), the deletion lingered and blocked the recreate, failing the upgrade
  with no service left behind. Upgrades now stop and reconfigure the service in place — nothing to
  linger, and a failed upgrade leaves the service intact rather than gone.
- **Upgrading the Linux package now restarts the engine onto the new version.** `apt`/`dnf` replaced
  the binary on disk but left the old one running until you restarted the service or rebooted — so a
  fix didn't take effect on its own. The upgrade now restarts a running engine automatically (a
  first-time install, service not yet enabled, is left untouched), matching the in-app auto-update.
  Expect a brief reconnect.
- **A Windows device could be unreachable to the whole mesh, blamed on "symmetric NAT".** On Windows
  the engine drives the WireGuard driver directly and — unlike the reference WireGuard app — never
  opened its own UDP listen port on the host firewall, so Windows Defender dropped every inbound
  handshake before it reached the tunnel: peers could see the device but never connect, and
  `ctl status` reported `unreachable: symmetric NAT?` when the real cause was the firewall. The engine
  now opens the listen port automatically (while the host firewall is enabled), matching what it
  relies on the distro firewall to allow on Linux. A self-managed Linux firewall must still permit
  the WireGuard `listen_port` — the engine only manages the Windows side. The status hint now names
  all three possible causes (NAT, a blocked UDP port, or no relay) instead of guessing symmetric NAT.
- **Two UnityLAN devices behind one router would fight over the same port, and one lost silently.**
  Every device asks its router to forward port 51820 by default, but a router can forward it to only
  one device — so the second's request was refused and it fell back to advertising no endpoint, going
  unreachable with only a single log line. When the preferred port is taken the engine now asks for
  the next one up (and reports the swap), so a second or third device behind the same NAT becomes
  reachable without manual port juggling.
- **One interrupted shutdown could leave the engine unable to start ever again.** If tearing down the
  interface wedged, systemd eventually killed the engine, and the killed process left its WireGuard
  control socket behind — after which every start failed with `Address already in use` and the service
  restart-looped until someone deleted the file by hand. A socket with nothing behind it is now
  recognised as leftover and cleared; one still answering is left strictly alone (another engine is
  running). Shutdown also now reverts firewall and DNS settings *before* the interface, so changes
  that outlive the process are undone even when that last step hangs, and it gives up after fifteen
  seconds instead of holding a stop — or a reboot — for a minute and a half.
- **Running the engine once by hand could break the service afterwards.** Doing so leaves the
  WireGuard runtime directory owned by your user, and the near-unprivileged service then can't write
  there. The failure surfaced as a bare `Permission denied` that made no sense for a root daemon; it
  now says which directory is wrong, who owns it, and how to fix it.
- **Two devices on the same network could never reach each other if the router wouldn't hairpin.**
  Both got handed the router's public address, dialed it, and the handshake quietly never landed —
  yet status kept reporting them as `Direct`, so nothing escalated to ICE and nothing in the log
  explained it. A peer that never completes a handshake is now treated as stuck however it was
  reached, which both tells the truth in `ctl status` and lets ICE take over, using the local
  addresses the two devices already share.
- **A stalled ICE attempt hung forever instead of retrying.** Waiting on a peer that never answered,
  or a negotiation that failed outright, parked the agent silently for the life of the process — the
  only trace an `ice: agent started` line with nothing after it. A failed negotiation now ends as
  soon as it fails, the agent is replaced (with a growing delay, so a peer that has actually gone away
  isn't retried at full tilt), and the reason it gave up is logged.
- **A connected ICE path sat unused for up to a full refresh cycle.** Once ICE found a working route,
  nothing told the tunnel to use it — the new path was only picked up next time the engine heard from
  the coordinator, which on an idle mesh could be many minutes. The engine now notices within seconds.
- **A port scoped to one community's network could be reached from another community's.** Networks
  were matched by role name alone, so if two of your Discord servers each had a role with the same
  name — an `Engineering` in both — a port you opened to one was reachable by the *other* server's
  members too. Scopes now carry the community as well as the role, listed and labelled as
  `role @ community`. If you had exposed a port to a role name that exists in two communities, that
  exposure now admits **nobody** until you re-open it against the community you meant: the old setting
  cannot say which one it was, and guessing is how the wrong people got in. Exposures naming a role
  unique to one community keep working, and `ctl expose <port> <role>` still takes a bare name,
  resolving on its own unless ambiguous, in which case it refuses and asks for `--guild`.

  Networks are now identified internally by their Discord guild and role ids rather than names, so
  renaming a role or community no longer changes what a port is exposed to, and two identically-named
  roles can never be confused. **This needs a coordinator running this release or newer**: an older
  one doesn't send those ids, and the client treats such a network as un-exposable — a port scoped to
  it stays closed until the coordinator is updated. Upgrade the coordinator before, or with, the
  clients.
- **A one-time enrollment key could enrol more than one device.** The coordinator checked whether a
  key was unused and then bound it in two separate steps, so two registrations racing the same leaked
  key with two different device keys could both slip past the check and both enrol. The claim is now a
  single atomic step, so exactly one of any racing pair wins and a "one-time" key really does admit
  only one device.
- **The engine's control socket was briefly world-reachable as it started.** On Linux the socket was
  created at default permissions and only tightened to owner/group a moment later, leaving a window in
  which any local user could connect and drive the daemon. It is now created locked down from the
  outset, and if the tightening that opens it to the intended group ever fails the socket stays
  private rather than falling open.
- **A downgrade couldn't be forced by replaying an old update.** The engine already refused to
  "update" to a version at or below the one it runs, but a stale, still-validly-signed offer for a
  version between the two could be replayed to walk a client back onto a release with a known flaw.
  Once the engine has seen a given release it now refuses any older one, signed or not.

### Security

- **The coordinator now authenticates each device by its bearer token, not just its WireGuard key.**
  A device's public key is shared with every co-member (it rides in each peer's seed), so it was
  never a secret — yet after enrollment the coordinator would serve anyone who presented a known key
  the full snapshot for that device (its networks, peers, trust anchors, and relay/ICE credentials)
  and accept presence, endpoint, and relay changes in its name. Register and refresh now require the
  device token the coordinator issued at enrollment. The client already stores that token, so nothing
  changes for you; the switch is per-device and automatic, so a mesh keeps working through the upgrade
  even before every client has updated — a device is only held to the token once it has presented the
  correct one at least once. Update the coordinator to close the exposure.
- **A member could no longer pull another member's device-management token.** Because a device's
  WireGuard *public* key travels in every co-member's peer list, anyone you share a network with
  already knows it — and the coordinator used to hand back a device's control token to any request
  that merely named its public key, letting a co-member rename, remove, or re-assign your devices.
  The coordinator now returns that token only on the request that first enrolls a device (where the
  caller proved ownership with a one-time enrollment key or an interactive login); the client keeps
  it from there, so nothing legitimate changes.
- **A member can no longer redirect another peer's hole-punch to an address of their choosing.**
  When two peers are both behind NAT, the coordinator relays each one the other's observed address to
  punch toward. It now accepts a reported address for a peer only when its IP matches where that peer
  itself connects to the coordinator from, so a co-member can't feed everyone a made-up address and
  make their connection attempts fire at an unrelated host.

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
