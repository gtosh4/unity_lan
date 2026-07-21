# Packaging

Distribution artifacts for UnityLAN.

| Target        | Package                         | Contents                          | Built by                        |
| ------------- | ------------------------------- | --------------------------------- | ------------------------------- |
| server        | `unitylan` .deb / .rpm          | engine daemon + CLI + systemd unit| `./build.sh`                    |
| desktop       | `unitylan-desktop` .deb / .rpm  | GUI; **depends on** `unitylan`    | `./build.sh`                    |
| windows       | `unitylan-<ver>-x64.msi`        | engine service + GUI + wireguard-nt | `windows/build.ps1`           |
| coordinator   | Docker image                    | coordinator server                | `docker/coordinator.Dockerfile` |

Installing `unitylan-desktop` pulls in `unitylan` automatically, so a desktop user gets the
engine, CLI, and GUI from one package. Servers install `unitylan` alone (no graphics libs).

## Build the packages

```sh
./build.sh          # needs cargo + nfpm; writes packaging/dist/*.{deb,rpm}
```

[nfpm](https://nfpm.goreleaser.com/install/) turns one spec into both `.deb` and `.rpm`,
so there is no per-distro build environment.

## Build the Windows installer

```powershell
packaging\windows\build.ps1            # needs Rust + WiX (dotnet tool install --global wix --version 5.0.2; v6+ needs the OSMF EULA)
```

The script builds the release exes, fetches the pinned wireguard-nt DLL (not committed), stages it
under `resources-windows\binaries\`, and runs `wix build` → `packaging\dist\unitylan-<ver>-x64.msi`.

The MSI installs the engine + GUI under `Program Files\UnityLAN`, drops a Start-menu shortcut, and
registers the `UnityLANEngine` LocalSystem service by calling the engine's own `service install`. See
[Windows install & run](#install--run-windows) below.

## Build the coordinator image

```sh
docker build -f packaging/docker/coordinator.Dockerfile -t unitylan-coordinator .
```

The image runs as a non-root `unitylan` user and carries a `HEALTHCHECK` against `/healthz`. The
build context is trimmed by the repo-root `.dockerignore` — critically, the coordinator's sqlite DB
(which holds the Ed25519 signing key) is excluded so it never lands in a build layer.

## Host the coordinator (server)

The release workflow pushes `ghcr.io/<owner>/unitylan-coordinator:<tag>` (and `:latest`) on every
`v*` tag, so a host just pulls the released image — no local build. Make the GHCR package **public**
once (GitHub → your profile → Packages → `unitylan-coordinator` → Package settings → Danger Zone →
Change visibility → Public) and the pull needs no auth:

```sh
docker pull ghcr.io/<owner>/unitylan-coordinator:v0.1.0
```

**1. Discord app prerequisites.** In the [Discord Developer Portal](https://discord.com/developers):
create an app, add a **bot** and copy its token, and note the app's **client ID**. Enable the
**Server Members Intent** (the coordinator reads member roles) and, under OAuth2, enable the
**Public Client** flag and register the loopback redirect `http://127.0.0.1:8765/callback` (the
engine runs PKCE as a public client — no client secret lives on the coordinator). Invite the bot to
each guild with the `applications.commands` + `bot` scopes so the `/unitylan` slash commands land.

**2. Write `coordinator.toml`** (real creds — keep it off disk-in-git; the repo's is gitignored):

```toml
bind     = "0.0.0.0:8080"          # bind all interfaces inside the container
database = "/data/coordinator.db"  # on the mounted volume — holds the Ed25519 signing key

[discord]
bot_token = "<your bot token>"

[oauth]
client_id = "<your app client id>"  # public client_id only; no secret/redirect here
```

Networks are added at runtime via the `/unitylan network add` slash command, so no `[[network]]`
seeds are needed in production. Omit the `[fake]` block entirely (that's offline-dev only), and do
**not** set `dev_auth = true` on a real deployment.

**3. Run it:**

```sh
docker run -d --name unitylan-coordinator --restart unless-stopped \
  -p 8080:8080 \
  -v $PWD/config:/etc/unitylan:ro \
  -v unitylan-data:/data \
  ghcr.io/<owner>/unitylan-coordinator:v0.1.0
```

Put `coordinator.toml` in a `./config` **directory** and mount the directory, not the file
(`ENTRYPOINT` reads `/etc/unitylan/coordinator.toml`). **Mount the dir, not the file:** a single-file
bind mount pins the host file's inode, so an editor that saves atomically (writes a temp file and
`rename()`s it over the original — vim, most editors, `sed -i`) swaps the inode and the container
keeps serving the **old** bytes. A directory mount resolves the path fresh on each open and picks up
the new inode. Either way the running process only re-reads config on restart or SIGHUP
(`docker kill -s HUP unitylan-coordinator` re-reads the `[release]` block; a `bind`/`[discord]`
change needs `docker restart`).

The container runs unprivileged and carries no traffic (control plane only). The `unitylan-data`
named volume persists `/data/coordinator.db` — **this holds the deployment's Ed25519 trust anchor
(signing key); back it up and never rebuild it**, or every enrolled peer's pinned anchor breaks.

**Or with Compose** (`docker compose up -d`):

```yaml
services:
  coordinator:
    image: ghcr.io/<owner>/unitylan-coordinator:v0.1.0
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ./config:/etc/unitylan:ro   # dir, not file — see above
      - unitylan-data:/data         # holds the Ed25519 signing key — back it up

volumes:
  unitylan-data:
```

**4. TLS / reverse proxy.** The coordinator speaks plain HTTP; front it with a reverse proxy
(Caddy / nginx / Traefik) terminating TLS on 443 and proxying to `:8080`. Engines pin the anchor,
but clients still reach the control API over the network — run it behind HTTPS in production. Set
`trusted_proxies` to the proxy's actual source CIDR so per-IP rate limits use the real client, keep
the proxy read timeout above the long-poll hold, and size both services' fd limits above
`max_longpolls` (default 4096); see `docs/coordinator-setup.md`.

**5. Publish an auto-update release** (optional): fill the `[release]` block (see
[Signed auto-update](#signed-auto-update)) and hot-reload without downtime —
`docker kill -s HUP unitylan-coordinator` re-signs and serves the new manifest.

## Automated releases

`.github/workflows/release.yml` runs on a `v*` tag: it builds the `.deb`/`.rpm` (amd64) and the
Windows `.msi` (x64), attaches all three to the GitHub Release, and pushes
`ghcr.io/<owner>/unitylan-coordinator:<tag>` + `:latest`. Cut a release with:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The package version comes from the tag (`VERSION=<tag without v> build.sh`). For arm64, add a
matrix leg that builds via [`cross`](https://github.com/cross-rs/cross).

Alongside the packages, the Linux job attaches **both** `unitylan-engine-linux-amd64` (the raw
binary) and `unitylan-linux-amd64.tar.gz` (engine + GUI), plus a `SHA256SUMS`; the Windows job
attaches the `.msi`, the `unitylan-windows-x64.tar.gz` auto-update bundle (engine + GUI), and
`SHA256SUMS-windows.txt`. These feed the auto-update below — see the phased rollout there for which
artifact to publish per platform.

## Signed auto-update

All crates share one version (`[workspace.package] version` in the root `Cargo.toml`). The wire
protocol carries a **negotiated range**: every client advertises `[MIN_PROTOCOL_VERSION,
PROTOCOL_VERSION]` (`common`) on register/refresh, the coordinator answers with the highest version
both speak, and only a range with **no overlap** is refused — `426 Upgrade Required`, naming both
ranges and which side is stale. The support window is **current + one previous**, so a client always
has a full release cycle to update before a coordinator stops answering it. Features that don't
require a break ride capability flags (`caps`) instead of a version bump.

Updates are **opt-in per deployment** and reuse the coordinator's existing Ed25519 trust anchor — no
new signing key. Add a `[release]` block to the coordinator config (see `coordinator.example.toml`)
naming the version and, per platform, the artifact URL + its SHA-256 (from the `SHA256SUMS` files
above) + size. The coordinator signs this manifest with its anchor at startup and serves it on the
long-poll. Each engine verifies it against its **pinned** anchor and, if the version is newer and an
artifact matches its platform, the GUI shows an **Update** button. Applying it downloads the
artifact, re-checks the SHA-256 against the signed manifest, then:

> **Which Linux artifact to publish (phased).** A **pre-0.3 engine** writes the artifact bytes
> straight over its own executable, so pointing it at the `.tar.gz` installs a gzip file as its
> binary and crash-loops it — a manual reinstall. While any pre-0.3 clients may still be out there,
> publish the raw `unitylan-engine-linux-amd64`; engines from 0.3 on handle either. Switch the
> `[release]` block to the bundle once every client is ≥ 0.3, which is also when the GUI starts
> being updated in lockstep.
>
> **Which Windows artifact to publish (phased).** Engines *before* the file-swap path only understand
> the `.msi`; engines from it on accept **either** (they sniff gzip magic — bundle → file-swap, else
> → MSI). So keep publishing the `.msi` while older Windows clients remain, and switch the Windows
> `[release]` artifact to `unitylan-windows-x64.tar.gz` once every client understands it, for the
> lighter, more robust upgrade. One caveat: the bundle carries **no wireguard-nt DLL**, so a release
> that bumps the DLL must be shipped as the `.msi` (which re-lays it), not the bundle.

- **Linux** — unpacks the `.tar.gz`, self-replaces the engine binary
  (`/usr/lib/unitylan/unitylan-engine`, symlinked onto PATH) in place, replaces the GUI at
  `/usr/bin/unitylan-gui` if one is installed, then tears down its tunnel/firewall/DNS cleanly and
  **re-execs the new binary in place** (same PID), so the update takes effect regardless of how the
  engine was started — a foreground `run`, a container entrypoint, or any supervisor, not just one
  that restarts on a clean exit. systemd (`Restart=always`, with `ReadWritePaths=/usr/lib/unitylan`)
  sees one continuously-running process — no restart gap — and still covers a crash; if the `exec`
  itself fails the engine falls back to `exit(0)` so a restart-on-exit supervisor recovers. **Both**
  binaries, because the
  GUI↔engine control protocol carries no version of its own — updating the engine alone left an
  older GUI talking to a newer daemon. A headless install (no GUI present) updates the engine only,
  and a bare (non-gzip) artifact is still accepted as the engine binary so manifests published
  before this change keep working. A GUI process already running when the swap happens shows a
  "relaunch to finish" notice, since replacing the file can't update a live process.
- **Windows** — unpacks the `unitylan-windows-x64.tar.gz` and, mirroring Linux, self-replaces the
  running `unitylan-engine.exe` in place and stages the new GUI beside it as `unitylan-gui.new.exe`,
  then tears its tunnel/firewall/DNS down cleanly and lets the **SCM restart the service** onto the
  new binary (a detached `service restart-after` helper waits for the stop, then starts it — Windows
  can't re-exec a service in place, but the SCM is a reliable supervisor). This deliberately avoids
  the MSI `MajorUpgrade` — no service re-registration, no DLL re-lay, none of the machinery that made
  installer-driven upgrades fragile. A running GUI shows a "relaunch to finish" notice and promotes
  its staged `.new.exe` itself (`swap_in_staged_gui`). For backward compatibility a **non-gzip
  artifact is treated as a legacy `.msi`** and applied the old way (launch `msiexec /quiet`, whose
  `MajorUpgrade` stops the service, replaces engine + GUI + DLL, and restarts) — now with an install
  log at `%ProgramData%\UnityLAN\update-msi.log`.

The coordinator only advertises a signed string (never the bytes), so this adds no data-plane load
and keeps it off the hot path — and the artifact download itself fans out to the URL host (GitHub
Releases / a CDN), never through the coordinator. Omit `[release]` to disable auto-update — clients
then just show a "newer version available" notice with no button.

Publishing a new release is an **admin action** (the coordinator does not poll or auto-discover):
edit the `[release]` block and `kill -HUP <coordinator-pid>` — it re-signs and serves the new
manifest with no restart and no dropped connections. A malformed edit is logged and the previous
manifest is kept serving. This keeps a human in the loop on what the mesh updates to. (SIGHUP is
unix-only; on Windows, restart the service.)

## One release covers every configuration — the two fork axes

The design goal is a **single package/release regardless of the node's environment**. Two things
could naively force separate builds; neither does:

### DNS resolver backend — handled at runtime

The engine picks its resolver backend at runtime (`resolver::platform_hook`): systemd-resolved
today, resolvconf / NetworkManager / others later. The package therefore only **recommends**
`systemd-resolved` — it never hard-depends on it. Adding a new backend is a code change in the
engine, not a new package. `resolver_hook` is best-effort: if no backend is available, meshing
still works, names just don't auto-resolve.

### Init system — one directory per system, not one package per system

The service unit is init-specific, so it lives under `init/<system>/`:

```
init/systemd/unitylan-engine.service   ← shipped today
init/openrc/…                          ← drop-in slot (add file + one contents: entry)
```

To support another init system, add its unit under `init/<system>/` and reference it from an
`nfpm/*.yaml` `contents:` entry. The binary and config are unchanged, so this stays one release.

## Layout

```
init/systemd/unitylan-engine.service   systemd unit (root; CAP_NET_ADMIN + CAP_NET_BIND_SERVICE)
config/engine.toml                     installed to /etc/unitylan/engine.toml (config, noreplace)
scripts/engine-*.sh                    maintainer scripts (daemon-reload, restart on upgrade, stop/disable on remove, wipe state on purge)
gui/unitylan-gui.desktop               desktop launcher (points at /run/unitylan/control.sock)
nfpm/engine.yaml, nfpm/desktop.yaml    package specs → deb + rpm
docker/coordinator.Dockerfile          coordinator image
build.sh                               binaries + all four packages
```

## Install & run (engine node)

```sh
sudo apt install ./dist/unitylan_<ver>_amd64.deb      # or: rpm -i dist/unitylan-<ver>.x86_64.rpm
sudoedit /etc/unitylan/engine.toml                    # set coordinator + enrollment_key
sudo usermod -aG unitylan $USER                       # drive the engine without root (re-login after)
sudo systemctl enable --now unitylan-engine
```

Runtime deps (`iproute2`, `nftables`) install automatically. The daemon runs as root with
`CAP_NET_ADMIN` for the userspace WireGuard interface, the nftables firewall, and `resolvectl`.

> **GUI ↔ daemon socket.** The daemon runs as root and owns `/run/unitylan/control.sock` (mode 660,
> `root:unitylan`). The postinstall creates the `unitylan` group and the systemd unit runs the engine
> with `Group=unitylan`, so `/run/unitylan` and the socket are group-owned by `unitylan`. Add your
> desktop user to that group (the `usermod` step above) and log back in — then the GUI/CLI connect
> without root.

## Install & run (Windows)

```powershell
msiexec /i unitylan-<ver>-x64.msi          # installs to Program Files\UnityLAN, registers + starts the service
# Self-hosting? Repoint the coordinator first, then restart the service:
# notepad "$env:ProgramData\UnityLAN\engine.toml"    # set coordinator (+ enrollment_key) as admin
# sc.exe stop UnityLANEngine; sc.exe start UnityLANEngine
```

The MSI registers `UnityLANEngine` as a **LocalSystem auto-start service** (via the engine's own
`service install`) and **starts it immediately** — no reboot needed. On an interactive install the
final wizard page has a **"Launch UnityLAN now"** checkbox (checked by default) that opens the GUI in
your desktop session so you can log in straight away; the GUI connects to the engine over the
`\\.\pipe\unitylan-control` named pipe. Re-open it any time from the **UnityLAN** Start-menu shortcut.

On first install the engine writes a default `engine.toml` at `%ProgramData%\UnityLAN\engine.toml`
(the MSI itself ships no config — the engine owns it, so upgrades never touch it) pointing at the
hosted coordinator, so a hosted-coordinator user is meshing after login with no config edit. A
**self-hoster** should repoint `coordinator` there (elevated) and restart the service — the first
auto-start harmlessly fails to enroll against the wrong coordinator (the start action is best-effort
and never blocks the install).

> The silent auto-update path (`msiexec /quiet`) shows none of this wizard UI: it swaps the files and
> restarts the service, but does **not** pop the GUI.

The wireguard-nt DLL ships inside the MSI at
`Program Files\UnityLAN\resources-windows\binaries\wireguard-amd64.dll` — defguard loads it by that
path relative to the engine exe, and the service pins its working directory to the install folder so
it resolves. Uninstalling (Add/Remove Programs) stops and removes the service.

## Upgrading

Two independent paths land a node on a new version; both **preserve your config and device identity**
and both end with the new engine binary running as the service.

The **in-app auto-update** (opt-in, user-triggered from the GUI) is documented above under
[Signed auto-update](#signed-auto-update): the engine verifies a signed manifest, the GUI shows an
**Update** button, and applying it swaps the engine binary in place on **both** platforms — Linux
re-execs it (same PID), Windows lets the SCM restart the service — with a legacy `.msi` still accepted
on Windows. This section is the other path — an admin upgrading the **OS package** (or MSI) directly.

### Linux (`.deb` / `.rpm`)

```sh
sudo apt install ./dist/unitylan_<newver>_amd64.deb    # or: rpm -U dist/unitylan-<newver>.x86_64.rpm
```

- **Binary + unit** are replaced (`/usr/lib/unitylan/unitylan-engine`, the systemd unit).
- **Config is preserved.** `/etc/unitylan/engine.toml` is a `noreplace` conffile, so dpkg/rpm never
  overwrite your edits (a changed default arrives as `engine.toml.dpkg-dist` / `.rpmnew` to merge by
  hand). This is the package manager's native equivalent of Windows' ProgramData ownership below.
- **State is preserved.** Keys, token, and pinned anchors under `/var/lib/unitylan` survive.
- **The engine restarts** onto the new binary if it was running — `postinstall` runs `systemctl
  try-restart`, which no-ops on a stopped or never-enabled node (so a first install is never started
  unconfigured). A running node blips: the tunnel, firewall, and resolver tear down and rebuild in a
  second or two, then re-establish.

### Windows (`.msi`)

```powershell
msiexec /i unitylan-<newver>-x64.msi          # a MajorUpgrade over the installed version
```

- **The service is adopted in place.** The upgrade *stops* the running service (freeing its exe to be
  replaced), lays the new files, then reconfigures and restarts the **same** registration — it is not
  deleted and recreated, so an open `services.msc` or a mid-upgrade failure can't wedge it.
- **Config is preserved.** `engine.toml` lives at `%ProgramData%\UnityLAN\engine.toml`, owned by the
  engine and kept out of the installer's file list, so an upgrade (or uninstall) never touches it.
- **State is preserved** under `%ProgramData%\UnityLAN`.
- Engine, GUI, and the wireguard-nt DLL are replaced and the daemon restarts — no reboot. The
  primary in-app auto-update no longer uses this MSI path — it file-swaps the engine and restarts via
  the SCM (see [Signed auto-update](#signed-auto-update)) — but a legacy `.msi` auto-update artifact
  still runs this same `MajorUpgrade` silently (`/quiet`, no wizard UI).

**Version skew.** Both paths update the engine *and* GUI together: the GUI↔engine control protocol
carries no version of its own, so a newer daemon must never be left talking to an older GUI.

**Upgrading off a pre-0.3.2 Windows build** is the one rough edge. 0.3.1 and earlier deleted their own
`engine.toml` during the upgrade before the new engine could rescue it, so that single transition
resets the config to the shipped default — re-enter coordinator/enrollment once via the GUI (device
identity in `%ProgramData%` survives). Every upgrade from 0.3.2 onward keeps your config untouched.

## Uninstall & cleanup

Host mutations are made at **runtime** by the daemon, not at install, so uninstall cleanup hinges on
stopping the daemon cleanly: on shutdown it **destroys the WireGuard interface, tears down the
nftables firewall, reverts the resolver, and removes any UPnP port mapping** — the host is left as it
was before the engine ran. A crash skips this, but the interface (userspace TUN) dies with the
process, the firewall/NRPT are replaced idempotently on next start, and the UPnP lease is finite.

**Linux.** `remove` keeps local state so a reinstall keeps the device's identity/IP; `purge` wipes it:

```sh
sudo systemctl disable --now unitylan-engine   # (the preremove script also does this)
sudo apt remove unitylan                        # host reverted on stop; keeps /var/lib/unitylan
sudo apt purge unitylan                         # also deletes /var/lib/unitylan (keys, token, anchors)
```

The package's device row at the coordinator is left to expire on presence-timeout. To un-enroll it
**actively** (and optionally wipe state) — the "forget me" path — run before removing:

```sh
sudo unitylan uninstall /etc/unitylan/engine.toml            # un-enroll at the coordinator, keep state
sudo unitylan uninstall /etc/unitylan/engine.toml --purge    # un-enroll and wipe local state
```

**Windows.** Uninstalling via Add/Remove Programs stops the service — which runs the same host
teardown — then removes it. Local state under `%ProgramData%\UnityLAN` is kept for reinstall; to
un-enroll and wipe it, run `unitylan-engine uninstall --purge` from an elevated shell first.
