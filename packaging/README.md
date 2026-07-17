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
packaging\windows\build.ps1            # needs Rust + WiX (dotnet tool install --global wix)
```

The script builds the release exes, fetches the pinned wireguard-nt DLL (not committed), stages it
under `resources-windows\binaries\`, and runs `wix build` → `packaging\dist\unitylan-<ver>-x64.msi`.

The MSI installs the engine + GUI under `Program Files\UnityLAN`, drops a Start-menu shortcut, and
registers the `UnityLANEngine` LocalSystem service by calling the engine's own `service install`
(which also relaxes the service DACL so the unprivileged GUI can start it). See
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
  -v $PWD/coordinator.toml:/etc/unitylan/coordinator.toml:ro \
  -v unitylan-data:/data \
  ghcr.io/<owner>/unitylan-coordinator:v0.1.0
```

The container runs unprivileged and carries no traffic (control plane only). The `unitylan-data`
named volume persists `/data/coordinator.db` — **this holds the deployment's Ed25519 trust anchor
(signing key); back it up and never rebuild it**, or every enrolled peer's pinned anchor breaks.

**4. TLS / reverse proxy.** The coordinator speaks plain HTTP; front it with a reverse proxy
(Caddy / nginx / Traefik) terminating TLS on 443 and proxying to `:8080`. Engines pin the anchor,
but clients still reach the control API over the network — run it behind HTTPS in production.

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

Alongside the packages, the Linux job attaches the raw `unitylan-engine-linux-amd64` binary and a
`SHA256SUMS`; the Windows job attaches `SHA256SUMS-windows.txt`. These feed the auto-update below.

## Signed auto-update

All crates share one version (`[workspace.package] version` in the root `Cargo.toml`), and the wire
protocol has a `PROTOCOL_VERSION` (`common`) advertised on every register/refresh so a mixed-version
mesh degrades to a warning, never a crash.

Updates are **opt-in per deployment** and reuse the coordinator's existing Ed25519 trust anchor — no
new signing key. Add a `[release]` block to the coordinator config (see `coordinator.example.toml`)
naming the version and, per platform, the artifact URL + its SHA-256 (from the `SHA256SUMS` files
above) + size. The coordinator signs this manifest with its anchor at startup and serves it on the
long-poll. Each engine verifies it against its **pinned** anchor and, if the version is newer and an
artifact matches its platform, the GUI shows an **Update** button. Applying it downloads the
artifact, re-checks the SHA-256 against the signed manifest, then:

- **Linux** — self-replaces `/usr/bin/unitylan-engine` in place and exits; systemd (`Restart=always`,
  with `ReadWritePaths=/usr/bin`) relaunches onto the new binary. The GUI is updated via the package
  manager as usual (the engine self-update keeps the resident daemon current).
- **Windows** — runs the signed `.msi`; its `MajorUpgrade` stops the service, replaces engine + GUI +
  DLL, and restarts.

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
scripts/engine-*.sh                    maintainer scripts (daemon-reload, stop/disable on remove, wipe state on purge)
gui/unitylan-gui.desktop               desktop launcher (points at /run/unitylan/control.sock)
nfpm/engine.yaml, nfpm/desktop.yaml    package specs → deb + rpm
docker/coordinator.Dockerfile          coordinator image
build.sh                               binaries + all four packages
```

## Install & run (engine node)

```sh
sudo apt install ./dist/unitylan_<ver>_amd64.deb      # or: rpm -i dist/unitylan-<ver>.x86_64.rpm
sudoedit /etc/unitylan/engine.toml                    # set coordinator + enrollment_key
sudo systemctl enable --now unitylan-engine
```

Runtime deps (`iproute2`, `nftables`) install automatically. The daemon runs as root with
`CAP_NET_ADMIN` for the userspace WireGuard interface, the nftables firewall, and `resolvectl`.

> **Note — GUI ↔ daemon socket.** The daemon runs as root and owns `/run/unitylan/control.sock`;
> the GUI runs as your desktop user. Group-readable socket access is not yet wired up, so the
> launcher currently assumes you can reach that socket. Tracked separately from packaging.

## Install & run (Windows)

```powershell
msiexec /i unitylan-<ver>-x64.msi          # installs to Program Files\UnityLAN, registers the service
notepad "$env:ProgramFiles\UnityLAN\engine.toml"   # set coordinator + enrollment_key (as admin)
sc.exe start UnityLANEngine                 # or reboot; the service is auto-start
```

The MSI registers `UnityLANEngine` as a **LocalSystem auto-start service** by invoking the engine's
own `service install`, which relaxes the service DACL so the desktop user can start it without a UAC
prompt. Launch the GUI from the **UnityLAN** Start-menu shortcut; it connects to the engine over the
`\\.\pipe\unitylan-control` named pipe.

The wireguard-nt DLL ships inside the MSI at
`Program Files\UnityLAN\resources-windows\binaries\wireguard-amd64.dll` — defguard loads it by that
path relative to the engine exe, and the service pins its working directory to the install folder so
it resolves. Uninstalling (Add/Remove Programs) stops and removes the service.

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
