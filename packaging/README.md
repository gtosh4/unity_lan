# Packaging

Linux distribution artifacts for UnityLAN.

| Target        | Package                         | Contents                          | Built by                        |
| ------------- | ------------------------------- | --------------------------------- | ------------------------------- |
| server        | `unitylan` .deb / .rpm          | engine daemon + CLI + systemd unit| `./build.sh`                    |
| desktop       | `unitylan-desktop` .deb / .rpm  | GUI; **depends on** `unitylan`    | `./build.sh`                    |
| coordinator   | Docker image                    | coordinator server                | `docker/coordinator.Dockerfile` |

Installing `unitylan-desktop` pulls in `unitylan` automatically, so a desktop user gets the
engine, CLI, and GUI from one package. Servers install `unitylan` alone (no graphics libs).

## Build the packages

```sh
./build.sh          # needs cargo + nfpm; writes packaging/dist/*.{deb,rpm}
```

[nfpm](https://nfpm.goreleaser.com/install/) turns one spec into both `.deb` and `.rpm`,
so there is no per-distro build environment.

## Build the coordinator image

```sh
docker build -f packaging/docker/coordinator.Dockerfile -t unitylan-coordinator .
```

## Automated releases

`.github/workflows/release.yml` runs on a `v*` tag: it builds the `.deb`/`.rpm` (amd64) and
attaches them to the GitHub Release, and pushes `ghcr.io/<owner>/unitylan-coordinator:<tag>` +
`:latest`. Cut a release with:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The package version comes from the tag (`VERSION=<tag without v> build.sh`). For arm64, add a
matrix leg that builds via [`cross`](https://github.com/cross-rs/cross).

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
scripts/engine-*.sh                    maintainer scripts (daemon-reload, stop/disable on remove)
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
