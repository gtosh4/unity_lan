# Contributing to UnityLAN

Thanks for hacking on UnityLAN. This guide covers building, running a full local mesh, and the
checks CI enforces — on both **Linux** and **Windows** (the two primary targets; macOS is
userspace-only and best-effort).

## Workspace layout

A Cargo workspace with four crates (`Cargo.toml`):

| Crate | Binary | What it is |
| --- | --- | --- |
| `crates/common` | — | shared types: control protocol, coordinator API, crypto |
| `crates/coordinator` | `unitylan-coordinator` | the server: Discord auth, network membership, signed attestations |
| `crates/engine` | `unitylan-engine` | the privileged node daemon: WireGuard, firewall, DNS, control socket |
| `crates/gui` | `unitylan-gui` | unprivileged iced desktop app driving the engine over its control socket |

Platform-specific engine code is split by module: `wg/{userspace,windows}.rs`,
`fw/{nftables,windows}.rs`, `resolver/{linux,windows}.rs`, selected at runtime.

## Prerequisites

- **Rust** ≥ 1.96 (edition 2021). Install via [rustup](https://rustup.rs).
  - Linux: the default `x86_64-unknown-linux-gnu` toolchain.
  - Windows: the **MSVC** toolchain (`x86_64-pc-windows-msvc`) — the default from rustup on Windows.
- **rustfmt** + **clippy** components: `rustup component add rustfmt clippy`.

## Build

```sh
cargo build              # whole workspace, debug
cargo build --release    # optimized
```

Build a single crate with `-p`, e.g. `cargo build -p unitylan-engine`.

## Checks CI enforces

`.github/workflows/ci.yml` runs three gates. Run them locally before pushing:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

A pre-commit hook runs exactly these. Enable it once per clone:

```sh
git config core.hooksPath .githooks
```

Bypass a single commit with `git commit --no-verify`. The hook is a bash script; on Windows run it
from Git Bash, or just run the three commands above manually.

`cargo test --workspace` is platform-aware: on Windows it exercises the `fw/windows.rs` and
`resolver/windows.rs` argument-construction tests; on Linux the nftables/resolved equivalents. None
of the unit tests need privilege or a network.

---

## Running a local mesh

A working mesh needs three things: a **coordinator**, and one or more **engine** daemons, each
optionally with a **GUI**. The engine needs elevation on every platform (it creates a WireGuard
interface, programs the host firewall, and points the OS resolver at its `.internal` server).

### 1. Coordinator

For offline development the coordinator runs in **fake-Discord mode**, seeded from a TOML file
(`coordinator.test.toml`) — no real Discord app or bot token required:

```sh
cargo run -p unitylan-coordinator -- coordinator.test.toml
```

It serves `http://127.0.0.1:8080` and seeds two guilds, a member (user id `333`), and a few
networks. A device enrolls against it in one of two ways:

- **Enrollment key** — add a seed to the coordinator config and reference it from the engine:

  ```toml
  # coordinator.test.toml
  [[enroll]]
  key = "dev-key-1"
  user_id = 333
  ```
  ```toml
  # engine.toml
  enrollment_key = "dev-key-1"
  ```
  The key binds to the first device that registers with it.

- **Interactive login** — `unitylan-engine login engine.toml`. In fake mode this uses an offline
  fake-OAuth provider (no Discord round-trip); the `oauth-test.sh` / `gui-login-test.sh` scripts
  exercise the same path.

To test against a **real** Discord network, run the coordinator with a real config
(`coordinator.example.toml` as a template, with `[discord]`/`[oauth]` blocks) and enroll via the
interactive login flow, which opens a real Discord authorize URL. The coordinator builds and runs
on Windows too (axum + SQLite), or run it on Linux / in Docker
(`packaging/docker/coordinator.Dockerfile`).

### 2. Engine + GUI — Linux

The engine needs root for the WireGuard interface. `scripts/dev-run.sh` starts the engine (via
`sudo`) and the GUI (unprivileged), sharing the control socket — the engine `chown`s the socket to
the invoking user so the GUI can connect:

```sh
cargo build
scripts/dev-run.sh              # bootstraps ./engine.toml on first run
scripts/dev-run.sh my.toml      # explicit config
```

If the device isn't enrolled yet, follow the printed login flow:

```sh
target/debug/unitylan-engine ctl login engine.toml   # open the printed Discord URL
```

### 2. Engine + GUI — Windows

Two one-time setup steps beyond `cargo build`:

**a. WireGuard driver.** The Windows WG backend drives the **wireguard-nt** kernel driver via
`wireguard.dll`, which the crate loads by name at startup. Drop the amd64 DLL next to the binary:

```powershell
# download + extract wireguard-nt, then:
Copy-Item .\wireguard-nt\bin\amd64\wireguard.dll .\target\debug\wireguard.dll
```

Get the runtime from <https://download.wireguard.com/wireguard-nt/> (verify it's signed by
"WireGuard LLC"). A `--release` build needs its own copy in `target\release\`. wireguard-nt is
self-contained — the DLL installs its kernel driver on first elevated use; nothing else to install.

**b. Config.** Copy `engine.example.toml` to `engine.toml` and set `coordinator` (and, for
fake-mode, `dev_user`). `engine.toml` and `engine-state/` are git-ignored.

Then start the engine + GUI with the PowerShell analogue of `dev-run.sh`:

```powershell
.\scripts\dev-run.ps1                 # engine.toml, target\debug
.\scripts\dev-run.ps1 -Release        # target\release
.\scripts\dev-run.ps1 -Config my.toml
```

It **self-elevates via UAC** (the engine needs Administrator for the interface, Defender Firewall,
and NRPT), waits for the control **named pipe** (`\\.\pipe\unitylan-control`), launches the GUI, and
stops the engine when the GUI closes. If the device isn't enrolled, use the GUI's
**"Log in with Discord"** button, or:

```powershell
.\target\debug\unitylan-engine.exe login engine.toml
```

> **Privilege split.** `dev-run.ps1` runs both processes elevated for a reliable one-command loop.
> To exercise the real *unprivileged* GUI → engine path (as it works against the installed
> service), leave the engine running and launch the GUI from a **separate, non-elevated** shell as
> the same user: `target\debug\unitylan-gui.exe control.sock`. It connects because the pipe's DACL
> grants the creating user and the pipe object defaults to medium integrity.

If PowerShell blocks the script (`running scripts is disabled`), invoke it as
`powershell -ExecutionPolicy Bypass -File .\scripts\dev-run.ps1`.

### 3. Talk to a running engine (any platform)

The `ctl` subcommand speaks the same control protocol as the GUI:

```sh
unitylan-engine ctl status  engine.toml     # device, networks, per-peer reachability
unitylan-engine ctl connect engine.toml     # connect / disconnect the mesh
unitylan-engine ctl devices engine.toml     # list / rename / set-primary / remove your devices
```

---

## Integration test scripts (Linux only)

`scripts/*.sh` are unprivileged end-to-end tests built on Linux **network namespaces** (plus
`nft`, `veth`, and a fake Discord/OAuth coordinator). They have no Windows equivalent — run them on
Linux (or WSL2):

| Script | Exercises |
| --- | --- |
| `mesh-test.sh` | two engine daemons meshing through a coordinator |
| `nat-test.sh` | NAT hole-punching between symmetric/cone NATs |
| `wg-tunnel-test.sh` | raw boringtun WireGuard connectivity over a veth |
| `oauth-test.sh` / `gui-login-test.sh` | interactive Discord login (offline fake OAuth) |
| `expose-net-test.sh` / `net-toggle-test.sh` | per-network expose scoping and peering toggles |
| `rotation-test.sh` | coordinator trust-anchor rotation |
| `resolver-hook-test.sh` | live systemd-resolved hookup (needs root + real resolved) |

For Windows-specific driver paths there are `unitylan-engine` dev subcommands that drive the real
backends on an elevated box: `wg-smoke` (bring a WG interface up/down) and
`resolver-install` / `resolver-revert` (drive the NRPT resolver hook).

---

## Packaging

Linux `.deb`/`.rpm` and the coordinator Docker image are built from `packaging/` — see
`packaging/README.md`. A Windows MSI/WiX installer (bundling engine + GUI + `wireguard.dll` and
registering the service) is still TODO.

## Submitting changes

1. Branch off `main`.
2. Make the change; keep it consistent with surrounding code.
3. Run the three CI gates (fmt, clippy, test) — the pre-commit hook does this for you.
4. Open a PR with a clear description of the behavior change and how you verified it.
