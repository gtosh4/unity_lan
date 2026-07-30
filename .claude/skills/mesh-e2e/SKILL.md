---
name: mesh-e2e
description: Run UnityLAN's end-to-end mesh test scripts (scripts/*-test.sh) — which script covers which behavior, what privilege each needs, and the timeout to wrap it in. Use when verifying a behavior change end-to-end or bringing up a local offline mesh.
---

# Running the e2e suite

`scripts/*-test.sh` = Linux-only end-to-end tests over network namespaces, against a fake
Discord/OAuth coordinator plus `nft`/`veth`. Most are run by `.github/workflows/e2e.yml`. Prefer
running the relevant one to verify a behavior change end-to-end.

**Privilege: almost none need `sudo`** — most re-exec under `unshare -Urnm --map-root-user`, so they
run fine unprivileged. Run them directly; `sudo` is unnecessary and, in a Claude session, impossible
(no password). Always wrap in `timeout` — a hung daemon otherwise blocks until the tool timeout.

| Script | How to run |
| --- | --- |
| `mesh-test.sh`, `nat-test.sh`, `gui-login-test.sh`, `gossip-test.sh`, `ice-test.sh`, `relay-test.sh`, `expose-net-test.sh`, `net-toggle-test.sh`, `own-device-test.sh`, `personal-mesh-test.sh`, `wg-tunnel-test.sh` | directly, self-unshares — `timeout 150 scripts/<name>.sh` |
| `cert-test.sh` | directly, self-unshares — `timeout 300 scripts/cert-test.sh`. Needs `dig`; the ACME leg needs `pebble` on PATH (release binary, no Go) and is **skipped with a loud notice** without it. Also runs the engine's `proxy-serve` subcommand against the issued certificate |
| `service-test.sh` | directly, self-unshares — `timeout 400 scripts/service-test.sh`. Named services end to end: peer-direct announcement, name resolution, scope enforcement, widening by name, withdrawal. Slower than the rest — it waits out three 30s announcement polls. Needs `dig` |
| `update-test.sh` | directly, self-unshares — `timeout 420 scripts/update-test.sh`. Covers the signed auto-update path (manifest → verify → download → swap → restart onto the new version); builds twice, temporarily patching the workspace version to make a fake-old client, then restoring it. Needs `openssl` + `python3` |
| `oauth-test.sh`, `rotation-test.sh` | directly, unprivileged (HTTP + key files only, no netns/WG) |
| `coordinator-scale-test.sh` | directly, unprivileged — a scaling probe (`[devices]` arg), no pass/fail assertion |
| `resolver-hook-test.sh` | **real host root** — needs live `systemd-resolved`, a userns won't do |
| `dev-run.sh` | **real host root** — engine builds a real `wg` interface on the host |
| `readme-demo.sh` | **interactive desktop** — needs a Wayland screencast portal, not headless-able |

The last three the user must run themselves via the `! <cmd>` prefix; ask rather than attempting.

## Local mesh by hand (offline, no real Discord)

```sh
cargo run -p unitylan-coordinator -- coordinator.test.toml   # fake-Discord mode on :8080
scripts/dev-run.sh                                           # engine (via sudo) + GUI, shared socket
```

Full local-mesh setup, Linux + Windows: `CONTRIBUTING.md`.
