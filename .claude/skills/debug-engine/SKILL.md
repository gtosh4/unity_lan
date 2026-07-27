---
name: debug-engine
description: Inspect a running UnityLAN engine over its control socket with socat + jq — one-shot Status or a live Watch subscription of peer state (endpoint, handshake, latency, bytes). Use when diagnosing a live mesh, a peer that won't connect, or tunnel flap.
---

# Debugging a live engine (subscribe, don't poll)

The engine's control socket (`<state_dir>/control.sock`, e.g. `engine-state-prod/control.sock`) speaks
**newline-delimited JSON** — a `ControlRequest` line in, `ControlResponse` line(s) out
(`crates/common/src/control.rs`). A unit-variant request serializes to a bare string, so `socat` + `jq`
reach it with no client build:

```sh
sock=engine-state-prod/control.sock
# One-shot snapshot, one peer's row:
printf '"Status"\n' | socat -t2 UNIX-CONNECT:$sock - \
  | jq -c '.Status.peers[]? | select(.wg_ip=="100.73.61.1")'
# Live subscription — the daemon holds the conn open and pushes a fresh StatusReport on EVERY change
# (the same push channel the GUI's `ctl::watch_status` uses). Prefer this over polling `Status`:
printf '"Watch"\n' | socat -t 86400 UNIX-CONNECT:$sock - \
  | jq --unbuffered -c '.Status.peers[]? | select(.wg_ip=="100.73.61.1")
        | {up, reach, ep:.endpoint, hs:.last_handshake_secs, lat:.latency_ms, rx:.rx_bytes, tx:.tx_bytes}'
```

Pair `Watch` with a `Monitor` over dedup'd output to wake on a specific edge (a down, an endpoint
landing) instead of re-polling.

**Flap diagnostic.** An all-null peer row at an `apply_state` timestamp with no matching log line is a
snapshot rebuild, not a real tunnel drop. Detail in `docs/technical.md` §5.7.

The full request/response surface is `ControlRequest` / `ControlResponse` in
`crates/common/src/control.rs` — read it before assuming a request doesn't exist.
