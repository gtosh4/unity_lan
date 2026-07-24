#!/usr/bin/env bash
# Local dev: start engine (root, builds wg iface) + GUI (unprivileged), sharing the control socket.
# Assumes the coordinator is already running. chmods the socket so the GUI can open it.
# With no config argument the engine writes a starter engine.toml in the repo root on first run.
#
# Usage:  scripts/dev-run.sh [engine.toml]
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="$ROOT/target/debug/unitylan-engine"
GUI="$ROOT/target/debug/unitylan-gui"
cd "$ROOT"

[ -x "$ENG" ] && [ -x "$GUI" ] || { echo "build first: cargo build"; exit 1; }

# Reap the engine by its own command line, not by PID. `$!` after the backgrounded `sudo` below is
# the *sudo wrapper's* PID (sudo forks a monitor → engine is its grandchild), and killing the wrapper
# doesn't reliably stop the root-owned engine — in a long session sudo's cached credentials have also
# expired, so a `sudo kill` in the trap silently fails for want of a password. A survivor keeps the WG
# interface, control socket, and beacon port, so the next run dies with "Address already in use".
# TERM first for a clean WireGuard teardown, then KILL any survivor: the engine can wedge in
# boringtun's uapi during teardown and ignore TERM (the packaged unit caps this with TimeoutStopSec),
# and a wedged survivor keeps the beacon port — so escalate rather than leave it holding :51821.
reap_engine() {
    local pat="$ENG( -c .*)? run"
    sudo pkill -TERM -f "$pat" 2>/dev/null || return 0
    for _ in $(seq 1 10); do sudo pgrep -f "$pat" >/dev/null || return 0; sleep 0.3; done
    sudo pkill -KILL -f "$pat" 2>/dev/null
}
reap_engine   # clear any survivor from a prior run before we bind (also caches sudo creds for below)

# Engine needs root for the WireGuard interface. No arg → engine bootstraps ./engine.toml.
# sudo scrubs the environment, so pass RUST_LOG through explicitly when it's set and non-empty.
sudo env ${RUST_LOG:+RUST_LOG="$RUST_LOG"} "$ENG" ${1:+-c "$1"} run &
trap 'reap_engine; kill $(jobs -p) 2>/dev/null' EXIT

# Resolve the config the engine used, then its control socket.
CFG="${1:-$ROOT/engine.toml}"
for _ in $(seq 1 40); do [ -f "$CFG" ] && break; sleep 0.25; done
STATE_DIR="$(grep -E '^\s*state_dir\s*=' "$CFG" | head -1 | sed -E 's/.*=\s*"?([^"]+)"?.*/\1/')"
SOCK="$(grep -E '^\s*control_socket\s*=' "$CFG" | head -1 | sed -E 's/.*=\s*"?([^"]+)"?.*/\1/')"
[ -n "$SOCK" ] || SOCK="$STATE_DIR/control.sock"

# Wait for the socket. The engine chowns it to $SUDO_UID (this user) with mode 660, so the
# unprivileged GUI below can connect without further chmod.
for _ in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.25; done
[ -S "$SOCK" ] || { echo "socket never appeared: $SOCK"; exit 1; }
echo "engine up, socket $SOCK ✓"

# If the coordinator is fake-mode and this device isn't bound yet, enroll:
#   $ENG -c "$CFG" ctl login   # follow the printed URL

"$GUI" "$SOCK"
