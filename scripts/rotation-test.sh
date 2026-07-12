#!/usr/bin/env bash
# Coordinator trust-anchor rotation test (design.md §9).
#
# Drives the real `register` client path (pins the anchor) and the `rotate-key` admin subcommand.
# No netns / no WG — `register` only pins + prints, so it runs unprivileged on localhost.
#
# Proves:
#   1. A client TOFU-pins the coordinator anchor (A).
#   2. After `rotate-key` (A→B) + restart, the same client re-pins to B by following the served
#      rotation chain — no manual intervention.
#   3. Pointed at an UNRELATED coordinator (fresh key C, empty chain), the B-pinned client REFUSES
#      (MITM protection intact — a bare anchor change with no valid chain is rejected).
#
# Usage:  cargo build && scripts/rotation-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="${ENG:-$ROOT/target/debug/unitylan-engine}"
COORD="${COORD:-$ROOT/target/debug/unitylan-coordinator}"
[ -x "$ENG" ] && [ -x "$COORD" ] || { echo "build first: cargo build"; exit 1; }

TMP="$(mktemp -d)"
COORD_PID=""
trap 'kill "$COORD_PID" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*"; exit 1; }

# fake-source coordinator config: one guild, one member (user 1), one network, one enrollment key.
mk_coord_toml() { # $1 = bind, $2 = db path
  cat >"$TMP/$3.toml" <<EOF
bind = "$1"
database = "$2"
[[fake.guild]]
id = 1
name = "Test"
[[fake.guild.member]]
user_id = 1
nick = "nodea"
role_ids = [10]
[[network]]
guild_id = 1
role_id = 10
name = "mesh"
[[enroll]]
key = "key-a"
user_id = 1
[[community]]
guild_id = 1
slug = "test"
EOF
}

wait_port() { # $1 = host, $2 = port
  for _ in $(seq 1 50); do
    (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
    sleep 0.1
  done
  return 1
}

start_coord() { # $1 = cfg name, $2 = host, $3 = port
  "$COORD" "$TMP/$1.toml" >"$TMP/$1.log" 2>&1 &
  COORD_PID=$!
  wait_port "$2" "$3" || fail "coordinator $1 did not start (see $TMP/$1.log)"
}

stop_coord() { kill "$COORD_PID" 2>/dev/null; wait "$COORD_PID" 2>/dev/null; COORD_PID=""; }

# engine config: shares one state_dir across the run so the pin persists between registrations.
mk_eng_toml() { # $1 = name, $2 = coordinator url
  cat >"$TMP/$1.toml" <<EOF
coordinator = "$2"
state_dir = "$TMP/client"
enrollment_key = "key-a"
device_name = "host-a"
EOF
}

anchor_hex() { xxd -p -c 64 "$TMP/client/anchor.pub" 2>/dev/null | tr -d '\n'; }

# ---------------- Phase 1: initial TOFU pin (anchor A) ----------------
mk_coord_toml "127.0.0.1:18080" "$TMP/coord.db" coord
mk_eng_toml eng "http://127.0.0.1:18080"
start_coord coord 127.0.0.1 18080
"$ENG" "$TMP/eng.toml" >"$TMP/reg1.log" 2>&1 || fail "initial register failed (see $TMP/reg1.log)"
A="$(anchor_hex)"
[ -n "$A" ] || fail "no anchor pinned after initial register"
echo "phase 1: TOFU-pinned anchor A=${A:0:16}… ✓"

# ---------------- Phase 2: rotate TWICE (A→B→C) while offline, client walks the full chain ----------------
rotate() { # echoes the new anchor hex
  local out
  out="$("$COORD" rotate-key "$TMP/coord.toml" 2>&1)" || { echo "rotate-key failed: $out" >&2; return 1; }
  printf '%s\n' "$out" | sed -n 's/.*new anchor: \([0-9a-f]*\).*/\1/p'
}
stop_coord
B="$(rotate)" || exit 1
C="$(rotate)" || exit 1
[ -n "$C" ] && [ "$C" != "$B" ] && [ "$C" != "$A" ] || fail "second rotation produced no distinct anchor"
start_coord coord 127.0.0.1 18080
# The client is still pinned at A (offline across both rotations) → must walk A→B→C.
"$ENG" "$TMP/eng.toml" >"$TMP/reg2.log" 2>&1 || fail "re-register after 2 rotations failed (multi-hop chain not followed) — see $TMP/reg2.log"
NOW="$(anchor_hex)"
[ "$NOW" = "$C" ] || fail "client did not re-pin to C (pinned=${NOW:0:16}…, want=${C:0:16}…)"
echo "phase 2: rotated A→B→C (client offline), client walked the multi-hop chain to C ✓"

# ---------------- Phase 3: unrelated coordinator (key C, empty chain) is refused ----------------
stop_coord
mk_coord_toml "127.0.0.1:18081" "$TMP/coord2.db" coord2   # fresh DB → brand-new key, no rotation chain
mk_eng_toml eng2 "http://127.0.0.1:18081"                 # same state_dir=client (pinned to B)
start_coord coord2 127.0.0.1 18081
if "$ENG" "$TMP/eng2.toml" >"$TMP/reg3.log" 2>&1; then
  fail "client accepted an unrelated anchor with no rotation chain (MITM not refused!)"
fi
grep -q "no valid rotation path" "$TMP/reg3.log" || fail "refused, but not for the expected reason (see $TMP/reg3.log)"
[ "$(anchor_hex)" = "$C" ] || fail "pin changed despite refusal"
echo "phase 3: unrelated anchor (no chain) refused, pin unchanged ✓"

echo "RESULT: PASS ✓  TOFU pin → rotation re-pin via chain → MITM without chain refused"
