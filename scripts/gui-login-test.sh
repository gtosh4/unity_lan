#!/usr/bin/env bash
# Daemon-mediated interactive login (the GUI path), offline via fake OAuth.
#
# A daemon starts with NO enrollment key: it serves the control socket and reports `needs_login`
# instead of bailing. We ask it to start login (`ctl login` == the GUI button), get the authorize
# URL, simulate the browser by curling the callback, and the daemon's register loop then binds the
# device and brings up the mesh. Single node, so no peers — we just prove the login → mesh path.
# No host root — re-execs under `unshare -Urnm --map-root-user`.
#
# Usage:  cargo build && scripts/gui-login-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="${ENG:-$ROOT/target/debug/unitylan-engine}"
COORD="${COORD:-$ROOT/target/debug/unitylan-coordinator}"

if [ "${UNL_INNS:-}" != "1" ]; then
  [ -x "$ENG" ] && [ -x "$COORD" ] || { echo "build first: cargo build"; exit 1; }
  exec unshare -Urnm --map-root-user env UNL_INNS=1 ENG="$ENG" COORD="$COORD" bash "${BASH_SOURCE[0]}"
fi

TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT
mount -t tmpfs none /run 2>/dev/null || { echo "FAIL: mount /run"; exit 1; }
mkdir -p /run/wireguard
ip link set lo up

cat >"$TMP/coord.toml" <<EOF
bind = "127.0.0.1:8088"
database = "$TMP/coord.db"
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
[[community]]
guild_id = 1
slug = "lan"
EOF

# No enrollment_key — the daemon must wait for interactive login.
cat >"$TMP/a.toml" <<EOF
coordinator = "http://127.0.0.1:8088"
state_dir = "$TMP/a"
device_name = "host-a"
iface = "unla"
listen_port = 51820
endpoint = "127.0.0.1:51820"
refresh_secs = 2
EOF

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf http://127.0.0.1:8088/healthz >/dev/null 2>&1 && break; sleep 0.25; done

"$ENG" run "$TMP/a.toml" >"$TMP/a.log" 2>&1 &

# The daemon should come up (control socket) and report needs_login, without meshing.
for _ in $(seq 1 40); do "$ENG" ctl status "$TMP/a.toml" 2>/dev/null | grep -q 'not logged in' && break; sleep 0.5; done
"$ENG" ctl status "$TMP/a.toml" 2>&1 | grep -q 'not logged in' \
  || { echo "FAIL: daemon did not report needs_login"; "$ENG" ctl status "$TMP/a.toml"; tail -10 "$TMP/a.log"; exit 1; }
echo "daemon up, not enrolled: reports needs_login ✓"

# The GUI "Log in" button == this control op: ask the daemon for the authorize URL.
LOGIN=$("$ENG" ctl login "$TMP/a.toml" 2>&1)
echo "$LOGIN" | grep -q 'oauth/callback' || { echo "FAIL: ctl login returned no authorize URL"; echo "$LOGIN"; exit 1; }
STATE=$(echo "$LOGIN" | grep -oE 'state=[A-Za-z0-9_]+' | head -1 | cut -d= -f2)
[ -n "$STATE" ] || { echo "FAIL: no state in authorize URL"; echo "$LOGIN"; exit 1; }
echo "ctl login: got authorize URL with state ✓"

# Simulate the browser redirect → binds pubkey -> user 1.
curl -sf "http://127.0.0.1:8088/oauth/callback?state=$STATE&code=user:1" >/dev/null \
  || { echo "FAIL: callback rejected"; exit 1; }
echo "callback: device bound ✓"

# The daemon's register loop now succeeds → brings up the interface and clears needs_login.
for _ in $(seq 1 30); do "$ENG" ctl status "$TMP/a.toml" 2>/dev/null | grep -q 'lan.internal' && break; sleep 0.5; done
ST=$("$ENG" ctl status "$TMP/a.toml" 2>&1)
if echo "$ST" | grep -q 'lan.internal' && ! echo "$ST" | grep -q 'not logged in'; then
  echo "$ST" | grep -E 'device:'
  echo "RESULT: PASS ✓  daemon-mediated login bound the device and brought up the mesh"
  exit 0
fi
echo "RESULT: FAIL ✗  daemon did not mesh after login"; echo "$ST"; tail -15 "$TMP/a.log"; exit 1
