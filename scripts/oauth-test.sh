#!/usr/bin/env bash
# Interactive login (OAuth) end to end, offline via the fake OAuth provider.
#
# A client with NO enrollment key runs `engine login`, which asks the coordinator for an authorize
# URL and polls register. We simulate the browser by curling the coordinator's /oauth/callback with
# a fake code (`user:1`); the coordinator binds the device pubkey to that user, and the client's
# register then succeeds — proving login binds a device without an enrollment key.
#
# No WireGuard, no namespaces — `login` only does HTTP + key files.
#
# Usage:  cargo build && scripts/oauth-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="${ENG:-$ROOT/target/debug/unitylan-engine}"
COORD="${COORD:-$ROOT/target/debug/unitylan-coordinator}"
[ -x "$ENG" ] && [ -x "$COORD" ] || { echo "build first: cargo build"; exit 1; }

TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT

cat >"$TMP/coord.toml" <<EOF
bind = "127.0.0.1:8087"
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

# Client config: note there is NO enrollment_key — login must bind the device instead.
cat >"$TMP/a.toml" <<EOF
coordinator = "http://127.0.0.1:8087"
state_dir = "$TMP/a"
device_name = "host-a"
EOF

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf http://127.0.0.1:8087/healthz >/dev/null 2>&1 && break; sleep 0.25; done

# Sanity: without login, register is refused (no key, not bound).
if "$ENG" run "$TMP/a.toml" >"$TMP/pre.log" 2>&1; then :; fi
grep -qiE "not enrolled|log in" "$TMP/pre.log" \
  && echo "pre-login: register refused without a key ✓" \
  || { echo "FAIL: register was not refused pre-login"; cat "$TMP/pre.log"; exit 1; }

# Start interactive login; it prints the authorize URL (with state) and polls register.
"$ENG" login "$TMP/a.toml" >"$TMP/login.out" 2>&1 &
for _ in $(seq 1 40); do grep -q 'oauth/callback' "$TMP/login.out" 2>/dev/null && break; sleep 0.25; done
STATE=$(grep -oE 'state=[A-Za-z0-9_]+' "$TMP/login.out" | head -1 | cut -d= -f2)
[ -n "$STATE" ] || { echo "FAIL: no authorize URL / state from login"; cat "$TMP/login.out"; exit 1; }
echo "login: got authorize URL with state ✓"

# Simulate the browser redirect: the callback exchanges the fake code and binds pubkey -> user 1.
curl -sf "http://127.0.0.1:8087/oauth/callback?state=$STATE&code=user:1" >/dev/null \
  || { echo "FAIL: callback rejected"; exit 1; }
echo "callback: fake code exchanged + device bound ✓"

# The login poll must now see a successful register.
for _ in $(seq 1 20); do grep -q 'Logged in' "$TMP/login.out" 2>/dev/null && break; sleep 0.5; done
if grep -q 'Logged in' "$TMP/login.out"; then
  echo "  $(grep 'Logged in' "$TMP/login.out")"
  echo "RESULT: PASS ✓  interactive login bound the device with no enrollment key"
  exit 0
fi
echo "RESULT: FAIL ✗  login did not complete"; cat "$TMP/login.out"; exit 1
