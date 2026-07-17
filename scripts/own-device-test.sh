#!/usr/bin/env bash
# Own-device peering test (unprivileged).
#
# Proves the "always peer with my own devices" option: a user's two devices form a mesh even when
# they share NO enabled network (the only shared network is opted out on both), while a *different*
# user's device — same opted-out network — is NOT pulled in (own-device peering is scoped per user).
#
# All three engines run in one user+net namespace on loopback endpoints (distinct ifaces/ports); no
# host root — re-execs under `unshare -Urn --map-root-user`.
#
# Usage:  cargo build && scripts/own-device-test.sh
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

# Coordinator: one guild/role ("mesh"). Users 1 (two devices) and 2 (one device) all hold the role.
cat >"$TMP/coord.toml" <<EOF
bind = "127.0.0.1:8080"
database = "$TMP/coord.db"
[[fake.guild]]
id = 1
name = "Test"
[[fake.guild.member]]
user_id = 1
nick = "alice"
role_ids = [10]
[[fake.guild.member]]
user_id = 2
nick = "bob"
role_ids = [10]
[[network]]
guild_id = 1
role_id = 10
name = "mesh"
[[enroll]]
key = "key-a1"
user_id = 1
[[enroll]]
key = "key-a2"
user_id = 1
[[enroll]]
key = "key-b1"
user_id = 2
[[community]]
guild_id = 1
slug = "lan"
EOF

# Every engine sets disable_new_networks = true → the only network ("mesh") is auto-disabled on
# discovery, so NO device has an enabled network. peer_own_devices is omitted (defaults to true).
mkcfg() { # name user-key iface port
  cat >"$TMP/$1.toml" <<EOF
coordinator = "http://127.0.0.1:8080"
allow_insecure_http = true
state_dir = "$TMP/$1"
enrollment_key = "$2"
device_name = "$1"
disable_new_networks = true
iface = "$3"
listen_port = $4
endpoint = "127.0.0.1:$4"
refresh_secs = 2
EOF
}
mkcfg a1 key-a1 unla1 51820   # user 1, device 1
mkcfg a2 key-a2 unla2 51821   # user 1, device 2
mkcfg b1 key-b1 unlb1 51822   # user 2, device 1

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done

"$ENG" run "$TMP/a1.toml" >"$TMP/a1.log" 2>&1 &
"$ENG" run "$TMP/a2.toml" >"$TMP/a2.log" 2>&1 &
"$ENG" run "$TMP/b1.toml" >"$TMP/b1.log" 2>&1 &

# Wait for user 1's two devices to mesh (peer set on both). If own-device peering were off they'd
# never mesh — the shared network is disabled on both ends.
for _ in $(seq 1 40); do
  grep -q "peer set" "$TMP/a1.log" 2>/dev/null && grep -q "peer set" "$TMP/a2.log" 2>/dev/null && break
  sleep 0.5
done

A1_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/a1.log" | head -1 | awk '{print $1}')
A2_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/a2.log" | head -1 | awk '{print $1}')
[ -n "$A1_IP" ] && [ -n "$A2_IP" ] || {
  echo "FAIL: own devices did not mesh (no enabled network → own-device peering should carry them)"
  tail -20 "$TMP/a1.log" "$TMP/a2.log"; exit 1
}
echo "A1=$A1_IP  A2=$A2_IP  (same user, meshed with NO enabled network → own-device peering ✓)"

echo "=== ping across own-device mesh ($A1_IP -> $A2_IP) ==="
if ping -c3 -W2 -I "$A1_IP" "$A2_IP"; then
  echo "own-device ping ✓  same user peers despite the shared network being disabled"
else
  echo "RESULT: FAIL ✗"; tail -20 "$TMP/a1.log" "$TMP/a2.log"; exit 1
fi

# Per-user scoping: user 2's device (b1) shares only the SAME disabled network and is a different
# user, so own-device peering must NOT expose it to user 1. It must not appear in a1's status.
echo "=== per-user scoping: user 2's device must not appear on user 1's node ==="
B1_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/b1.log" | head -1 | awk '{print $1}')
echo "b1 (user 2) self IP = ${B1_IP:-<none>}"
CTL=$("$ENG" ctl status "$TMP/a1.toml" 2>&1)
echo "$CTL" | grep -q "$A2_IP" || { echo "FAIL: a1 status did not list its own sibling a2"; echo "$CTL"; exit 1; }
if [ -n "$B1_IP" ] && echo "$CTL" | grep -q "$B1_IP"; then
  echo "FAIL: user 2's device leaked into user 1's mesh via own-device peering"; echo "$CTL"; exit 1
fi
echo "scoping: a1 sees sibling a2 but never user 2's b1 ✓"

# CLI toggle: turn own-device peering off on a1. The coordinator evicts a1's per-user presence and
# stops seeding its siblings, so a1 and a2 drop each other on the next refresh.
echo "=== cli toggle: 'ctl own-devices off' drops the own-device mesh ==="
"$ENG" ctl own-devices "$TMP/a1.toml" off
for _ in $(seq 1 20); do
  "$ENG" ctl status "$TMP/a1.toml" 2>/dev/null | grep -q "$A2_IP" || break
  sleep 0.5
done
"$ENG" ctl status "$TMP/a1.toml" 2>&1 | grep -q "$A2_IP" && {
  echo "FAIL: a1 still lists a2 after own-device peering turned off"; exit 1
}
echo "toggle off: a1 no longer meshes its sibling a2 ✓"

# Turn it back on → they re-mesh.
echo "=== cli toggle: 'ctl own-devices on' restores it ==="
"$ENG" ctl own-devices "$TMP/a1.toml" on
for _ in $(seq 1 20); do
  "$ENG" ctl status "$TMP/a1.toml" 2>/dev/null | grep -q "$A2_IP" && break
  sleep 0.5
done
"$ENG" ctl status "$TMP/a1.toml" 2>&1 | grep -q "$A2_IP" || {
  echo "FAIL: a1 did not re-mesh a2 after own-device peering turned back on"; exit 1
}
echo "toggle on: a1 re-meshes sibling a2 ✓"

echo "RESULT: PASS ✓  own devices peer across a disabled network; other users stay out; toggle works"
