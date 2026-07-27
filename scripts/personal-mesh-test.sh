#!/usr/bin/env bash
# Personal mesh test (unprivileged).
#
# Proves the no-network path: a user who holds NO role in any registered network — nothing but a
# Discord account — still gets an identity and meshes their own devices. This is the difference from
# `own-device-test.sh`, where the users hold the role and merely opt out of the network: here there
# is no role to opt out of, so the whole identity comes from the personal scope (guild_id 0).
#
# Also checks the two things that scope must not do: pull in a *different* roleless user's device,
# and hand out an identity to a device that didn't ask for own-device peering.
#
# All engines run in one user+net namespace on loopback endpoints (distinct ifaces/ports); no host
# root — re-execs under `unshare -Urn --map-root-user`.
#
# Usage:  cargo build && scripts/personal-mesh-test.sh
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

# A guild with a registered network exists — users 1 and 2 are simply not in it (no role_ids naming
# role 10). That is the shape a canonical deployment has for someone who just installed the app.
cat >"$TMP/coord.toml" <<EOF
bind = "127.0.0.1:8080"
database = "$TMP/coord.db"
[[fake.guild]]
id = 1
name = "Test"
[[fake.guild.member]]
user_id = 1
nick = "alice"
role_ids = []
[[fake.guild.member]]
user_id = 2
nick = "bob"
role_ids = []
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
[[enroll]]
key = "key-a3"
user_id = 1
[[community]]
guild_id = 1
slug = "lan"
EOF

mkcfg() { # name user-key iface port [extra]
  cat >"$TMP/$1.toml" <<EOF
coordinator = "http://127.0.0.1:8080"
allow_insecure_http = true
state_dir = "$TMP/$1"
enrollment_key = "$2"
device_name = "$1"
iface = "$3"
listen_port = $4
endpoint = "127.0.0.1:$4"
refresh_secs = 2
EOF
}
mkcfg a1 key-a1 unla1 51820   # user 1, device 1
mkcfg a2 key-a2 unla2 51821   # user 1, device 2
mkcfg b1 key-b1 unlb1 51822   # user 2, device 1
mkcfg a3 key-a3 unla3 51823   # user 1, device 3 — opts out of own-device peering below

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done

"$ENG" -c "$TMP/a1.toml" run >"$TMP/a1.log" 2>&1 &
"$ENG" -c "$TMP/a2.toml" run >"$TMP/a2.log" 2>&1 &
"$ENG" -c "$TMP/b1.toml" run >"$TMP/b1.log" 2>&1 &

for _ in $(seq 1 40); do
  grep -q "peer set" "$TMP/a1.log" 2>/dev/null && grep -q "peer set" "$TMP/a2.log" 2>/dev/null && break
  sleep 0.5
done

A1_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/a1.log" | head -1 | awk '{print $1}')
A2_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/a2.log" | head -1 | awk '{print $1}')
[ -n "$A1_IP" ] && [ -n "$A2_IP" ] || {
  echo "FAIL: a roleless user's devices got no identity (personal scope should carry them)"
  tail -20 "$TMP/a1.log" "$TMP/a2.log"; exit 1
}
echo "A1=$A1_IP  A2=$A2_IP  (no role anywhere, meshed → personal scope ✓)"

echo "=== ping across the personal mesh ($A1_IP -> $A2_IP) ==="
if ping -c3 -W2 -I "$A1_IP" "$A2_IP"; then
  echo "personal ping ✓  a user with no role at all meshes their own devices"
else
  echo "RESULT: FAIL ✗"; tail -20 "$TMP/a1.log" "$TMP/a2.log"; exit 1
fi

# The personal scope is per owner. User 2 is equally roleless — that must not make them peers.
echo "=== per-user scoping: another roleless user must stay out ==="
B1_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/b1.log" | head -1 | awk '{print $1}')
echo "b1 (user 2) self IP = ${B1_IP:-<none>}"
[ -n "$B1_IP" ] || { echo "FAIL: user 2 got no personal identity either"; tail -20 "$TMP/b1.log"; exit 1; }
# Poll rather than sample once: a status snapshot caught mid-rebuild can report an empty peer list
# for an instant, which is a display artifact and not a dropped tunnel (docs/technical.md §5.7).
for _ in $(seq 1 20); do
  CTL=$("$ENG" -c "$TMP/a1.toml" ctl status 2>&1)
  echo "$CTL" | grep -q "$A2_IP" && break
  sleep 0.5
done
echo "$CTL" | grep -q "$A2_IP" || { echo "FAIL: a1 does not list its own sibling a2"; echo "$CTL"; exit 1; }
if echo "$CTL" | grep -q "$B1_IP"; then
  echo "FAIL: another roleless user's device leaked into user 1's personal mesh"; echo "$CTL"; exit 1
fi
echo "scoping: a1 sees sibling a2, never user 2's b1 ✓"

# Opting out is opting out of everything: with no role to fall back on, a device that declines
# own-device peering has nothing to be attested under and must get no address at all (TM-2 — an
# account with nothing to mesh must not consume one).
echo "=== a roleless device that declines own-device peering gets no address ==="
mkdir -p "$TMP/a3" && echo false >"$TMP/a3/peer_own_devices.json"
"$ENG" -c "$TMP/a3.toml" run >"$TMP/a3.log" 2>&1 &
sleep 6
A3_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/a3.log" | head -1 | awk '{print $1}')
[ -z "$A3_IP" ] || {
  echo "FAIL: a3 was allocated $A3_IP despite holding no role and wanting no own-device peering"
  tail -20 "$TMP/a3.log"; exit 1
}
echo "declined: a3 holds no identity ✓"

echo "RESULT: PASS ✓  personal scope meshes one owner's devices; other users out; opt-out allocates nothing"
