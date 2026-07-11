#!/usr/bin/env bash
# Unprivileged multi-node mesh test.
#
# A coordinator (fake Discord source) plus two engine daemons in separate network namespaces
# register, receive each other as seeds, form a WireGuard mesh, and ping across it. Proves the
# whole path: membership -> coordinator seeds -> WG mesh -> traffic. No host root — re-execs
# under `unshare -Urnm --map-root-user`.
#
# Usage:  cargo build && scripts/mesh-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="${ENG:-$ROOT/target/debug/unitylan-engine}"
COORD="${COORD:-$ROOT/target/debug/unitylan-coordinator}"

if [ "${UNL_INNS:-}" != "1" ]; then
  [ -x "$ENG" ] && [ -x "$COORD" ] || { echo "build first: cargo build"; exit 1; }
  exec unshare -Urnm --map-root-user env UNL_INNS=1 ENG="$ENG" COORD="$COORD" bash "${BASH_SOURCE[0]}"
fi

# ---------------- inside the user+net+mount namespace ----------------
TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT
mount -t tmpfs none /run 2>/dev/null || { echo "FAIL: mount /run"; exit 1; }
mkdir -p /run/wireguard
ip link set lo up

unshare --net -- sleep 300 & CHILD=$!
sleep 0.3
NS1="nsenter -t $CHILD -n"
ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$CHILD"
ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
$NS1 ip addr add 10.0.0.2/24 dev veth1; $NS1 ip link set veth1 up; $NS1 ip link set lo up

cat >"$TMP/coord.toml" <<EOF
bind = "10.0.0.1:8080"
database = "$TMP/coord.db"
[[fake.guild]]
id = 1
name = "Test"
[[fake.guild.member]]
user_id = 1
nick = "nodea"
role_ids = [10]
[[fake.guild.member]]
user_id = 2
nick = "nodeb"
role_ids = [10]
[[network]]
guild_id = 1
role_id = 10
name = "mesh"
[[enroll]]
key = "key-a"
user_id = 1
[[enroll]]
key = "key-b"
user_id = 2
[[community]]
guild_id = 1
slug = "lan"
EOF
# NOTE distinct iface names only because this test shares one /run across the namespaces
# (boringtun's control socket is /run/wireguard/<iface>.sock). Real hosts each have their own.
cat >"$TMP/a.toml" <<EOF
coordinator = "http://10.0.0.1:8080"
state_dir = "$TMP/a"
enrollment_key = "key-a"
iface = "unla"
listen_port = 51820
endpoint = "10.0.0.1:51820"
refresh_secs = 2
EOF
cat >"$TMP/b.toml" <<EOF
coordinator = "http://10.0.0.1:8080"
state_dir = "$TMP/b"
enrollment_key = "key-b"
iface = "unlb"
listen_port = 51821
endpoint = "10.0.0.2:51821"
refresh_secs = 2
EOF

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf http://10.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done

"$ENG" run "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
$NS1 "$ENG" run "$TMP/b.toml" >"$TMP/b.log" 2>&1 &

for _ in $(seq 1 40); do
  grep -q "peer set" "$TMP/a.log" 2>/dev/null && grep -q "peer set" "$TMP/b.log" 2>/dev/null && break
  sleep 0.5
done

A_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/a.log" | head -1 | awk '{print $1}')
B_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/b.log" | head -1 | awk '{print $1}')
[ -n "$A_IP" ] && [ -n "$B_IP" ] || { echo "FAIL: nodes did not mesh"; cat "$TMP/a.log" "$TMP/b.log"; exit 1; }
echo "A=$A_IP  B=$B_IP  (meshed via coordinator seeds)"

# Naming: the community slug must appear in the device hostname (<device>.<user>.lan.internal).
if grep -q '\.lan\.internal' "$TMP/a.log"; then
  echo "hostname: $(grep -oE '[a-z0-9-]+\.[a-z0-9-]+\.lan\.internal' "$TMP/a.log" | head -1) (community slug applied)"
else
  echo "FAIL: community slug not in hostname"; grep -E '100\.[0-9]' "$TMP/a.log"; exit 1
fi

# No manual plumbing: the daemon brings its own link up and installs routes.
echo "=== ping across mesh ($A_IP -> $B_IP) ==="
if ping -c3 -W2 -I "$A_IP" "$B_IP"; then
  echo "RESULT: PASS ✓  membership -> coordinator seeds -> WG mesh -> traffic"
  exit 0
else
  echo "RESULT: FAIL ✗"; tail -15 "$TMP/a.log" "$TMP/b.log"; exit 1
fi
