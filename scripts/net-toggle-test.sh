#!/usr/bin/env bash
# Per-network peering toggle (GUI/CLI: `ctl net enable|disable <network>`). Three nodes, two nets:
#   A ∈ {mesh, mesh2}   B ∈ {mesh}   C ∈ {mesh2}
# A peers with both B (shares mesh) and C (shares mesh2). Disabling mesh2 on A drops C (both ways)
# while B stays; re-enabling brings C back. Proves the coordinator-side, symmetric opt-out.
# No host root — re-execs under `unshare -Urnm --map-root-user`; nodes hang off a bridge.
#
# Usage:  cargo build && scripts/net-toggle-test.sh
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
ip link add br0 type bridge
ip addr add 10.0.0.1/24 dev br0
ip link set br0 up

make_node() {
  local name="$1" ip="$2" pid
  unshare --net -- sleep 600 >/dev/null 2>&1 & pid=$!
  sleep 0.2
  ip link add "$name" type veth peer name "${name}p"
  ip link set "$name" master br0
  ip link set "$name" up
  ip link set "${name}p" netns "$pid"
  nsenter -t "$pid" -n ip addr add "$ip/24" dev "${name}p"
  nsenter -t "$pid" -n ip link set "${name}p" up
  nsenter -t "$pid" -n ip link set lo up
  echo "$pid"
}

PIDB=$(make_node vethb 10.0.0.2)
PIDC=$(make_node vethc 10.0.0.3)
NSB="nsenter -t $PIDB -n"
NSC="nsenter -t $PIDC -n"

cat >"$TMP/coord.toml" <<EOF
bind = "0.0.0.0:8080"
database = "$TMP/coord.db"
[[fake.guild]]
id = 1
name = "Test"
[[fake.guild.member]]
user_id = 1
nick = "nodea"
role_ids = [10, 20]
[[fake.guild.member]]
user_id = 2
nick = "nodeb"
role_ids = [10]
[[fake.guild.member]]
user_id = 3
nick = "nodec"
role_ids = [20]
[[network]]
guild_id = 1
role_id = 10
name = "mesh"
[[network]]
guild_id = 1
role_id = 20
name = "mesh2"
[[enroll]]
key = "key-a"
user_id = 1
[[enroll]]
key = "key-b"
user_id = 2
[[enroll]]
key = "key-c"
user_id = 3
[[community]]
guild_id = 1
slug = "lan"
EOF

node_toml() { # $1=name $2=iface $3=port $4=endpoint_ip $5=key
  cat >"$TMP/$1.toml" <<EOF
coordinator = "http://10.0.0.1:8080"
allow_insecure_http = true
state_dir = "$TMP/$1"
enrollment_key = "$5"
device_name = "host-$1"
iface = "$2"
listen_port = $3
endpoint = "$4:$3"
refresh_secs = 2
disable_new_networks = false
EOF
}
node_toml a unla 51820 10.0.0.1 key-a
node_toml b unlb 51821 10.0.0.2 key-b
node_toml c unlc 51822 10.0.0.3 key-c

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 & COORD_PID=$!
for _ in $(seq 1 40); do curl -sf http://10.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done
"$ENG"     run "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
$NSB "$ENG" run "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
$NSC "$ENG" run "$TMP/c.toml" >"$TMP/c.log" 2>&1 &

for _ in $(seq 1 60); do
  [ "$(grep -c 'peer set' "$TMP/a.log" 2>/dev/null)" -ge 2 ] && break
  sleep 0.5
done
[ "$(grep -c 'peer set' "$TMP/a.log" 2>/dev/null)" -ge 2 ] || { echo "FAIL: A did not peer with both B and C"; tail -20 "$TMP"/*.log; exit 1; }

wg_ip() { grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/$1.log" | head -1 | awk '{print $1}'; }
A_IP=$(wg_ip a); B_IP=$(wg_ip b); C_IP=$(wg_ip c)
echo "A=$A_IP (mesh,mesh2)  B=$B_IP (mesh)  C=$C_IP (mesh2)"

# A's status must list a given peer IP.
a_has_peer() { "$ENG" ctl status "$TMP/a.toml" 2>/dev/null | grep -q "$1"; }
# Wait up to ~15s for a predicate.
wait_for() { for _ in $(seq 1 30); do "$@" && return 0; sleep 0.5; done; return 1; }

fail=0
a_has_peer "$B_IP" && a_has_peer "$C_IP" || { echo "FAIL: A didn't start peering both"; exit 1; }
echo "initial: A peers B (mesh) and C (mesh2) ✓"

echo "=== disable mesh2 on A ==="
"$ENG" ctl net "$TMP/a.toml" disable mesh2
# C must drop out of A's mesh; B must remain.
wait_for bash -c '! '"$ENG"' ctl status "'"$TMP"'/a.toml" 2>/dev/null | grep -q "'"$C_IP"'"' \
  && echo "  ok: C dropped from A after disabling mesh2" || { echo "  FAIL: C still peered"; fail=1; }
a_has_peer "$B_IP" && echo "  ok: B (mesh) still peered" || { echo "  FAIL: B dropped too"; fail=1; }
# Symmetric: C loses its only peer (A).
wait_for bash -c '! '"$ENG"' ctl status "'"$TMP"'/c.toml" 2>/dev/null | grep -q "'"$A_IP"'"' \
  && echo "  ok: A dropped from C (symmetric)" || { echo "  FAIL: A still in C's mesh"; fail=1; }

echo "=== re-enable mesh2 on A ==="
"$ENG" ctl net "$TMP/a.toml" enable mesh2
wait_for a_has_peer "$C_IP" && echo "  ok: C re-peered after enabling mesh2" || { echo "  FAIL: C did not return"; fail=1; }

# The point: opt-out must work even when the coordinator is unreachable. Kill it, then disable
# mesh2 — the command must succeed and A must drop C locally (its own enforcement), without the
# coordinator in the loop.
echo "=== coordinator DOWN: local opt-out still works ==="
kill "$COORD_PID" 2>/dev/null; wait "$COORD_PID" 2>/dev/null
if "$ENG" ctl net "$TMP/a.toml" disable mesh2; then
  echo "  ok: 'ctl net disable' succeeded with coordinator down"
else
  echo "  FAIL: toggle command failed when coordinator down"; fail=1
fi
wait_for bash -c '! '"$ENG"' ctl status "'"$TMP"'/a.toml" 2>/dev/null | grep -q "'"$C_IP"'"' \
  && echo "  ok: A dropped C locally while coordinator down" || { echo "  FAIL: C still peered offline"; fail=1; }
a_has_peer "$B_IP" && echo "  ok: B (mesh) still peered offline" || { echo "  FAIL: B dropped offline"; fail=1; }

[ "$fail" = 0 ] && { echo "RESULT: PASS ✓  peering toggle enforced (both ways online + locally offline)"; exit 0; }
echo "RESULT: FAIL ✗"; tail -n 20 "$TMP"/*.log; exit 1
