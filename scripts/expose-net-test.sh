#!/usr/bin/env bash
# Expose scoping. Four nodes on two networks:
#   A ∈ {mesh, mesh2}   B ∈ {mesh}   C ∈ {mesh2}   D ∈ {mesh, mesh2}, same owner as A
# A peers with both B (shares mesh) and C (shares mesh2); B and C don't peer.
# A exposes 9001 --net mesh and 9002 --net mesh2, then we prove source scoping:
#   B reaches 9001 but not 9002; C reaches 9002 but not 9001.
# A also exposes 9004 --own-devices, which must admit D (the owner's other device) and refuse B —
# even though B shares network `mesh` with A, and D holds no network B doesn't.
# No host root — re-execs under `unshare -Urnm --map-root-user`. Nodes hang off a bridge so all
# three share one L2 segment (single WG endpoint each).
#
# Usage:  cargo build && scripts/expose-net-test.sh
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

# Bridge segment 10.0.0.0/24; A lives in the root netns on the bridge itself.
ip link add br0 type bridge
ip addr add 10.0.0.1/24 dev br0
ip link set br0 up

# Spawn a child netns attached to the bridge with the given host IP. Echoes the child PID.
make_node() {
  local name="$1" ip="$2" pid
  # Redirect the sleep's fds: otherwise the backgrounded job holds the $() stdout pipe open and
  # the command substitution that captures our PID would block until the sleep exits.
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
PIDD=$(make_node vethd 10.0.0.4)
NSB="nsenter -t $PIDB -n"
NSC="nsenter -t $PIDC -n"
NSD="nsenter -t $PIDD -n"

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
# A second guild whose role is *also* called "mesh". A and C are both in it; B is not. Two
# networks, same role name — the collision that guild-qualified scopes exist to keep apart.
[[fake.guild]]
id = 2
name = "Other"
[[fake.guild.member]]
user_id = 1
nick = "nodea"
role_ids = [30]
[[fake.guild.member]]
user_id = 3
nick = "nodec"
role_ids = [30]
[[network]]
guild_id = 2
role_id = 30
name = "mesh"
[[enroll]]
key = "key-a"
user_id = 1
[[enroll]]
key = "key-b"
user_id = 2
[[enroll]]
key = "key-c"
user_id = 3
# D is a second device of A's owner — the own-device scope is about identity, not membership.
[[enroll]]
key = "key-d"
user_id = 1
[[community]]
guild_id = 1
slug = "lan"
[[community]]
guild_id = 2
slug = "other"
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
node_toml d unld 51823 10.0.0.4 key-d

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf http://10.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done

"$ENG"     run "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
$NSB "$ENG" run "$TMP/b.toml" >"$TMP/b.log" 2>&1 &
$NSC "$ENG" run "$TMP/c.toml" >"$TMP/c.log" 2>&1 &
$NSD "$ENG" run "$TMP/d.toml" >"$TMP/d.log" 2>&1 &

# A must learn all three co-members (one per network, plus its owner's other device).
for _ in $(seq 1 60); do
  [ "$(grep -c 'peer set' "$TMP/a.log" 2>/dev/null)" -ge 3 ] && break
  sleep 0.5
done
[ "$(grep -c 'peer set' "$TMP/a.log" 2>/dev/null)" -ge 3 ] || { echo "FAIL: A did not peer with B, C and D"; tail -20 "$TMP"/*.log; exit 1; }

wg_ip() { grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/$1.log" | head -1 | awk '{print $1}'; }
A_IP=$(wg_ip a); B_IP=$(wg_ip b); C_IP=$(wg_ip c); D_IP=$(wg_ip d)
[ -n "$A_IP" ] && [ -n "$B_IP" ] && [ -n "$C_IP" ] && [ -n "$D_IP" ] || { echo "FAIL: missing wg IPs"; exit 1; }
echo "A=$A_IP (mesh,mesh2)  B=$B_IP (mesh)  C=$C_IP (mesh2)  D=$D_IP (A's other device)"

# Listeners on A for both ports (A is in the root netns).
socat TCP-LISTEN:9001,fork,reuseaddr /dev/null >/dev/null 2>&1 &
socat TCP-LISTEN:9002,fork,reuseaddr /dev/null >/dev/null 2>&1 &
socat TCP-LISTEN:9004,fork,reuseaddr /dev/null >/dev/null 2>&1 &
socat TCP-LISTEN:9005,fork,reuseaddr /dev/null >/dev/null 2>&1 &
sleep 0.5
# probe <netns-prefix> <port> → exit 0 if a new TCP connect to A succeeds (dropped port → timeout).
probe() { $1 timeout 3 bash -c "exec 3<>/dev/tcp/$A_IP/$2" >/dev/null 2>&1; }

echo "=== expose 9001 mesh@lan, 9002 mesh2 (bare), 9004 --own-devices on A ==="
# Pinned: "mesh" exists in both of A's guilds. 9002 stays bare on purpose — "mesh2" is unique to
# one guild, so it exercises the unqualified path still resolving when there's no ambiguity.
"$ENG" ctl expose "$TMP/a.toml" 9001 mesh --guild lan
"$ENG" ctl expose "$TMP/a.toml" 9002 mesh2
"$ENG" ctl expose "$TMP/a.toml" 9004 --own-devices
# "mesh" exists in both guilds, so it must be pinned to one; B is in lan/mesh, C is in other/mesh.
"$ENG" ctl expose "$TMP/a.toml" 9005 mesh --guild lan

fail=0
check() { # <desc> <expect open|blocked> <netns> <port>
  if probe "$3" "$4"; then got=open; else got=blocked; fi
  if [ "$got" = "$2" ]; then echo "  ok: $1 ($got)"; else echo "  FAIL: $1 — expected $2, got $got"; fail=1; fi
}
check "B (mesh) -> 9001 [scoped to mesh]"   open    "$NSB" 9001
check "C (mesh2) -> 9001 [scoped to mesh]"  blocked "$NSC" 9001
check "C (mesh2) -> 9002 [scoped to mesh2]" open    "$NSC" 9002
check "B (mesh) -> 9002 [scoped to mesh2]"  blocked "$NSB" 9002
# The own-device scope: D is admitted by identity, B refused despite sharing a network with A.
check "D (A's device) -> 9004 [own-devices]" open    "$NSD" 9004
check "B (co-member)  -> 9004 [own-devices]" blocked "$NSB" 9004
check "C (co-member)  -> 9004 [own-devices]" blocked "$NSC" 9004
# Guild-qualified: B is in lan/mesh; C is in other/mesh, a different network with the same role
# name. Keying the source set on the name alone would let C in here.
check "B (lan/mesh)   -> 9005 [mesh @ lan]"  open    "$NSB" 9005
check "C (other/mesh) -> 9005 [mesh @ lan]"  blocked "$NSC" 9005

# Sanity: a --net for a network A doesn't hold must be rejected. Capture first — `ctl` exits
# non-zero by design, and under pipefail that would mask grep's match in an `if … | grep`.
reject_out=$("$ENG" ctl expose "$TMP/a.toml" 9003 nonesuch 2>&1 || true)
if echo "$reject_out" | grep -q "not a member"; then
  echo "  ok: expose --net nonesuch rejected"
else
  echo "  FAIL: expose to a non-held network was not rejected ($reject_out)"; fail=1
fi

# A bare "mesh" names a role A holds in *two* guilds. Guessing either would expose the port to a
# community the caller never named, so it must refuse and say so.
ambig_out=$("$ENG" ctl expose "$TMP/a.toml" 9006 mesh 2>&1 || true)
if echo "$ambig_out" | grep -q "ambiguous"; then
  echo "  ok: bare 'mesh' refused as ambiguous across guilds"
else
  echo "  FAIL: ambiguous network name was not refused ($ambig_out)"; fail=1
fi

[ "$fail" = 0 ] && { echo "RESULT: PASS ✓  per-network, per-guild and own-device expose scoping enforced"; exit 0; }
echo "RESULT: FAIL ✗"; tail -n 20 "$TMP"/*.log; exit 1
