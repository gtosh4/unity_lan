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
allow_insecure_http = true
state_dir = "$TMP/a"
enrollment_key = "key-a"
device_name = "host-a"
disable_new_networks = false
iface = "unla"
listen_port = 51820
endpoint = "10.0.0.1:51820"
refresh_secs = 2
EOF
cat >"$TMP/b.toml" <<EOF
coordinator = "http://10.0.0.1:8080"
allow_insecure_http = true
state_dir = "$TMP/b"
enrollment_key = "key-b"
device_name = "host-b"
disable_new_networks = false
iface = "unlb"
listen_port = 51821
endpoint = "10.0.0.2:51821"
refresh_secs = 2
EOF

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 & COORD_PID=$!
for _ in $(seq 1 40); do curl -sf http://10.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done

"$ENG" -c "$TMP/a.toml" run >"$TMP/a.log" 2>&1 &
$NS1 "$ENG" -c "$TMP/b.toml" run >"$TMP/b.log" 2>&1 &

for _ in $(seq 1 40); do
  grep -q "peer set" "$TMP/a.log" 2>/dev/null && grep -q "peer set" "$TMP/b.log" 2>/dev/null && break
  sleep 0.5
done

A_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/a.log" | head -1 | awk '{print $1}')
B_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/b.log" | head -1 | awk '{print $1}')
[ -n "$A_IP" ] && [ -n "$B_IP" ] || { echo "FAIL: nodes did not mesh"; cat "$TMP/a.log" "$TMP/b.log"; exit 1; }
echo "A=$A_IP  B=$B_IP  (meshed via coordinator seeds)"

# Naming: hostname is <device>.<user>.unity.internal — the community/guild is NOT in the name
# (one identity/IP across a coordinator's guilds; the guild tags shared networks instead).
if grep -qE 'host-a\.nodea\.unity\.internal' "$TMP/a.log" && ! grep -q '\.lan\.unity\.internal' "$TMP/a.log"; then
  echo "hostname: $(grep -oE 'host-a\.nodea\.unity\.internal' "$TMP/a.log" | head -1) (no community slug in name ✓)"
else
  echo "FAIL: hostname not <device>.<user>.unity.internal (or community slug leaked into name)"; grep -E '100\.[0-9]|unity\.internal' "$TMP/a.log"; exit 1
fi

# Primary: each node is its user's only device, so it auto-becomes primary.
grep -q '\[primary\]' "$TMP/a.log" || { echo "FAIL: node A not marked primary"; exit 1; }
echo "primary: node A auto-assigned primary ✓"

# DNS: query node A's resolver for peer B by name (A learned B as a seed). The resolver listens on
# node A's own mesh IP, port 53 (not loopback), so query it there.
echo "=== dns: resolve peer B via node A's .unity.internal resolver ==="
DNS_IP=$(dig @"$A_IP" +short host-b.nodeb.unity.internal A | head -1)
ALIAS_IP=$(dig @"$A_IP" +short nodeb.unity.internal A | head -1)
echo "host-b.nodeb.unity.internal -> ${DNS_IP:-<none>}   nodeb.unity.internal (primary alias) -> ${ALIAS_IP:-<none>}   (B=$B_IP)"
{ [ "$DNS_IP" = "$B_IP" ] && [ "$ALIAS_IP" = "$B_IP" ]; } || { echo "FAIL: resolver did not map peer name to its device IP"; exit 1; }
echo "dns: peer hostname + primary alias resolve to B ✓"

# Control socket: query node A's daemon for its status; it must list peer B.
echo "=== control socket: ctl status on node A ==="
CTL=$("$ENG" -c "$TMP/a.toml" ctl status 2>&1)
echo "$CTL"
echo "$CTL" | grep -q "$B_IP" || { echo "FAIL: ctl status did not list peer B"; exit 1; }
echo "ctl: status lists peer B ✓"

# Control mutations: rename node A's device (authenticated by its bearer token) and confirm.
echo "=== control mutations: ctl rename on node A ==="
"$ENG" -c "$TMP/a.toml" ctl rename workstation
"$ENG" -c "$TMP/a.toml" ctl devices | grep -q 'workstation.*this device' || { echo "FAIL: rename not reflected in devices"; exit 1; }
echo "ctl: rename applied + listed ✓"

# No manual plumbing: the daemon brings its own link up and installs routes.
echo "=== ping across mesh ($A_IP -> $B_IP) ==="
if ping -c3 -W2 -I "$A_IP" "$B_IP"; then
  echo "mesh ping ✓  membership -> coordinator seeds -> WG mesh -> traffic"
else
  echo "RESULT: FAIL ✗"; tail -15 "$TMP/a.log" "$TMP/b.log"; exit 1
fi

# Firewall: default-deny inbound on the wg iface; only ports the owner exposes are reachable.
echo "=== firewall: default-deny + expose enforcement (node B) ==="
grep -q "firewall: default-deny" "$TMP/b.log" || { echo "FAIL: node B did not install firewall"; tail -15 "$TMP/b.log"; exit 1; }
# Two TCP listeners on B: 9001 will be exposed, 9002 stays closed.
$NS1 socat TCP-LISTEN:9001,fork,reuseaddr /dev/null >/dev/null 2>&1 &
$NS1 socat TCP-LISTEN:9002,fork,reuseaddr /dev/null >/dev/null 2>&1 &
sleep 0.5
# A new TCP connect from A to B: exit 0 if open; a dropped (default-deny) port hangs → timeout.
probe() { timeout 3 bash -c "exec 3<>/dev/tcp/$B_IP/$1" >/dev/null 2>&1; }

probe 9001 && { echo "FAIL: 9001 reachable before expose (default-deny not enforced)"; exit 1; }
echo "pre-expose: 9001 blocked by default-deny ✓"
"$ENG" -c "$TMP/b.toml" ctl expose 9001
probe 9001 || { echo "FAIL: 9001 unreachable after expose"; exit 1; }
echo "post-expose: 9001 reachable ✓"
probe 9002 && { echo "FAIL: never-exposed 9002 reachable"; exit 1; }
echo "unexposed 9002 still blocked ✓"
"$ENG" -c "$TMP/b.toml" ctl unexpose 9001
probe 9001 && { echo "FAIL: 9001 still reachable after unexpose"; exit 1; }
echo "post-unexpose: 9001 blocked again ✓"

# Revocation: strip node B's role and restart the coordinator (persistent DB, empty presence).
# On reconnect A holds the role, B does not, so A's seed list no longer contains B → A prunes it.
echo "=== revocation: remove node B's role, restart coordinator ==="
awk '/^role_ids = \[10\]/ && ++c==2 {sub(/\[10\]/,"[]")} 1' "$TMP/coord.toml" >"$TMP/coord2.toml"
kill "$COORD_PID" 2>/dev/null; wait "$COORD_PID" 2>/dev/null
"$COORD" "$TMP/coord2.toml" >>"$TMP/coord.log" 2>&1 & COORD_PID=$!
for _ in $(seq 1 40); do curl -sf http://10.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done

for _ in $(seq 1 40); do grep -q "peer removed" "$TMP/a.log" 2>/dev/null && break; sleep 0.5; done
grep -q "peer removed" "$TMP/a.log" || { echo "FAIL: node A did not prune revoked peer B"; tail -15 "$TMP/a.log"; exit 1; }
echo "prune: node A dropped peer B after revocation ✓"

# Node A's status must no longer list B.
CTL=$("$ENG" -c "$TMP/a.toml" ctl status 2>&1)
if echo "$CTL" | grep -q "$B_IP"; then echo "FAIL: ctl status still lists revoked peer B"; echo "$CTL"; exit 1; fi
echo "ctl: status no longer lists B ✓"

echo "RESULT: PASS ✓  mesh forms, carries traffic, firewalls to exposed ports, prunes a revoked member"
exit 0
