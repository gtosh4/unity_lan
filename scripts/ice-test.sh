#!/usr/bin/env bash
# Unprivileged side-socket ICE test (M5.5).
#
# Topology (all inside one user+net+mount namespace, no host root):
#
#     B ── natB ──┐                 ┌── natC ── C
#   (10.11.0.2)   │                 │        (10.12.0.2)
#                 └── hub (public) ─┘
#                     10.0.0.1  = coordinator + node A (reachable, RELAY)
#
# Same base topology as relay-test.sh, but ICE is left ON (the default) instead of forced off — so
# this exercises the M5.5 side-socket ICE path, where the M5.4 relay is reached as ICE's *relay
# candidate* rather than by the standalone RelayManager:
#   1. Node A opts in as a relay (`relay = true`) — it runs the embedded TURN server on :3478, which
#      also answers STUN Binding (so it doubles as B's and C's server-reflexive source).
#   2. The two NAT externals (10.0.0.2 and 10.0.0.3) are firewall-isolated from *each other* (both
#      still reach A at 10.0.0.1). So B and C can never punch, and their ICE host/srflx candidate
#      pairs can't connect either — the ONLY pair that validates is relay↔relay through A.
#
# Flow: B & C mesh with A, punch each other, fail (isolated) → `Unreachable` → each runs a side-socket
# ICE agent (webrtc-ice) for the other, gathering host + srflx (STUN A) + relay (TURN A) candidates,
# exchanging them over the coordinator long-poll → connectivity checks pick the relay↔relay pair →
# WG ciphertext rides A's TURN relay via ICE → B pings C. GATED like relay-test: the winning pair's
# legs are single conntrack-friendly flows to A:3478, so they traverse netns NAT reliably.
#
# Usage:  cargo build && scripts/ice-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="${ENG:-$ROOT/target/debug/unitylan-engine}"
COORD="${COORD:-$ROOT/target/debug/unitylan-coordinator}"

if [ "${UNL_INNS:-}" != "1" ]; then
  [ -x "$ENG" ] && [ -x "$COORD" ] || { echo "build first: cargo build"; exit 1; }
  exec unshare -Urnm --map-root-user env UNL_INNS=1 ENG="$ENG" COORD="$COORD" KEEP_DIR="${KEEP_DIR:-}" bash "${BASH_SOURCE[0]}"
fi

# ---------------- inside the namespace ----------------
TMP="${KEEP_DIR:-$(mktemp -d)}"
mkdir -p "$TMP"
trap 'kill $(jobs -p) 2>/dev/null; [ -n "${KEEP_DIR:-}" ] || rm -rf "$TMP"' EXIT
mount -t tmpfs none /run 2>/dev/null || { echo "FAIL: mount /run"; exit 1; }
mkdir -p /run/wireguard
ip link set lo up
echo 1 >/proc/sys/net/ipv4/ip_forward

mkns() { unshare --net -- sleep 900 >/dev/null 2>&1 & echo $!; }
NAT_B=$(mkns); NAT_C=$(mkns); INR_B=$(mkns); INR_C=$(mkns)
sleep 0.3
NB="nsenter -t $NAT_B -n"; NC="nsenter -t $NAT_C -n"
IB="nsenter -t $INR_B -n"; IC="nsenter -t $INR_C -n"

# hub: bridged "public" 10.0.0.0/24. Coordinator + node A (the relay) at 10.0.0.1.
ip link add br0 type bridge; ip addr add 10.0.0.1/24 dev br0; ip link set br0 up

ip link add hb0 type veth peer name wb1; ip link set wb1 netns "$NAT_B"
ip link set hb0 master br0; ip link set hb0 up
$NB ip addr add 10.0.0.2/24 dev wb1; $NB ip link set wb1 up; $NB ip link set lo up

ip link add hc0 type veth peer name wc1; ip link set wc1 netns "$NAT_C"
ip link set hc0 master br0; ip link set hc0 up
$NC ip addr add 10.0.0.3/24 dev wc1; $NC ip link set wc1 up; $NC ip link set lo up

$NB ip link add lb0 type veth peer name lb1
$NB ip link set lb1 netns "$INR_B"
$NB ip addr add 10.11.0.1/24 dev lb0; $NB ip link set lb0 up
$IB ip addr add 10.11.0.2/24 dev lb1; $IB ip link set lb1 up; $IB ip link set lo up

$NC ip link add lc0 type veth peer name lc1
$NC ip link set lc1 netns "$INR_C"
$NC ip addr add 10.12.0.1/24 dev lc0; $NC ip link set lc0 up
$IC ip addr add 10.12.0.2/24 dev lc1; $IC ip link set lc1 up; $IC ip link set lo up

# Full-cone NAT on each gateway (as in nat-test.sh) — a stable outbound mapping + inbound DNAT.
setup_nat() {  # $1=netns-cmd  $2=wan-iface  $3=gateway  $4=inner-host-ip  $5=wg-port
  $1 sh -c "echo 1 >/proc/sys/net/ipv4/ip_forward"
  $1 ip route add default via "$3"
  $1 nft add table ip nat
  $1 nft add chain ip nat post '{ type nat hook postrouting priority 100 ; }'
  $1 nft add rule ip nat post oifname "$2" masquerade
  $1 nft add chain ip nat pre '{ type nat hook prerouting priority -100 ; }'
  $1 nft add rule ip nat pre iifname "$2" udp dport "$5" dnat to "$4":"$5"
}
setup_nat "$NB" wb1 10.0.0.1 10.11.0.2 51821
setup_nat "$NC" wc1 10.0.0.1 10.12.0.2 51822

# Isolate the two NAT externals from EACH OTHER (but not from A): guarantees the B↔C hole punch can
# never complete, so a tunnel can only form through A's relay. Drop forwarded traffic to/from the
# other external at each gateway.
isolate() {  # $1=netns-cmd  $2=other-external-ip
  $1 nft add table ip filter
  $1 nft add chain ip filter isol '{ type filter hook forward priority 0 ; }'
  $1 nft add rule ip filter isol ip daddr "$2" drop
  $1 nft add rule ip filter isol ip saddr "$2" drop
}
isolate "$NB" 10.0.0.3
isolate "$NC" 10.0.0.2

$IB ip route add default via 10.11.0.1
$IC ip route add default via 10.12.0.1

# --- coordinator: A, B, C all members of network "mesh" (role 10) ---
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
[[fake.guild.member]]
user_id = 3
nick = "nodec"
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
[[enroll]]
key = "key-c"
user_id = 3
[[community]]
guild_id = 1
slug = "lan"
EOF

# A is reachable AND a relay. B and C advertise no endpoint → NAT'd, and isolated from each other.
cat >"$TMP/a.toml" <<EOF
coordinator = "http://10.0.0.1:8080"
state_dir = "$TMP/a"
enrollment_key = "key-a"
device_name = "host-a"
disable_new_networks = false
iface = "unla"
listen_port = 51820
endpoint = "10.0.0.1:51820"
upnp = false
firewall = false
relay = true
relay_port = 3478
refresh_secs = 2
EOF
cat >"$TMP/b.toml" <<EOF
coordinator = "http://10.0.0.1:8080"
state_dir = "$TMP/b"
enrollment_key = "key-b"
device_name = "host-b"
disable_new_networks = false
iface = "unlb"
listen_port = 51821
upnp = false
firewall = false
refresh_secs = 2
EOF
cat >"$TMP/c.toml" <<EOF
coordinator = "http://10.0.0.1:8080"
state_dir = "$TMP/c"
enrollment_key = "key-c"
device_name = "host-c"
disable_new_networks = false
iface = "unlc"
listen_port = 51822
upnp = false
firewall = false
refresh_secs = 2
EOF

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf http://10.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done

"$ENG" run "$TMP/a.toml"      >"$TMP/a.log" 2>&1 &
$IB "$ENG" run "$TMP/b.toml"  >"$TMP/b.log" 2>&1 &
$IC "$ENG" run "$TMP/c.toml"  >"$TMP/c.log" 2>&1 &

# A's embedded TURN relay must come up.
for _ in $(seq 1 40); do grep -q "TURN server up" "$TMP/a.log" 2>/dev/null && break; sleep 0.25; done
grep -q "TURN server up" "$TMP/a.log" || { echo "FAIL: relay node A did not start its TURN server"; tail -20 "$TMP/a.log"; exit 1; }
echo "relay node A: TURN server up ✓"

# Mesh bootstraps (B and C reach A).
for _ in $(seq 1 40); do
  grep -q "peer set" "$TMP/b.log" 2>/dev/null && grep -q "peer set" "$TMP/c.log" 2>/dev/null && break
  sleep 0.5
done
B_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/b.log" | head -1 | awk '{print $1}')
C_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/c.log" | head -1 | awk '{print $1}')
[ -n "$B_IP" ] && [ -n "$C_IP" ] || { echo "FAIL: NAT'd nodes did not register"; tail -20 "$TMP/b.log" "$TMP/c.log"; exit 1; }
echo "A=10.0.0.1 (relay)  B=$B_IP  C=$C_IP (behind isolated NATs)"

# B and C punch, fail (isolated), go Unreachable, then each starts a side-socket ICE agent for the
# other and negotiates a working pair. Gate on both nodes' ICE agents connecting (the relay↔relay
# pair is the only one that validates here).
echo "=== waiting for ICE to connect (punch fails → Unreachable → ICE agent → relay pair) ==="
CONNECTED=0
for _ in $(seq 1 200); do
  if grep -q "ice: connected" "$TMP/b.log" 2>/dev/null && grep -q "ice: connected" "$TMP/c.log" 2>/dev/null; then
    CONNECTED=1; break
  fi
  sleep 0.5
done
[ "$CONNECTED" = 1 ] || { echo "FAIL: B and C never connected via ICE"; echo "-- b --"; tail -40 "$TMP/b.log"; echo "-- c --"; tail -40 "$TMP/c.log"; exit 1; }
echo "  B: $(grep -h 'ice: connected' "$TMP/b.log" | tail -1)"
echo "  C: $(grep -h 'ice: connected' "$TMP/c.log" | tail -1)"
echo "ICE connect ✓  both stuck peers negotiated a pair via ICE"

# Data-plane hop (GATED): carry a ping B -> C over the ICE-negotiated (relay↔relay) path. This must
# succeed — the winning pair's legs are conntrack-friendly flows to A:3478 that traverse the NATs.
echo "=== data-plane: ping B -> C over the ICE path ($B_IP -> $C_IP) ==="
OK=0
for _ in $(seq 1 40); do
  if $IB ping -c2 -W2 -I "$B_IP" "$C_IP" >/dev/null 2>&1; then OK=1; break; fi
  sleep 1
done
[ "$OK" = 1 ] || { echo "FAIL: ping did not traverse the ICE path"; echo "-- b --"; tail -30 "$TMP/b.log"; echo "-- c --"; tail -30 "$TMP/c.log"; exit 1; }
$IB ping -c3 -W2 -I "$B_IP" "$C_IP"
echo "data-plane ✓  ping traversed the ICE-negotiated path through A"

# The daemon marks an ICE-routed peer `[ice]` over the control socket.
echo "=== diagnostics: B's view of C via ctl status ==="
"$ENG" ctl status "$TMP/b.toml" 2>&1 | grep -E "peers|$C_IP" || echo "  (ctl status unavailable)"
"$ENG" ctl status "$TMP/b.toml" 2>&1 | grep -q "ice" && echo "ctl status: C shown [ice] ✓"

echo "RESULT: PASS ✓  punch isolated → ICE negotiated → relay pair selected → WG ciphertext rides ICE end-to-end"
exit 0
