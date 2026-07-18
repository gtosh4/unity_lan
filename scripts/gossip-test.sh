#!/usr/bin/env bash
# Peer-direct attestation refresh (docs/gossip-refresh.md) end-to-end test.
#
# Two engines mesh via a coordinator that signs SHORT-lived attestations (attestation_ttl_secs).
# Then node A is cut off from the coordinator (nft drop in its netns) while node B stays connected.
# With gossip on, A keeps its peer B alive past several attestation TTLs by pulling B's fresh
# attestation straight from B over the tunnel — proving the mesh self-maintains freshness without the
# coordinator. Then B is killed: A can no longer refresh B from anywhere, so A drops B on expiry —
# proving revocation propagates via expiry even while the coordinator is unreachable.
#
# Topology (mirrors mesh-test): coordinator + node B in the main ns; node A in a child net ns, so
# blocking A->coordinator is a local nft rule in A's ns that leaves the A<->B WG tunnel untouched.
#
# Usage:  cargo build && scripts/gossip-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="${ENG:-$ROOT/target/debug/unitylan-engine}"
COORD="${COORD:-$ROOT/target/debug/unitylan-coordinator}"
TTL=20 # attestation lifetime (s) — short so expiry/refresh happen in seconds

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

# Child ns holds node A; the main ns holds the coordinator + node B.
unshare --net -- sleep 300 & CHILD=$!
sleep 0.3
NSA="nsenter -t $CHILD -n"
ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$CHILD"
ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
$NSA ip addr add 10.0.0.2/24 dev veth1; $NSA ip link set veth1 up; $NSA ip link set lo up

cat >"$TMP/coord.toml" <<EOF
bind = "10.0.0.1:8080"
database = "$TMP/coord.db"
attestation_ttl_secs = $TTL
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
# Node A (child ns). gossip on; a fast refresh so the loop (and its peer-direct step) ticks quickly.
cat >"$TMP/a.toml" <<EOF
coordinator = "http://10.0.0.1:8080"
allow_insecure_http = true
state_dir = "$TMP/a"
enrollment_key = "key-a"
device_name = "host-a"
disable_new_networks = false
iface = "unla"
listen_port = 51820
endpoint = "10.0.0.2:51820"
refresh_secs = 2
gossip = true
EOF
# Node B (main ns). gossip on so it serves its own attestation to A.
cat >"$TMP/b.toml" <<EOF
coordinator = "http://10.0.0.1:8080"
allow_insecure_http = true
state_dir = "$TMP/b"
enrollment_key = "key-b"
device_name = "host-b"
disable_new_networks = false
iface = "unlb"
listen_port = 51821
endpoint = "10.0.0.1:51821"
refresh_secs = 2
gossip = true
EOF

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 & COORD_PID=$!
for _ in $(seq 1 40); do curl -sf http://10.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done

# A in the child ns with daemon debug on, so the peer-direct refresh line is captured as evidence.
$NSA env RUST_LOG="info,unitylan_engine::daemon=debug" "$ENG" run "$TMP/a.toml" >"$TMP/a.log" 2>&1 &
"$ENG" run "$TMP/b.toml" >"$TMP/b.log" 2>&1 &

for _ in $(seq 1 40); do
  grep -q "peer set" "$TMP/a.log" 2>/dev/null && grep -q "peer set" "$TMP/b.log" 2>/dev/null && break
  sleep 0.5
done
A_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/a.log" | head -1 | awk '{print $1}')
B_IP=$(grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/b.log" | head -1 | awk '{print $1}')
[ -n "$A_IP" ] && [ -n "$B_IP" ] || { echo "FAIL: nodes did not mesh"; cat "$TMP/a.log" "$TMP/b.log"; exit 1; }
echo "A=$A_IP  B=$B_IP  (meshed via coordinator; attestation TTL=${TTL}s, gossip on)"

$NSA ping -c2 -W2 -I "$A_IP" "$B_IP" >/dev/null 2>&1 || { echo "FAIL: initial mesh ping"; exit 1; }
echo "initial mesh ping ✓"

# ---- Cut node A off from the coordinator (leave the A<->B WG tunnel alone) ----
echo "=== cut node A off from the coordinator (nft drop tcp/8080 in A's ns) ==="
$NSA nft add table ip blk
$NSA nft "add chain ip blk out { type filter hook output priority 0 ; policy accept ; }"
$NSA nft add rule ip blk out ip daddr 10.0.0.1 tcp dport 8080 drop
# Confirm A really can't reach the coordinator now.
$NSA curl -sf -m2 http://10.0.0.1:8080/healthz >/dev/null 2>&1 && { echo "FAIL: A still reaches coordinator after block"; exit 1; }
echo "A -> coordinator blocked ✓"

# Cut off from the coordinator, the only way A can keep B fresh is by pulling B's attestation straight
# from B (peer-direct). Without gossip A would drop B within one TTL. Poll for the evidence.
echo "=== A is coordinator-isolated; expect it to keep B via peer-direct refresh ==="
for _ in $(seq 1 $((TTL * 4))); do
  grep -q "attestation refreshed peer-direct" "$TMP/a.log" 2>/dev/null && break
  sleep 1
done
grep -q "attestation refreshed peer-direct" "$TMP/a.log" || { echo "FAIL: A did not refresh B peer-direct"; grep -E "peer-direct|refresh" "$TMP/a.log" | tail; exit 1; }
echo "A refreshed B's attestation peer-direct ✓"

# Keep going well past several TTLs, then confirm A still holds B and the tunnel still carries traffic.
sleep $((TTL * 2))
CTL=$($NSA "$ENG" ctl status "$TMP/a.toml" 2>&1)
echo "$CTL" | grep -q "$B_IP" || { echo "FAIL: A dropped B despite peer-direct refresh"; echo "$CTL"; exit 1; }
# Data-plane check (retry: at this extreme short TTL the WG handshake can briefly flap as attestations
# churn — a test artifact, not a real-TTL concern).
PINGED=0
for _ in $(seq 1 15); do
  $NSA ping -c1 -W2 -I "$A_IP" "$B_IP" >/dev/null 2>&1 && { PINGED=1; break; }
  sleep 1
done
[ "$PINGED" = 1 ] || { echo "FAIL: mesh ping never recovered while A coordinator-isolated"; exit 1; }
echo "A still meshed with B past $((TTL * 4))s of coordinator isolation ✓  (peer-direct carried it)"

# ---- Now kill B: A can no longer refresh B from anywhere -> A drops B on expiry ----
echo "=== kill node B; A can refresh B neither from coordinator (blocked) nor from B (dead) ==="
pkill -f "$TMP/b.toml" 2>/dev/null
for _ in $(seq 1 $((TTL * 4))); do
  grep -q "lapsed attestations" "$TMP/a.log" 2>/dev/null && break
  sleep 1
done
grep -q "lapsed attestations" "$TMP/a.log" || { echo "FAIL: A did not drop B on attestation expiry"; tail -20 "$TMP/a.log"; exit 1; }
echo "A dropped B on attestation expiry ✓  (revocation via expiry, coordinator unreachable)"
CTL=$($NSA "$ENG" ctl status "$TMP/a.toml" 2>&1)
if echo "$CTL" | grep -q "$B_IP"; then echo "FAIL: A still lists B after expiry drop"; echo "$CTL"; exit 1; fi
echo "A's status no longer lists B ✓"

echo "RESULT: PASS ✓  peer-direct refresh keeps a coordinator-isolated node meshed; expiry drops an unrefreshable peer"
exit 0
