#!/usr/bin/env bash
# Unprivileged WireGuard connectivity test.
#
# Builds two network namespaces joined by a veth, runs a boringtun WG node (the engine's
# `wg-node` subcommand) in each, and pings across the tunnel. Requires NO host root — it
# re-execs itself inside a user+net+mount namespace where the caller is mapped to root and
# holds CAP_NET_ADMIN scoped to that namespace.
#
# Usage:  cargo build -p unitylan-engine && scripts/wg-tunnel-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-$ROOT/target/debug/unitylan-engine}"

if [ "${UNL_INNS:-}" != "1" ]; then
  [ -x "$BIN" ] || { echo "build first: cargo build -p unitylan-engine"; exit 1; }
  command -v unshare >/dev/null || { echo "unshare missing (util-linux)"; exit 1; }
  exec unshare -Urnm --map-root-user env UNL_INNS=1 BIN="$BIN" bash "${BASH_SOURCE[0]}"
fi

# ---------------- inside the user+net+mount namespace ----------------
command -v nsenter >/dev/null || { echo "FAIL: nsenter missing"; exit 1; }
LOG="$(mktemp -d)"
trap 'kill $A_PID $B_PID $CHILD 2>/dev/null; rm -rf "$LOG"' EXIT

# boringtun's control socket lives at /var/run/wireguard/<if>.sock; make /run writable.
mount -t tmpfs none /run 2>/dev/null || { echo "FAIL: mount tmpfs /run"; exit 1; }
mkdir -p /run/wireguard
ip link set lo up

# Second netns = a child process's net namespace (addressed by PID; no /var/run/netns needed).
unshare --net -- sleep 300 & CHILD=$!
sleep 0.3
[ -e "/proc/$CHILD/ns/net" ] || { echo "FAIL: child netns"; exit 1; }
NS1="nsenter -t $CHILD -n"

# veth underlay between the two namespaces.
ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$CHILD"
ip addr add 10.0.0.1/24 dev veth0; ip link set veth0 up
$NS1 ip addr add 10.0.0.2/24 dev veth1; $NS1 ip link set veth1 up; $NS1 ip link set lo up
ping -c1 -W1 10.0.0.2 >/dev/null || { echo "FAIL: underlay veth"; exit 1; }
echo "underlay OK (10.0.0.1 <-> 10.0.0.2)"

read -r A_PRIV A_PUB < <("$BIN" wg-keygen)
read -r B_PRIV B_PUB < <("$BIN" wg-keygen)

"$BIN" wg-node unl-a "$A_PRIV" 51820 100.64.0.1/32 "$B_PUB" 10.0.0.2:51821 100.64.0.2/32 20 >"$LOG/A" 2>&1 & A_PID=$!
$NS1 "$BIN" wg-node unl-b "$B_PRIV" 51821 100.64.0.2/32 "$A_PUB" 10.0.0.1:51820 100.64.0.1/32 20 >"$LOG/B" 2>&1 & B_PID=$!

for _ in $(seq 1 40); do
  grep -q READY "$LOG/A" && grep -q READY "$LOG/B" && break; sleep 0.25
done
grep -q READY "$LOG/A" && grep -q READY "$LOG/B" || { echo "FAIL: nodes not ready"; cat "$LOG/A" "$LOG/B"; exit 1; }
ip link set unl-a up; $NS1 ip link set unl-b up      # admin-up so routes can be added
ip route replace 100.64.0.2/32 dev unl-a
$NS1 ip route replace 100.64.0.1/32 dev unl-b

echo "=== ping across WG tunnel (100.64.0.1 -> 100.64.0.2) ==="
if ping -c3 -W2 -I 100.64.0.1 100.64.0.2; then
  echo "RESULT: PASS ✓  (encrypted tunnel carries traffic)"
  exit 0
else
  echo "RESULT: FAIL ✗"; exit 1
fi
