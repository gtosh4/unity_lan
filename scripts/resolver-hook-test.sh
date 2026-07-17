#!/usr/bin/env bash
# Live systemd-resolved hookup test (M6). Needs root + a real systemd-resolved on the host.
#
# Proves the resolver hook end to end: our `.unity.internal` DNS server + the real `resolver.rs`
# ResolvectlHook point the OS resolver at it via a `~unity.internal` routing domain, so `resolvectl
# query <name>.unity.internal` returns our answer — while global DNS is untouched. Scoped to a throwaway
# dummy link, reverted + deleted on exit, so it never disturbs the host's real DNS config.
#
# Usage:  cargo build && sudo scripts/resolver-hook-test.sh
#   (in a Claude session: `! sudo scripts/resolver-hook-test.sh`)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="${ENG:-$ROOT/target/debug/unitylan-engine}"

[ "$(id -u)" = "0" ] || { echo "FAIL: run as root (sudo) — resolvectl per-link config needs privilege"; exit 1; }
[ -x "$ENG" ] || { echo "build first: cargo build"; exit 1; }
systemctl is-active --quiet systemd-resolved || { echo "SKIP: systemd-resolved not active"; exit 0; }

IFACE="unl-restest"
LINK_IP="10.123.45.1"          # the link MUST have an address — resolved ignores per-link DNS on a
                               # non-operational link (this is why prod works: the wg iface carries its /32)
BIND="127.0.0.1:15353"        # standalone hook test binds loopback; the daemon binds its own mesh IP:53
NAME="host-a.alice.unity.internal"
IP="100.64.0.9"

cleanup() {
  "$ENG" resolver-revert "$IFACE" 2>/dev/null
  ip link del "$IFACE" 2>/dev/null
  kill "${SRV:-0}" 2>/dev/null
  resolvectl flush-caches 2>/dev/null
}
trap cleanup EXIT

# Throwaway link to anchor the per-link resolver config (kept off real interfaces).
ip link add "$IFACE" type dummy && ip link set "$IFACE" up
ip addr add "$LINK_IP/24" dev "$IFACE"

# Our real `.unity.internal` resolver, serving one name (bound on the link IP).
"$ENG" dns-serve "$BIND" "$NAME" "$IP" & SRV=$!
sleep 0.4

# The production hook: resolvectl dns <iface> <server> + domain <iface> ~unity.internal.
"$ENG" resolver-install "$IFACE" "$BIND" || { echo "FAIL: resolver-install"; exit 1; }
resolvectl dnssec "$IFACE" no   # `.unity.internal` is unsigned; don't let DNSSEC validation drop it
resolvectl flush-caches

# Positive: our .unity.internal name resolves through the OS resolver to our answer.
GOT="$(resolvectl query --legend=no "$NAME" 2>/dev/null | awk '{print $2; exit}')"
if [ "$GOT" = "$IP" ]; then
  echo "PASS: resolvectl query $NAME -> $GOT (via .unity.internal routing domain)"
else
  echo "FAIL: expected $IP, got '${GOT:-<none>}'"
  resolvectl query "$NAME"
  exit 1
fi

# Sanity: the routing domain is scoped — resolved shows ~unity.internal only on our link.
resolvectl domain "$IFACE" | grep -q 'unity.internal' && echo "PASS: ~unity.internal routing domain on $IFACE" \
  || { echo "FAIL: routing domain not set"; exit 1; }

echo "ALL PASS"
