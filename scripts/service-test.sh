#!/usr/bin/env bash
# Named services, end to end. Three nodes on two networks:
#   A ∈ {mesh, mesh2}   B ∈ {mesh}   C ∈ {mesh2}
# A serves `mc` scoped to mesh and `jelly` offered to both networks, then we prove the two halves of the
# feature that only meet on a real mesh:
#   * the name resolves — B's resolver answers A's service name with A's mesh address. A's handle is
#     deliberately not a valid DNS label, so the expected names are derived from the hostname the
#     engine reports rather than hardcoded: composing them from the Discord handle is the bug this
#     pins down;
#   * the name is scoped exactly like the port — C, who cannot reach `mc`, is never even told it
#     exists, while both peers learn `jelly`, which A offered to both.
# Announcements are peer-direct over the tunnel; the coordinator holds no service state, so this
# also demonstrates a mesh feature that costs the control plane nothing.
#
# No host root — re-execs under `unshare -Urnm --map-root-user`. Nodes hang off a bridge so all
# three share one L2 segment (single WG endpoint each).
#
# Usage:  cargo build && scripts/service-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="${ENG:-$ROOT/target/debug/unitylan-engine}"
COORD="${COORD:-$ROOT/target/debug/unitylan-coordinator}"

if [ "${UNL_INNS:-}" != "1" ]; then
  [ -x "$ENG" ] && [ -x "$COORD" ] || { echo "build first: cargo build"; exit 1; }
  command -v dig >/dev/null || { echo "needs dig (bind-utils / dnsutils)"; exit 1; }
  exec unshare -Urnm --map-root-user env UNL_INNS=1 ENG="$ENG" COORD="$COORD" bash "${BASH_SOURCE[0]}"
fi

# ---------------- inside the user+net+mount namespace ----------------
TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; sleep 0.5; kill -9 $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT
mount -t tmpfs none /run 2>/dev/null || { echo "FAIL: mount /run"; exit 1; }
mkdir -p /run/wireguard
ip link set lo up

ip link add br0 type bridge
ip addr add 10.0.0.1/24 dev br0
ip link set br0 up

make_node() { # $1=name $2=ip → echoes the child PID
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
# Deliberately not a usable DNS label. The user part of a mesh name is allocated by the
# coordinator (sanitised, suffixed on collision), so a client that composes a name from the Discord
# handle instead prints one that never resolves. NOTE: no backticks in this heredoc -- it is
# unquoted, so they would run as command substitution and silently empty the config.
username = "nodea#4021"
role_ids = [10, 20]
[[fake.guild.member]]
user_id = 2
username = "nodeb"
role_ids = [10]
[[fake.guild.member]]
user_id = 3
username = "nodec"
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

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf http://10.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done

"$ENG" -c "$TMP/a.toml" run >"$TMP/a.log" 2>&1 &
$NSB "$ENG" -c "$TMP/b.toml" run >"$TMP/b.log" 2>&1 &
$NSC "$ENG" -c "$TMP/c.toml" run >"$TMP/c.log" 2>&1 &

for _ in $(seq 1 60); do
  [ "$(grep -c 'peer set' "$TMP/a.log" 2>/dev/null)" -ge 2 ] && break
  sleep 0.5
done
[ "$(grep -c 'peer set' "$TMP/a.log" 2>/dev/null)" -ge 2 ] \
  || { echo "FAIL: A did not peer with B and C"; tail -n 20 "$TMP"/*.log; exit 1; }

wg_ip() { grep -oE '100\.[0-9]+\.[0-9]+\.[0-9]+ ->' "$TMP/$1.log" | head -1 | awk '{print $1}'; }
A_IP=$(wg_ip a); B_IP=$(wg_ip b); C_IP=$(wg_ip c)
[ -n "$A_IP" ] && [ -n "$B_IP" ] && [ -n "$C_IP" ] || { echo "FAIL: missing wg IPs"; exit 1; }
echo "A=$A_IP (mesh,mesh2)  B=$B_IP (mesh)  C=$C_IP (mesh2)"

fail=0
ok()  { echo "  ok: $1"; }
bad() { echo "  FAIL: $1"; fail=1; }

echo "=== A serves 'mc' (scoped to mesh) and 'jelly' (both networks) ==="
"$ENG" -c "$TMP/a.toml" ctl service add mc 25565 --net mesh >"$TMP/svc.log" 2>&1 \
  || { bad "service add mc: $(tail -2 "$TMP/svc.log")"; }
# Every exposure names who it is for, so reaching both networks is two scopes on one name.
for n in mesh mesh2; do
  "$ENG" -c "$TMP/a.toml" ctl service add jelly 8096 --net "$n" >>"$TMP/svc.log" 2>&1 \
    || { bad "service add jelly --net $n: $(tail -2 "$TMP/svc.log")"; }
done

# A's allocated `<user>` label, read out of the hostname the engine reports — never assumed from the
# Discord handle, which here is `nodea#4021` and is not a DNS label at all.
A_HOST=$(grep -oE 'host-a\.[a-z0-9-]+\.unity\.internal' "$TMP/a.log" | head -1)
A_USER=${A_HOST#host-a.}
A_USER=${A_USER%.unity.internal}
[ -n "$A_USER" ] && [ "$A_USER" != "nodea#4021" ] \
  && ok "A's user label was allocated, not taken from the handle ($A_USER)" \
  || bad "could not read A's allocated user label (host=$A_HOST)"
MC="mc.$A_USER.unity.internal"
JELLY="jelly.$A_USER.unity.internal"

# The name a peer types, printed by A itself — it is the one that knows its allocated user label.
LIST=$("$ENG" -c "$TMP/a.toml" ctl services 2>&1)
echo "$LIST" | grep -q "$MC" \
  && ok "A lists mc under its allocated user label" || bad "A's service list is wrong: $LIST"

# An unusable label must be refused before it reaches the daemon's state.
badname=$("$ENG" -c "$TMP/a.toml" ctl service add 'Not A Name' 9999 2>&1 || true)
echo "$badname" | grep -qi "not a usable service name" \
  && ok "an unusable service name is refused" || bad "bad label was not refused ($badname)"

echo "=== peers learn the names peer-direct, scoped like the ports ==="
# Announcements ride the tunnel on their own cadence — there is no push, so a peer learns a new
# service on its next poll. Wait out a full `mesh_services::REFRESH` (30s) plus slack.
dig_at() { # $1=netns-prefix $2=resolver-ip $3=name → the A record, or empty
  $1 dig @"$2" +short A "$3" +time=2 +tries=1 2>/dev/null | head -1
}
for _ in $(seq 1 90); do
  [ "$(dig_at "$NSB" "$B_IP" "$MC")" = "$A_IP" ] && break
  sleep 0.5
done

got=$(dig_at "$NSB" "$B_IP" "$MC")
[ "$got" = "$A_IP" ] && ok "B resolves $MC -> A" \
  || bad "B resolved mc to '$got', expected $A_IP"

got=$(dig_at "$NSB" "$B_IP" "$JELLY")
[ "$got" = "$A_IP" ] && ok "B resolves $JELLY -> A" \
  || bad "B resolved jelly to '$got', expected $A_IP"

# C polls on its own cadence, so wait for it the way we waited for B before asserting anything about
# what C knows — otherwise "C hasn't polled yet" and "C was never told" look identical, which would
# make the scope assertion below pass for the wrong reason.
for _ in $(seq 1 90); do
  [ "$(dig_at "$NSC" "$C_IP" "$JELLY")" = "$A_IP" ] && break
  sleep 0.5
done

# C is in mesh2, which `mc` is not scoped to. It must never learn the name — being told about a
# service it cannot reach would leak exactly what the scope exists to withhold.
got=$(dig_at "$NSC" "$C_IP" "$MC")
[ -z "$got" ] && ok "C is never told about mc (scoped to a network it isn't in)" \
  || bad "C resolved a service outside its scope: '$got'"

# ...while the one offered to both networks reaches both.
got=$(dig_at "$NSC" "$C_IP" "$JELLY")
[ "$got" = "$A_IP" ] && ok "C resolves jelly, which A offered to mesh2 as well" \
  || bad "C resolved jelly to '$got', expected $A_IP"

echo "=== widening a service by name reaches the network it gains ==="
# `service scope` widens by name: A never restates mc's port, and the announcement scoping follows,
# so C — previously not told the name existed — starts resolving it.
"$ENG" -c "$TMP/a.toml" ctl service scope mc --net mesh2 >>"$TMP/svc.log" 2>&1 \
  || bad "service scope failed: $(tail -2 "$TMP/svc.log")"
for _ in $(seq 1 90); do
  [ "$(dig_at "$NSC" "$C_IP" "$MC")" = "$A_IP" ] && break
  sleep 0.5
done
got=$(dig_at "$NSC" "$C_IP" "$MC")
[ "$got" = "$A_IP" ] && ok "C resolves mc once A widens it to mesh2" \
  || bad "C resolved mc to '$got' after widening, expected $A_IP"

# Widening must not have moved it: B is in mesh and keeps it.
got=$(dig_at "$NSB" "$B_IP" "$MC")
[ "$got" = "$A_IP" ] && ok "B still resolves mc after the widening" \
  || bad "widening mc lost its original scope (B got '$got')"

# One name, one port, two scopes — not a second port invented along the way.
ports=$("$ENG" -c "$TMP/a.toml" ctl exposes 2>&1 | grep -c "25565" || true)
[ "$ports" = 2 ] && ok "the widened service is one port on two scopes" \
  || bad "expected 25565 on exactly 2 scopes, found $ports"

# Saying it twice is a no-op, not a duplicate rule.
again=$("$ENG" -c "$TMP/a.toml" ctl service scope mc --net mesh2 2>&1)
echo "$again" | grep -qi "already open" \
  && ok "widening to a scope it already has says so" || bad "re-widening was not a no-op: $again"

# A device name outranks a service label: A cannot make its own hostname point elsewhere, and a
# name nobody claims stays NXDOMAIN.
got=$(dig_at "$NSB" "$B_IP" "nothing.$A_USER.unity.internal")
[ -z "$got" ] && ok "an unclaimed name does not resolve" \
  || bad "an unclaimed service name resolved to '$got'"

echo "=== removing a service withdraws the name ==="
"$ENG" -c "$TMP/a.toml" ctl service rm mc >>"$TMP/svc.log" 2>&1 \
  || bad "service rm failed: $(tail -2 "$TMP/svc.log")"
# Withdrawal travels the same way an announcement does, so it takes a poll too.
for _ in $(seq 1 90); do
  [ -z "$(dig_at "$NSB" "$B_IP" "$MC")" ] && break
  sleep 0.5
done
got=$(dig_at "$NSB" "$B_IP" "$MC")
[ -z "$got" ] && ok "B stops resolving mc once A withdraws it" \
  || bad "mc still resolves to '$got' after removal"

# The port went with the name — a service is its ports, so removing it closes them.
if "$ENG" -c "$TMP/a.toml" ctl exposes 2>&1 | grep -q "25565"; then
  bad "removing the service left its port open"
else
  ok "removing the service closed its port"
fi

# The coordinator was never involved: no service state, no service route.
if grep -qi "service" "$TMP/coord.log"; then
  bad "the coordinator logged something about services — it should hold none"
else
  ok "the coordinator holds no service state"
fi

[ "$fail" = 0 ] && { echo "RESULT: PASS ✓  names resolve peer-direct, scoped like their ports, and withdraw cleanly"; exit 0; }
echo "RESULT: FAIL ✗"; tail -n 20 "$TMP"/*.log; exit 1
