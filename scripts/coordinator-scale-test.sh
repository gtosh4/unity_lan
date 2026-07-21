#!/usr/bin/env bash
# Coordinator-only scaling probe derived from mesh-test.sh's fake Discord setup.
# Usage: cargo build -p unitylan-coordinator && scripts/coordinator-scale-test.sh [devices]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COORD="${COORD:-$ROOT/target/debug/unitylan-coordinator}"
N="${1:-250}"
PARK="${2:-}"
PORT="${PORT:-18080}"
TMP="$(mktemp -d)"
trap 'kill "${CPID:-}" 2>/dev/null || true; rm -rf "$TMP"' EXIT
trap 'echo "benchmark failed; coordinator log:" >&2; tail -40 "$TMP/coordinator.log" >&2 || true' ERR

CFG="$TMP/coordinator.toml"
{
  echo "bind = \"127.0.0.1:$PORT\""
  echo "database = \"$TMP/coordinator.db\""
  echo 'trusted_proxies = ["127.0.0.1/32"]'
  echo 'attestation_ttl_secs = 30'
  echo '[[fake.guild]]'
  echo 'id = 1'
  echo 'name = "Scale"'
  for ((i=1; i<=N; i++)); do
    echo '[[fake.guild.member]]'
    echo "user_id = $i"
    echo "nick = \"user-$i\""
    echo 'role_ids = [10]'
  done
  echo '[[network]]'
  echo 'guild_id = 1'
  echo 'role_id = 10'
  echo 'name = "mesh"'
  for ((i=1; i<=N; i++)); do
    echo '[[enroll]]'
    echo "key = \"key-$i\""
    echo "user_id = $i"
  done
} >"$CFG"

"$COORD" "$CFG" >"$TMP/coordinator.log" 2>&1 & CPID=$!
for _ in $(seq 1 80); do
  curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null

token=""
pubkey=""
for ((i=1; i<=N; i++)); do
  pubkey="$(jq -cn --argjson n "$i" '[range(0;32) | if . < 4 then (($n / pow(256;.)) | floor % 256) else 0 end]')"
  body="$(jq -cn --argjson pk "$pubkey" --arg key "key-$i" --arg name "host-$i" \
    '{wg_pubkey:$pk,enrollment_key:$key,device_name:$name,proto:5,proto_min:4}')"
  response="$(curl -sS --fail-with-body -H 'content-type: application/json' -H "x-forwarded-for: 198.18.$((i / 250)).$((i % 250 + 1))" -d "$body" "http://127.0.0.1:$PORT/register")"
  token="$(jq -r .device_token <<<"$response")"
  jq -cn --argjson pk "$pubkey" --arg tok "$token" --arg name "host-$i" \
    '{wg_pubkey:$pk,device_token:$tok,device_name:$name,proto:5,proto_min:4}' >"$TMP/request-$i.json"
done

rss_kib="$(awk '/VmRSS:/ {print $2}' "/proc/$CPID/status")"
body="$(jq -cn --argjson pk "$pubkey" --arg tok "$token" --arg name "host-$N" \
  '{wg_pubkey:$pk,device_token:$tok,device_name:$name,proto:5,proto_min:4}')"

times="$TMP/times"
size=0
for _ in $(seq 1 10); do
  result="$(curl -sS -o "$TMP/response" -w '%{time_total} %{size_download}' \
    -H 'content-type: application/json' -d "$body" "http://127.0.0.1:$PORT/register")"
  echo "${result%% *}" >>"$times"
  size="${result##* }"
done

awk -v n="$N" -v rss="$rss_kib" -v bytes="$size" '
  { a[NR]=$1; sum+=$1 }
  END {
    asort(a);
    printf "devices=%d rss_mib=%.1f response_kib=%.1f latency_mean_ms=%.1f latency_p50_ms=%.1f latency_p90_ms=%.1f\n", n, rss/1024, bytes/1024, sum/NR*1000, a[int((NR+1)*.5)]*1000, a[int((NR+1)*.9)]*1000
  }' "$times"

if [[ "$PARK" == "--park" ]]; then
  version="$(jq -r .version "$TMP/response")"
  for ((i=1; i<=N; i++)); do
    jq --argjson since "$version" '.since=$since' "$TMP/request-$i.json" >"$TMP/park-$i.json"
    curl -sS -o /dev/null -H 'content-type: application/json' \
      -H "x-forwarded-for: 198.18.$((i / 250)).$((i % 250 + 1))" \
      --data-binary "@$TMP/park-$i.json" "http://127.0.0.1:$PORT/register" &
    if ((i % 100 == 0)); then sleep 1; fi
  done
  sleep 2
  parked_rss_kib="$(awk '/VmRSS:/ {print $2}' "/proc/$CPID/status")"
  printf 'parked=%s parked_rss_mib=%.1f rss_per_park_kib=%.1f\n' "$N" \
    "$(awk -v r="$parked_rss_kib" 'BEGIN {print r/1024}')" \
    "$(awk -v a="$rss_kib" -v b="$parked_rss_kib" -v n="$N" 'BEGIN {print (b-a)/n}')"
fi
