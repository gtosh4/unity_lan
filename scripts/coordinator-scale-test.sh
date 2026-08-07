#!/usr/bin/env bash
# Coordinator scaling probe: what a herd of devices costs, across both dimensions that scale it —
# devices *and* registered guilds.
#
# Runs against `examples/mock_discord.rs` rather than the config-seeded `[fake]` role source, because
# the per-guild member walk in `build_snapshot` is the thing most likely to bind first and a fake
# source answers it instantly and for free. The mock rate-limits and delays the way Discord does, so
# twilight's own ratelimiter does its real work. Set `LATENCY_MS=0 GLOBAL_RPS=100000` to get the old
# free-and-instant behaviour back for an isolated look at snapshot cost.
#
# Usage: cargo build -p unitylan-coordinator --example mock_discord &&
#          cargo build -p unitylan-coordinator &&
#          scripts/coordinator-scale-test.sh [devices] [guilds] [--park]
#
# Env: GLOBAL_RPS PER_GUILD_RPS LATENCY_MS JITTER_MS  (the mock's limits, all per Discord's shape)
#
# Each device belongs to exactly one guild (`user_id % guilds + 1`), but every registered network is
# walked on every snapshot, so the walk costs `guilds` lookups per device regardless. Devices enrol
# once (sequentially — that's setup), then all refresh at once: the herd a version bump produces, and
# the case that decides whether a busy weekend degrades or falls over.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COORD="${COORD:-$ROOT/target/debug/unitylan-coordinator}"
MOCK="${MOCK:-$ROOT/target/debug/examples/mock_discord}"
N="${1:-250}"
G="${2:-1}"
PARK="${3:-}"
PORT="${PORT:-18080}"
MOCK_PORT="${MOCK_PORT:-18081}"
TMP="$(mktemp -d)"

cleanup() {
  for pid in "${CPID:-}" "${MPID:-}"; do
    [[ -n "$pid" ]] || continue
    kill "$pid" 2>/dev/null || true
  done
  sleep 0.5
  for pid in "${CPID:-}" "${MPID:-}"; do
    [[ -n "$pid" ]] || continue
    kill -9 "$pid" 2>/dev/null || true
  done
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'echo "benchmark failed; coordinator log:" >&2; tail -30 "$TMP/coordinator.log" >&2 || true' ERR

[[ -x "$COORD" ]] || { echo "missing $COORD — cargo build -p unitylan-coordinator" >&2; exit 1; }
[[ -x "$MOCK" ]] || { echo "missing $MOCK — cargo build -p unitylan-coordinator --example mock_discord" >&2; exit 1; }

GUILDS="$G" PORT="$MOCK_PORT" \
  GLOBAL_RPS="${GLOBAL_RPS:-50}" PER_GUILD_RPS="${PER_GUILD_RPS:-10}" \
  LATENCY_MS="${LATENCY_MS:-40}" JITTER_MS="${JITTER_MS:-20}" \
  "$MOCK" >"$TMP/mock.log" 2>&1 & MPID=$!
for _ in $(seq 1 60); do
  curl -sf "http://127.0.0.1:$MOCK_PORT/healthz" >/dev/null && break
  sleep 0.1
done
curl -sf "http://127.0.0.1:$MOCK_PORT/healthz" >/dev/null

CFG="$TMP/coordinator.toml"
{
  echo "bind = \"127.0.0.1:$PORT\""
  echo "database = \"$TMP/coordinator.db\""
  echo 'trusted_proxies = ["127.0.0.1/32"]'
  # `MIN_ATTESTATION_TTL_SECS` is the floor the coordinator's config validation enforces; below it
  # the process refuses to start.
  echo 'attestation_ttl_secs = 60'
  # Synthetic devices hold no WG private key, so they cannot build the DH possession proof an
  # enrolling register requires by default. Observe-only is the harness's business, not a statement
  # about deployments.
  echo '[enrollment]'
  echo 'require_proof = false'
  echo '[discord]'
  echo 'bot_token = "mock-token"'
  echo "api_proxy = \"http://127.0.0.1:$MOCK_PORT\""
  # One network per guild — every one of them is walked for every device.
  for ((g=1; g<=G; g++)); do
    echo '[[network]]'
    echo "guild_id = $g"
    echo 'role_id = 10'
    echo "name = \"mesh-$g\""
  done
  for ((i=1; i<=N; i++)); do
    echo '[[enroll]]'
    echo "key = \"key-$i\""
    echo "user_id = $i"
  done
} >"$CFG"

"$COORD" "$CFG" >"$TMP/coordinator.log" 2>&1 & CPID=$!
# The coordinator warms a per-guild Discord cache before it binds, so startup itself scales with
# guild count against a rate-limited API — reported below, because a restart is a real outage.
warm_start="$(date +%s.%N)"
for _ in $(seq 1 1800); do
  curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break
  sleep 0.2
done
warm_secs="$(awk -v a="$warm_start" -v b="$(date +%s.%N)" 'BEGIN {printf "%.1f", b-a}')"
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null

# Enrol every device once, sequentially: setup, not measurement.
token=""
pubkey=""
for ((i=1; i<=N; i++)); do
  pubkey="$(jq -cn --argjson n "$i" '[range(0;32) | if . < 4 then (($n / pow(256;.)) | floor % 256) else 0 end]')"
  body="$(jq -cn --argjson pk "$pubkey" --arg key "key-$i" --arg name "host-$i" \
    '{wg_pubkey:$pk,enrollment_key:$key,device_name:$name,proto:5,proto_min:4}')"
  response="$(curl -sS --fail-with-body -H 'content-type: application/json' \
    -H "x-forwarded-for: 198.18.$((i / 250)).$((i % 250 + 1))" -d "$body" "http://127.0.0.1:$PORT/register")"
  token="$(jq -r .device_token <<<"$response")"
  jq -cn --argjson pk "$pubkey" --arg tok "$token" --arg name "host-$i" \
    '{wg_pubkey:$pk,device_token:$tok,device_name:$name,proto:5,proto_min:4}' >"$TMP/request-$i.json"
done

rss_kib="$(awk '/VmRSS:/ {print $2}' "/proc/$CPID/status")"

# Let `MEMBER_TTL` (30s, `discord.rs`) lapse before measuring. Enrolment has just fetched every
# member, and a wave fired straight after would read that cache and report a Discord cost of zero —
# which is true only for a herd that arrives within 30s of the last one. The case that matters is the
# renewal herd at `LONGPOLL_HOLD_SECS` (15 min), where every entry is long expired.
sleep "${MEMBER_TTL_WAIT:-31}"

before="$(curl -sf "http://127.0.0.1:$MOCK_PORT/stats")"

# The measurement: every device refreshes at once, as they do on a version bump.
start="$(date +%s.%N)"
wave=()
for ((i=1; i<=N; i++)); do
  curl -sS -o "$TMP/response-$i" -w '%{time_total} %{size_download}\n' -H 'content-type: application/json' \
    -H "x-forwarded-for: 198.18.$((i / 250)).$((i % 250 + 1))" \
    --data-binary "@$TMP/request-$i.json" "http://127.0.0.1:$PORT/register" >>"$TMP/times" &
  wave+=($!)
done
# Only the wave — a bare `wait` would also wait on the coordinator and the mock, which never exit.
wait "${wave[@]}"
wall="$(awk -v a="$start" -v b="$(date +%s.%N)" 'BEGIN {print b-a}')"

after="$(curl -sf "http://127.0.0.1:$MOCK_PORT/stats")"
wave_calls=$(( $(jq -r .member_calls <<<"$after") - $(jq -r .member_calls <<<"$before") ))
wave_limited=$(( $(jq -r .rate_limited <<<"$after") - $(jq -r .rate_limited <<<"$before") ))

awk -v n="$N" -v g="$G" -v rss="$rss_kib" -v wall="$wall" '
  { a[NR]=$1; sum+=$1; bytes=$2 }
  END {
    asort(a);
    printf "devices=%d guilds=%d wave_secs=%.1f rss_mib=%.1f response_kib=%.1f latency_mean_ms=%.0f p50_ms=%.0f p90_ms=%.0f p99_ms=%.0f\n",
      n, g, wall, rss/1024, bytes/1024, sum/NR*1000, a[int((NR+1)*.5)]*1000, a[int((NR+1)*.9)]*1000, a[int(NR*.99)]*1000
  }' "$TMP/times"

printf 'startup_warm_secs=%s member_calls_in_wave=%d calls_per_device=%.1f rate_limited=%d peak_rps=%d\n' \
  "$warm_secs" "$wave_calls" \
  "$(awk -v c="$wave_calls" -v n="$N" 'BEGIN {print c/n}')" \
  "$wave_limited" "$(jq -r .peak_rps <<<"$after")"

if [[ "$PARK" == "--park" ]]; then
  version="$(jq -r .version "$TMP/response-1")"
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
