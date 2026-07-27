#!/usr/bin/env bash
# The certificate control path, end to end and offline: a device asks the coordinator to publish its
# ACME DNS-01 challenge, and a resolver reads it back out of the coordinator's authoritative zone.
#
# This is what a CA does when it validates an order. Mesh names resolve to CGNAT addresses no CA can
# reach, so HTTP-01 and TLS-ALPN-01 are impossible and DNS-01 is the only challenge left — which
# means this zone working is the whole feature working. The device's own ACME conversation with the
# CA is exercised too, when `pebble` is installed (see the last section).
#
# Also asserts the hardening the responder needs, since it answers unauthenticated, source-spoofable
# packets: no recursion, no ANY, no zone transfers, nothing outside its own zone.
#
# No WireGuard, no namespaces — HTTP, key files and DNS only.
#
# Usage:  cargo build && scripts/cert-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENG="${ENG:-$ROOT/target/debug/unitylan-engine}"
COORD="${COORD:-$ROOT/target/debug/unitylan-coordinator}"

# Re-exec under a user+net+mount namespace. Only the issuance leg needs it — a real daemon, and so a
# real WireGuard interface — but the whole script runs inside so the coordinator, pebble and the
# daemon share one loopback. No host root required.
if [ "${UNL_INNS:-}" != "1" ]; then
  [ -x "$ENG" ] && [ -x "$COORD" ] || { echo "build first: cargo build"; exit 1; }
  command -v dig >/dev/null || { echo "needs dig (bind-utils / dnsutils)"; exit 1; }
  exec unshare -Urnm --map-root-user env UNL_INNS=1 ENG="$ENG" COORD="$COORD" \
    PATH="$PATH" bash "${BASH_SOURCE[0]}"
fi

# ---------------- inside the user+net+mount namespace ----------------
TMP="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$TMP"' EXIT
mount -t tmpfs none /run 2>/dev/null || { echo "FAIL: mount /run"; exit 1; }
mkdir -p /run/wireguard
ip link set lo up

PORT=8089
DNS_PORT=15353
DOMAIN="mesh.example.com"
FAILED=0
SKIPPED_ACME=0
ok()   { echo "  ok: $1"; }
bad()  { echo "  FAIL: $1"; FAILED=1; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$3', got '$2')"; fi; }

# `max_certs_per_week = 3` so the budget guard is reachable without starving the legs before it: one
# manual publish, one real ACME order, one more manual — and the next must be refused rather than
# spending a budget the whole deployment shares. The budget leg runs last for that reason.
cat >"$TMP/coord.toml" <<EOF
bind = "127.0.0.1:$PORT"
database = "$TMP/coord.db"
[dns]
domain = "$DOMAIN"
bind = "127.0.0.1:$DNS_PORT"
max_certs_per_week = 3
[[fake.guild]]
id = 1
name = "Test"
[[fake.guild.member]]
user_id = 1
username = "nodea"
role_ids = [10]
[[network]]
guild_id = 1
role_id = 10
name = "mesh"
EOF

REDIR_PORT=8766
cat >"$TMP/a.toml" <<EOF
coordinator = "http://127.0.0.1:$PORT"
state_dir = "$TMP/a"
device_name = "host-a"
disable_new_networks = false
oauth_redirect = "http://127.0.0.1:$REDIR_PORT/callback"
EOF

"$COORD" "$TMP/coord.toml" >"$TMP/coord.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 0.25; done
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null || { echo "FAIL: coordinator did not start"; cat "$TMP/coord.log"; exit 1; }

echo "=== enrol a device (interactive login, real possession proof) ==="
"$ENG" -c "$TMP/a.toml" login >"$TMP/login.out" 2>&1 &
for _ in $(seq 1 40); do grep -q 'oauth2/authorize' "$TMP/login.out" 2>/dev/null && break; sleep 0.25; done
STATE=$(grep -oE 'state=[A-Za-z0-9]+' "$TMP/login.out" | head -1 | cut -d= -f2)
[ -n "$STATE" ] || { echo "FAIL: no authorize URL from login"; cat "$TMP/login.out"; exit 1; }
curl -sf "http://127.0.0.1:$REDIR_PORT/callback?state=$STATE&code=user:1" >/dev/null \
  || { echo "FAIL: loopback redirect rejected"; exit 1; }
for _ in $(seq 1 60); do grep -q 'Logged in' "$TMP/login.out" 2>/dev/null && break; sleep 0.5; done
for _ in $(seq 1 20); do [ -s "$TMP/a/token" ] && break; sleep 0.5; done
TOKEN=$(cat "$TMP/a/token" 2>/dev/null)
[ -n "$TOKEN" ] || { echo "FAIL: device never got a bearer token"; cat "$TMP/login.out"; exit 1; }
echo "  enrolled ✓"

# `<device>.<user>`, the stem the coordinator derives both challenge names from. The user label is
# allocated (not merely sanitised) so it is unique deployment-wide — see `Store::user_label`.
DEVICE_NAME="host-a.nodea"

echo "=== publish a challenge, then read it back as a CA would ==="
publish() {
  curl -s -o "$TMP/pub.out" -w '%{http_code}' -X POST "http://127.0.0.1:$PORT/acme-challenge" \
    -H 'content-type: application/json' \
    -d "{\"token\":\"$1\",\"device\":\"$2\",\"primary\":${3:-null}}"
}
CODE=$(publish "$TOKEN" "token-value-one" "\"alias-value-one\"")
check "POST /acme-challenge accepted" "$CODE" "200"
grep -q "_acme-challenge.$DEVICE_NAME.$DOMAIN" "$TMP/pub.out" \
  && ok "published the device's own name" || bad "device name missing: $(cat "$TMP/pub.out")"
# This device is the owner's only one, so it is primary and the bare `<user>` alias is published too.
grep -q "_acme-challenge.nodea.$DOMAIN" "$TMP/pub.out" \
  && ok "published the primary's bare alias" || bad "primary alias missing: $(cat "$TMP/pub.out")"

dig_() { dig @127.0.0.1 -p "$DNS_PORT" "$@" +time=2 +tries=1; }

TXT=$(dig_ +short TXT "_acme-challenge.$DEVICE_NAME.$DOMAIN" | tr -d '"')
check "TXT resolves to the published value" "$TXT" "token-value-one"
TXT=$(dig_ +short TXT "_acme-challenge.nodea.$DOMAIN" | tr -d '"')
check "the alias TXT resolves too" "$TXT" "alias-value-one"

# A resolver that gets a truncated UDP answer retries over TCP, so a UDP-only server silently fails.
TXT=$(dig_ +tcp +short TXT "_acme-challenge.$DEVICE_NAME.$DOMAIN" | tr -d '"')
check "the same answer over TCP" "$TXT" "token-value-one"

echo "=== the zone carries challenges and nothing else ==="
ST=$(dig_ TXT "_acme-challenge.nobody.$DOMAIN" | grep -oE 'status: [A-Z]+' | cut -d' ' -f2)
check "an unpublished name is NXDOMAIN" "$ST" "NXDOMAIN"
ST=$(dig_ A "$DOMAIN" | grep -oE 'status: [A-Z]+' | cut -d' ' -f2)
check "no A record at the apex (mesh addresses stay unpublished)" "$ST" "NOERROR"
[ "$(dig_ +short A "$DOMAIN" | wc -l)" = "0" ] \
  && ok "...and it really is empty" || bad "apex A returned data"
ST=$(dig_ SOA "$DOMAIN" | grep -oE 'status: [A-Z]+' | cut -d' ' -f2)
check "SOA answers at the apex (delegation needs it)" "$ST" "NOERROR"

echo "=== hardening: unauthenticated, spoofable input ==="
ST=$(dig_ A example.com | grep -oE 'status: [A-Z]+' | cut -d' ' -f2)
check "a name outside the zone is REFUSED, never answered" "$ST" "REFUSED"
ST=$(dig_ ANY "$DOMAIN" | grep -oE 'status: [A-Z]+' | cut -d' ' -f2)
check "ANY is refused (amplification lever)" "$ST" "REFUSED"
# dig reports a refused transfer as "Transfer failed." rather than a status line, so match on that
# and on no records having come back.
dig_ AXFR "$DOMAIN" 2>&1 | grep -q 'Transfer failed' \
  && ok "zone transfer is refused" || bad "zone transfer was not refused"
dig_ +noall +comment TXT "_acme-challenge.$DEVICE_NAME.$DOMAIN" | grep -q ' ra[;, ]' \
  && bad "offered recursion" || ok "never offers recursion (no ra flag)"

echo "=== a device cannot publish for a name it does not hold ==="
CODE=$(publish "not-a-real-token" "stolen-value")
check "an invalid device token is rejected" "$CODE" "401"

echo "=== full ACME issuance against a local CA ==="
# The legs above prove the coordinator's half. This proves the device's: a real ACME conversation,
# ending in a certificate on disk. It needs `pebble` (Let's Encrypt's test CA) because talking to the
# real one from a test would spend the weekly budget on every run. Grab the release binary:
#
#   curl -sL https://github.com/letsencrypt/pebble/releases/latest/download/pebble-linux-amd64.tar.gz \
#     | tar xz && install -m755 pebble-linux-amd64/linux/amd64/pebble ~/.local/bin/pebble
#
# Pebble is pointed at our zone with `-dnsserver`, so it resolves `_acme-challenge` from the
# coordinator exactly as Let's Encrypt would; the engine is pointed back at pebble with
# `[cert] acme_directory`, trusting its API certificate via `acme_root`.
if ! command -v pebble >/dev/null; then
  SKIPPED_ACME=1
  echo "  SKIPPED: pebble not installed — the ACME path is NOT covered by this run"
  echo "           install it to cover issuance end to end (see the comment above)"
else
  # Mint pebble's own API certificate here rather than reaching into its source tree: the release
  # tarball ships the binary alone, and `go install` likewise leaves no `test/certs` to point at.
  #
  # Two tiers, not one self-signed file: rustls rejects a CA certificate presented as a server leaf
  # (`CaUsedAsEndEntity`), so the root the engine trusts must be distinct from the leaf pebble serves.
  # This governs the TLS connection to the ACME directory only — it is not a CA for issuance.
  {
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
      -keyout "$TMP/ca-key.pem" -out "$TMP/ca.pem" -subj "/CN=pebble-test-ca" &&
    openssl req -newkey rsa:2048 -nodes -keyout "$TMP/pebble-key.pem" \
      -out "$TMP/pebble.csr" -subj "/CN=localhost" &&
    openssl x509 -req -in "$TMP/pebble.csr" -CA "$TMP/ca.pem" -CAkey "$TMP/ca-key.pem" \
      -CAcreateserial -days 1 -out "$TMP/pebble-cert.pem" \
      -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\n')
  } >/dev/null 2>&1 \
    || { bad "could not mint pebble's API certificate (needs openssl)"; SKIPPED_ACME=1; }
  cat >"$TMP/pebble.json" <<EOF
{ "pebble": {
    "listenAddress": "127.0.0.1:14000",
    "managementListenAddress": "127.0.0.1:15000",
    "certificate": "$TMP/pebble-cert.pem",
    "privateKey": "$TMP/pebble-key.pem",
    "httpPort": 5002, "tlsPort": 5001, "ocspResponderURL": "" } }
EOF
  # `-dnsserver` sends every validation query at the coordinator's zone. `NOSLEEP` drops pebble's
  # deliberate random validation delay, which exists to catch clients that assume it is instant —
  # we are not testing that here, and it would add tens of seconds per run.
  PEBBLE_VA_NOSLEEP=1 \
    pebble -config "$TMP/pebble.json" -dnsserver "127.0.0.1:$DNS_PORT" >"$TMP/pebble.log" 2>&1 &
  for _ in $(seq 1 40); do
    curl -sfk https://127.0.0.1:14000/dir >/dev/null 2>&1 && break; sleep 0.25
  done

  cat >>"$TMP/a.toml" <<EOF

[cert]
acme_directory = "https://127.0.0.1:14000/dir"
acme_root = "$TMP/ca.pem"
EOF
  # Issuance is reconciled by the *daemon*, so this leg needs one running — `login` above was a
  # one-shot and leaves no control socket behind.
  "$ENG" -c "$TMP/a.toml" run >"$TMP/engine.log" 2>&1 &
  for _ in $(seq 1 60); do [ -S "$TMP/a/control.sock" ] && break; sleep 0.5; done
  [ -S "$TMP/a/control.sock" ] || { bad "the daemon never opened its control socket"; tail -15 "$TMP/engine.log"; }

  # Expose a port and opt in — both gates the daemon requires before it will issue.
  "$ENG" -c "$TMP/a.toml" ctl expose 8443 >>"$TMP/ctl.log" 2>&1 \
    || bad "ctl expose failed: $(tail -2 "$TMP/ctl.log")"
  "$ENG" -c "$TMP/a.toml" ctl cert on >>"$TMP/ctl.log" 2>&1 \
    || bad "ctl cert on failed: $(tail -2 "$TMP/ctl.log")"
  for _ in $(seq 1 90); do [ -s "$TMP/a/certs/cert.pem" ] && break; sleep 1; done

  if [ -s "$TMP/a/certs/cert.pem" ] && [ -s "$TMP/a/certs/key.pem" ]; then
    ok "a certificate was issued and written"
    openssl x509 -in "$TMP/a/certs/cert.pem" -noout -text 2>/dev/null \
      | grep -q "$DEVICE_NAME.$DOMAIN" \
      && ok "it names this device" || bad "the certificate does not name $DEVICE_NAME.$DOMAIN"
    # The key is the one secret here. Only the last digit matters: any "other" bit set means every
    # local account can read it. 600 (default) and 640 (`[cert] group`) both pass; 644 must not.
    MODE=$(stat -c '%a' "$TMP/a/certs/key.pem")
    case "$MODE" in
      *0) ok "the private key is not world-readable (mode $MODE)" ;;
      *)  bad "the private key is mode $MODE — readable by every local account" ;;
    esac
  else
    bad "no certificate was issued"
    echo "--- engine ---"; grep -iE "cert|acme" "$TMP/engine.log" 2>/dev/null | tail -15
    echo "--- pebble ---"; tail -10 "$TMP/pebble.log" 2>/dev/null
  fi
fi

# Last, because it deliberately spends the deployment's remaining quota: anything ordering after it
# would be refused for the wrong reason.
echo "=== the weekly budget refuses rather than spending the last of it ==="
# Exhausting the CA's per-domain cap locks the deployment out for the rest of the week, which is
# worse than declining early — so the coordinator meters and says no.
# Drain rather than assume a count: how much budget is left here depends on whether the ACME leg
# above ran, and a hard-coded expectation would pass or fail for the wrong reason.
DRAINED=0
for i in $(seq 1 6); do
  CODE=$(publish "$TOKEN" "drain-value-$i")
  if [ "$CODE" = "429" ]; then DRAINED=1; break; fi
  [ "$CODE" = "200" ] || { bad "unexpected $CODE while draining the budget"; break; }
done
[ "$DRAINED" = "1" ] \
  && ok "orders are refused once the weekly budget is spent" \
  || bad "the budget never refused an order — the meter is not enforcing"

if [ "$FAILED" = "0" ]; then
  if [ "$SKIPPED_ACME" = "1" ]; then
    echo "RESULT: PASS ✓  coordinator half verified — ACME issuance SKIPPED (no pebble)"
  else
    echo "RESULT: PASS ✓  challenge published, served, zone hardened, budget enforced, certificate issued"
  fi
  exit 0
fi
echo "RESULT: FAIL ✗"; cat "$TMP/coord.log"; exit 1
