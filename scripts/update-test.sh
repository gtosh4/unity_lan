#!/usr/bin/env bash
# End-to-end auto-update test: an old client updates to the tip of main over the real signed path.
#
# Proves the whole design-phase-3 chain on one node, offline: coordinator signs a release manifest
# under its guild anchor -> the (older) engine verifies it against the anchor it TOFU-pinned ->
# stages a strictly-newer, platform-matching artifact -> `ctl update` downloads it over HTTPS ->
# re-verifies the SHA-256 -> swaps the engine + bundled GUI on disk -> exits for the restart onto the
# new version. Only the network hop is simulated: a self-signed localhost HTTPS server stands in for
# the GitHub Release host (the update client trusts only compiled-in webpki roots, so the baseline
# engine is built with the default-off `test-insecure-tls` feature for this test alone).
#
# The "old" side is the tip's own code compiled with its version patched down to 0.0.1, so the gap is
# real to `is_newer` without needing to build an actual past release (whose immutable binary couldn't
# trust a local cert anyway). The "new" side is the tip built normally and packaged as the artifact.
#
# No host root: re-execs under `unshare -Urnm --map-root-user` for the WireGuard interface, exactly
# like mesh-test.sh. Needs `openssl` and `python3` for the self-signed HTTPS server.
#
# Usage:  scripts/update-test.sh          (builds what it needs; allow a few minutes on a cold cache)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ---------------- outer phase: build + package (unprivileged, no namespace) ----------------
if [ "${UNL_INNS:-}" != "1" ]; then
  command -v openssl >/dev/null || { echo "need openssl"; exit 1; }
  command -v python3 >/dev/null || { echo "need python3"; exit 1; }

  TIPVER="$(grep -m1 '^version' "$ROOT/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
  OLDVER="0.0.1"
  [ "$TIPVER" != "$OLDVER" ] || { echo "tip version is already $OLDVER; bump it"; exit 1; }
  WORK="$(mktemp -d)"        # under /tmp, so it survives the /run tmpfs remount inside the namespace
  echo "tip version = $TIPVER   baseline (fake-old) version = $OLDVER   work = $WORK"
  mkdir -p "$WORK/tip" "$WORK/baseline"

  # 1. The "new" release: tip engine + GUI, packaged the way the Linux artifact is (a .tar.gz the
  #    engine's apply_bytes recognises by gzip magic and unpacks by file name).
  echo "=== building tip (new) engine + gui ==="
  cargo build -p unitylan-engine -p unitylan-gui 2>&1 | tail -3 || { echo "FAIL: tip build"; exit 1; }
  cp "$ROOT/target/debug/unitylan-engine" "$ROOT/target/debug/unitylan-gui" "$WORK/tip/"
  tar czf "$WORK/artifact.tar.gz" -C "$WORK/tip" unitylan-engine unitylan-gui
  SHA="$(sha256sum "$WORK/artifact.tar.gz" | awk '{print $1}')"
  SIZE="$(stat -c%s "$WORK/artifact.tar.gz")"
  echo "artifact: $SIZE bytes  sha256=$SHA"

  # 2. The "old" client: same code, version patched down + the test-only insecure-TLS seam so it can
  #    fetch from the self-signed local host. Cargo.toml/Cargo.lock are restored right after.
  echo "=== building baseline (old) engine at $OLDVER with test-insecure-tls ==="
  cp "$ROOT/Cargo.toml" "$WORK/Cargo.toml.bak"; cp "$ROOT/Cargo.lock" "$WORK/Cargo.lock.bak"
  restore() { cp "$WORK/Cargo.toml.bak" "$ROOT/Cargo.toml"; cp "$WORK/Cargo.lock.bak" "$ROOT/Cargo.lock"; }
  sed -i -E "0,/^version = \"$TIPVER\"/s//version = \"$OLDVER\"/" "$ROOT/Cargo.toml"
  if ! cargo build --features test-insecure-tls -p unitylan-engine 2>&1 | tail -3; then
    restore; echo "FAIL: baseline build"; exit 1
  fi
  cp "$ROOT/target/debug/unitylan-engine" "$WORK/baseline/unitylan-engine"
  restore
  # A stub GUI beside the engine, so the bundle's replace_gui path has something to swap (and we can
  # assert it became the tip GUI). An update only ever *replaces* an installed GUI, never installs one.
  printf 'OLD-GUI-STUB' > "$WORK/baseline/unitylan-gui"

  # 3. Self-signed cert for the artifact host (CN/SAN = localhost + 127.0.0.1).
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 1 -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1" >/dev/null 2>&1 \
    || { echo "FAIL: cert gen"; exit 1; }

  export UNL_INNS=1 WORK TIPVER OLDVER SHA SIZE ROOT
  exec unshare -Urnm --map-root-user env \
    UNL_INNS=1 WORK="$WORK" TIPVER="$TIPVER" OLDVER="$OLDVER" SHA="$SHA" SIZE="$SIZE" ROOT="$ROOT" \
    bash "${BASH_SOURCE[0]}"
fi

# ---------------- inner phase: run (root inside the user+net+mount namespace) ----------------
COORD="$ROOT/target/debug/unitylan-coordinator"
ENG="$WORK/baseline/unitylan-engine"          # the running OLD engine (self-replaced on update)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
mount -t tmpfs none /run 2>/dev/null || { echo "FAIL: mount /run"; exit 1; }
mkdir -p /run/wireguard
ip link set lo up

[ -x "$COORD" ] || { echo "=== building coordinator ==="; (cd "$ROOT" && cargo build -p unitylan-coordinator 2>&1 | tail -3); }

# Artifact host: self-signed HTTPS, stands in for the GitHub Release download.
python3 - "$WORK" <<'PY' >"$WORK/https.log" 2>&1 &
import http.server, ssl, os, sys
os.chdir(sys.argv[1])
httpd = http.server.HTTPServer(("127.0.0.1", 8443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("cert.pem", "key.pem")
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY

# Coordinator with a [release] block pointing at the local artifact, plus fake-Discord membership so
# the device enrols, holds a role (=> a guild anchor exists to sign the manifest), and pins it.
cat >"$WORK/coord.toml" <<EOF
bind = "127.0.0.1:8080"
database = "$WORK/coord.db"
# Deliberately left at the default attestation TTL, so the long-poll hold is the full ~15 min.
# Membership never changes on this single node, so its first /refresh parks for that whole hold:
# the update below can therefore only be staged from the *register* response. That makes this a
# regression test for exactly that (an earlier version staged only on refresh, so a solo or idle
# device saw no update offer for half the attestation TTL).
[[fake.guild]]
id = 1
name = "Test"
[[fake.guild.member]]
user_id = 1
nick = "nodea"
role_ids = [10]
[[network]]
guild_id = 1
role_id = 10
name = "mesh"
[[enroll]]
key = "key-a"
user_id = 1
[[community]]
guild_id = 1
slug = "lan"

[release]
version = "$TIPVER"

[[release.artifact]]
platform = "linux-amd64"
url = "https://127.0.0.1:8443/artifact.tar.gz"
sha256 = "$SHA"
size = $SIZE
EOF

cat >"$WORK/eng.toml" <<EOF
coordinator = "http://127.0.0.1:8080"
allow_insecure_http = true
state_dir = "$WORK/baseline"
enrollment_key = "key-a"
device_name = "host-a"
disable_new_networks = false
iface = "unla"
listen_port = 51820
endpoint = "127.0.0.1:51820"
refresh_secs = 2
EOF

"$COORD" "$WORK/coord.toml" >"$WORK/coord.log" 2>&1 &
for _ in $(seq 1 40); do curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1 && break; sleep 0.25; done
curl -sf http://127.0.0.1:8080/healthz >/dev/null 2>&1 || { echo "FAIL: coordinator never came up"; cat "$WORK/coord.log"; exit 1; }

echo "=== baseline engine v$OLDVER running; waiting for it to stage the v$TIPVER update ==="
"$ENG" -c "$WORK/eng.toml" run >"$WORK/eng.log" 2>&1 &
ENG_PID=$!

# The engine pins the anchor on register, then each refresh verifies the manifest + stages it.
staged=""
for _ in $(seq 1 40); do
  kill -0 "$ENG_PID" 2>/dev/null || { echo "FAIL: engine exited early"; cat "$WORK/eng.log"; exit 1; }
  out="$("$ENG" -c "$WORK/eng.toml" ctl status 2>/dev/null)"
  if echo "$out" | grep -q "v$TIPVER available (staged"; then staged="1"; echo "$out" | grep "update:"; break; fi
  sleep 0.5
done
[ -n "$staged" ] || { echo "FAIL: update never staged"; echo "--- status ---"; "$ENG" -c "$WORK/eng.toml" ctl status; echo "--- eng.log ---"; tail -20 "$WORK/eng.log"; exit 1; }
echo "stage: baseline verified + staged the tip manifest against its pinned anchor ✓"

echo "=== applying the update (ctl update) ==="
"$ENG" -c "$WORK/eng.toml" ctl update || { echo "FAIL: ctl update rejected"; exit 1; }

# The daemon downloads over HTTPS, re-verifies the SHA-256, swaps the binary, and exit(0)s. Wait for
# the running exe on disk to have become the tip version.
swapped=""
for _ in $(seq 1 40); do
  ver="$("$ENG" --version 2>/dev/null | awk '{print $2}')"
  [ "$ver" = "$TIPVER" ] && { swapped="1"; break; }
  sleep 0.5
done
[ -n "$swapped" ] || { echo "FAIL: engine binary not swapped to v$TIPVER (still '$ver')"; echo "--- eng.log ---"; tail -25 "$WORK/eng.log"; echo "--- https.log ---"; tail -10 "$WORK/https.log"; exit 1; }
echo "swap: running engine binary is now v$TIPVER (was v$OLDVER) ✓"

# The bundle replaces the GUI in lockstep, so an old GUI never talks to a new daemon.
if cmp -s "$WORK/baseline/unitylan-gui" "$WORK/tip/unitylan-gui"; then
  echo "bundle: co-located GUI replaced with the tip GUI in lockstep ✓"
else
  echo "FAIL: bundled GUI was not swapped"; exit 1
fi

echo "RESULT: PASS ✓  old client -> coordinator manifest -> verify -> download -> SHA-256 -> swap engine+gui -> restart onto tip"
exit 0
