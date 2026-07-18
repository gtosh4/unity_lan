#!/usr/bin/env bash
# Record the GUI demo GIF (+ stills) for the README.
#
# Runs the `fake-engine` example (canned mesh fixtures + a scripted UI tour — see
# crates/gui/examples/fake-engine.rs), which launches the GUI and drives it over the control
# socket: switch to Peers, open a peer menu, arm/cancel a block, back to Networks. A screencast of
# that window is captured and encoded to a small, looping GIF plus two stills.
#
# Capture uses GPU Screen Recorder (Flatpak) via the desktop screencast portal — the sandbox-
# friendly path on Wayland (KMS/monitor capture is blocked in the flatpak). The FIRST run pops a
# "Share your screen" dialog: pick the **UnityLAN** window. The choice is saved to a restore-token
# file, so later runs are non-interactive.
#
# Deps:  cargo, ffmpeg, and the flatpak com.dec05eba.gpu_screen_recorder
#        (flatpak install flathub com.dec05eba.gpu_screen_recorder)
# Usage: scripts/readme-demo.sh            # writes assets/demo.gif, assets/peers.png, assets/networks.png
#        SECS=30 FPS=15 WIDTH=400 scripts/readme-demo.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GSR_APP="com.dec05eba.gpu_screen_recorder"
GSR_COMM="gpu-screen-reco" # Linux truncates comm to 15 chars — pkill/pgrep match this, not the full name.
SOCK="$(mktemp -u /tmp/unitylan-demo.XXXXXX.sock)"
TOKEN="${XDG_CACHE_HOME:-$HOME/.cache}/unitylan-readme-demo.token" # persists so only the first run prompts
WORK="$(mktemp -d)"
OUT="$ROOT/assets"

SECS="${SECS:-31}"   # recording length; the scripted tour runs ~30s
FPS="${FPS:-15}"     # GIF frame rate
WIDTH="${WIDTH:-400}" # GIF width (height auto)

command -v ffmpeg >/dev/null || { echo "FAIL: ffmpeg not found"; exit 1; }
flatpak info "$GSR_APP" >/dev/null 2>&1 || {
  echo "FAIL: $GSR_APP not installed"
  echo "  flatpak install flathub $GSR_APP"
  exit 1
}

# Kill our procs + salvage the recording on any exit. INT the gsr child so it finalizes the file.
cleanup() {
  pkill -INT -x "$GSR_COMM" 2>/dev/null
  sleep 2
  killall fake-engine unitylan-gui 2>/dev/null
  rm -f "$SOCK"
  rm -rf "$WORK"
}
trap cleanup EXIT

echo "==> building GUI + fake-engine"
cargo build -q -p unitylan-gui --example fake-engine || exit 1
cargo build -q -p unitylan-gui || exit 1
FAKE="$ROOT/target/debug/examples/fake-engine"

echo "==> launching fake-engine + GUI"
"$FAKE" "$SOCK" >"$WORK/fake.log" 2>&1 &
# Wait for the GUI window to exist (the example spawns it) so the portal has something to capture.
for _ in $(seq 1 20); do
  pgrep -x unitylan-gui >/dev/null && break
  sleep 0.25
done
sleep 2

echo "==> recording ${SECS}s (first run: pick the UnityLAN window in the portal dialog)"
flatpak run --filesystem="$WORK" --filesystem="$(dirname "$TOKEN")" \
  --command=gpu-screen-recorder "$GSR_APP" \
  -w portal -restore-portal-session yes -portal-session-token-filepath "$TOKEN" \
  -cursor no -f 30 -o "$WORK/tour.mkv" >"$WORK/gsr.log" 2>&1 &
sleep "$SECS"

echo "==> stopping recording"
pkill -INT -n -x "$GSR_COMM" 2>/dev/null
for _ in $(seq 1 12); do
  pgrep -x "$GSR_COMM" >/dev/null || break
  sleep 0.5
done
[ -s "$WORK/tour.mkv" ] || { echo "FAIL: no recording (see $WORK/gsr.log)"; cat "$WORK/gsr.log"; exit 1; }

echo "==> encoding GIF + stills -> $OUT"
mkdir -p "$OUT"
VF="fps=$FPS,scale=$WIDTH:-1:flags=lanczos"
ffmpeg -y -v error -i "$WORK/tour.mkv" -vf "$VF,palettegen=max_colors=128" "$WORK/palette.png"
ffmpeg -y -v error -i "$WORK/tour.mkv" -i "$WORK/palette.png" \
  -lavfi "$VF[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3" "$OUT/demo.gif"
# Stills from stable tour marks (recording starts a couple seconds into the tour): a clean Peers
# list in the menu-closed window (tour ~18-22s), and Networks from the tour's end (it returns to
# the Networks tab at tour t=27 and dwells there — the initial Networks view is gone before the
# recording starts).
ffmpeg -y -v error -ss 17 -i "$WORK/tour.mkv" -frames:v 1 "$OUT/peers.png"
ffmpeg -y -v error -ss 26 -i "$WORK/tour.mkv" -frames:v 1 "$OUT/networks.png"

echo "==> done:"
ls -la "$OUT/demo.gif" "$OUT/peers.png" "$OUT/networks.png"
