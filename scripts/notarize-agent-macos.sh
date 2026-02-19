#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[notarize] missing required command: $1" >&2
    exit 1
  fi
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "[notarize] this script must run on macOS" >&2
  exit 1
fi

require_cmd security
require_cmd codesign
require_cmd xcrun
require_cmd spctl
require_cmd cargo

TEAM_ID="${APPLE_TEAM_ID:-}"
SIGNING_IDENTITY="${APPLE_SIGNING_IDENTITY:-}"
NOTARY_PROFILE="${NOTARYTOOL_PROFILE:-}"
APPLE_ID="${APPLE_ID:-}"
APPLE_PASSWORD="${APPLE_PASSWORD:-}"

if [[ -z "$SIGNING_IDENTITY" ]]; then
  SIGNING_IDENTITY="$(security find-identity -v -p codesigning | awk -F'"' '/Developer ID Application/{print $2; exit}')"
fi

if [[ -z "$TEAM_ID" ]]; then
  echo "[notarize] APPLE_TEAM_ID is required" >&2
  exit 1
fi

if [[ -z "$SIGNING_IDENTITY" ]]; then
  echo "[notarize] no Developer ID Application signing identity found" >&2
  exit 1
fi

if [[ -z "$NOTARY_PROFILE" ]]; then
  if [[ -z "$APPLE_ID" || -z "$APPLE_PASSWORD" ]]; then
    echo "[notarize] set NOTARYTOOL_PROFILE or APPLE_ID + APPLE_PASSWORD" >&2
    exit 1
  fi
fi

TS="$(date -u +%Y%m%d-%H%M%S)"
OUT_DIR="docs/roadmaps/cua/research/artifacts/notarization-${TS}"
mkdir -p "$OUT_DIR"

echo "[notarize] building signed app+dmg"
pushd apps/agent/src-tauri >/dev/null
APPLE_SIGNING_IDENTITY="$SIGNING_IDENTITY" APPLE_TEAM_ID="$TEAM_ID" cargo tauri build --bundles app,dmg
popd >/dev/null

APP_PATH="$(ls -t apps/agent/src-tauri/target/release/bundle/macos/*.app | head -n 1)"
DMG_PATH="$(ls -t apps/agent/src-tauri/target/release/bundle/dmg/*.dmg | head -n 1)"

if [[ -z "$APP_PATH" || -z "$DMG_PATH" ]]; then
  echo "[notarize] failed to locate built app/dmg artifacts" >&2
  exit 1
fi

echo "[notarize] verify codesign"
codesign --verify --deep --strict --verbose=2 "$APP_PATH" | tee "$OUT_DIR/codesign-verify.txt"
codesign -dv --verbose=4 "$APP_PATH" 2>&1 | tee "$OUT_DIR/codesign-details.txt"
spctl -a -vv "$APP_PATH" 2>&1 | tee "$OUT_DIR/spctl-before.txt"

echo "[notarize] submitting dmg for notarization"
if [[ -n "$NOTARY_PROFILE" ]]; then
  xcrun notarytool submit "$DMG_PATH" --keychain-profile "$NOTARY_PROFILE" --wait | tee "$OUT_DIR/notary-submit.txt"
else
  xcrun notarytool submit "$DMG_PATH" --apple-id "$APPLE_ID" --password "$APPLE_PASSWORD" --team-id "$TEAM_ID" --wait | tee "$OUT_DIR/notary-submit.txt"
fi

echo "[notarize] stapling app and dmg"
xcrun stapler staple "$APP_PATH" | tee "$OUT_DIR/staple-app.txt"
xcrun stapler staple "$DMG_PATH" | tee "$OUT_DIR/staple-dmg.txt"
xcrun stapler validate "$APP_PATH" | tee "$OUT_DIR/staple-validate-app.txt"
xcrun stapler validate "$DMG_PATH" | tee "$OUT_DIR/staple-validate-dmg.txt"
spctl -a -vv "$APP_PATH" 2>&1 | tee "$OUT_DIR/spctl-after.txt"

cat > "$OUT_DIR/summary.txt" <<SUMMARY
timestamp_utc: ${TS}
app_path: ${APP_PATH}
dmg_path: ${DMG_PATH}
signing_identity: ${SIGNING_IDENTITY}
team_id: ${TEAM_ID}
notary_profile: ${NOTARY_PROFILE}
SUMMARY

echo "[notarize] done"
echo "[notarize] artifacts: $OUT_DIR"
