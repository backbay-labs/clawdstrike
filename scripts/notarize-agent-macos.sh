#!/usr/bin/env bash
set -euo pipefail

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[notarize] missing required command: $1" >&2
    exit 1
  fi
}

plist_value() {
  local plist_path="$1"
  local key="$2"
  plutil -extract "$key" raw -o - "$plist_path"
}

validate_source_packaging_assets() {
  if grep -R -nE "__[A-Z0-9_]+__" apps/agent/src-tauri/macos/system-extension >/dev/null; then
    echo "[notarize] packaging assets still contain placeholders; concrete source metadata is required before notarization" >&2
    exit 1
  fi

  if grep -R -n "scaffold_only" apps/agent/src-tauri/macos/system-extension >/dev/null; then
    echo "[notarize] packaging assets still declare scaffold_only state; notarization requires concrete source metadata plus a real embedded system extension bundle" >&2
    exit 1
  fi
}

validate_embedded_system_extension() {
  local app_path="$1"
  local out_dir="$2"
  local app_info="$app_path/Contents/Info.plist"
  local system_extensions_dir="$app_path/Contents/Library/SystemExtensions"
  local sysext_path
  local sysext_info
  local expected_app_bundle_id
  local expected_system_extension_bundle_id
  local expected_system_extension_version

  if [[ ! -d "$system_extensions_dir" ]]; then
    echo "[notarize] built app bundle is missing Contents/Library/SystemExtensions" >&2
    exit 1
  fi

  sysext_path="$(find "$system_extensions_dir" -maxdepth 1 -type d -name '*.systemextension' | head -n 1)"
  if [[ -z "$sysext_path" ]]; then
    echo "[notarize] built app bundle is missing an embedded .systemextension" >&2
    exit 1
  fi

  sysext_info="$sysext_path/Contents/Info.plist"
  if [[ ! -f "$app_info" || ! -f "$sysext_info" ]]; then
    echo "[notarize] missing Info.plist in built app or embedded system extension" >&2
    exit 1
  fi

  expected_app_bundle_id="$(plist_value apps/agent/src-tauri/macos/system-extension/plists/agent-packaging-template.plist CFBundleIdentifier)"
  expected_system_extension_bundle_id="$(plist_value apps/agent/src-tauri/macos/system-extension/plists/combined-system-extension-template.plist CFBundleIdentifier)"
  expected_system_extension_version="$(plist_value apps/agent/src-tauri/macos/system-extension/plists/combined-system-extension-template.plist CFBundleVersion)"

  if [[ "$(plist_value "$app_info" CFBundleIdentifier)" != "$expected_app_bundle_id" ]]; then
    echo "[notarize] built app bundle identifier does not match packaging source metadata" >&2
    exit 1
  fi

  if [[ "$(plist_value "$sysext_info" CFBundleIdentifier)" != "$expected_system_extension_bundle_id" ]]; then
    echo "[notarize] embedded system extension bundle identifier does not match packaging source metadata" >&2
    exit 1
  fi

  if [[ "$(plist_value "$sysext_info" CFBundleVersion)" != "$expected_system_extension_version" ]]; then
    echo "[notarize] embedded system extension version does not match packaging source metadata" >&2
    exit 1
  fi

  codesign --verify --verbose=2 "$sysext_path" | tee "$out_dir/codesign-verify-system-extension.txt"
  codesign -d --entitlements :- "$app_path" > "$out_dir/app-entitlements.plist" 2>/dev/null
  codesign -d --entitlements :- "$sysext_path" > "$out_dir/system-extension-entitlements.plist" 2>/dev/null

  grep -q "com.apple.developer.system-extension.install" "$out_dir/app-entitlements.plist" || {
    echo "[notarize] app bundle is missing system-extension.install entitlement" >&2
    exit 1
  }
  grep -q "content-filter-provider-systemextension" "$out_dir/app-entitlements.plist" || {
    echo "[notarize] app bundle is missing NetworkExtension install entitlement" >&2
    exit 1
  }
  grep -q "com.apple.developer.endpoint-security.client" "$out_dir/system-extension-entitlements.plist" || {
    echo "[notarize] embedded system extension is missing EndpointSecurity entitlement" >&2
    exit 1
  }
  grep -q "content-filter-provider-systemextension" "$out_dir/system-extension-entitlements.plist" || {
    echo "[notarize] embedded system extension is missing NetworkExtension entitlement" >&2
    exit 1
  }

  echo "$sysext_path" > "$out_dir/system-extension-path.txt"
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "[notarize] this script must run on macOS" >&2
  exit 1
fi

require_cmd security
require_cmd codesign
require_cmd xcrun
require_cmd spctl
require_cmd plutil
require_cmd cargo

required_assets=(
  "apps/agent/src-tauri/macos/system-extension/entitlements/agent-app.entitlements"
  "apps/agent/src-tauri/macos/system-extension/entitlements/combined-system-extension.entitlements"
  "apps/agent/src-tauri/macos/system-extension/plists/agent-packaging-template.plist"
  "apps/agent/src-tauri/macos/system-extension/plists/combined-system-extension-template.plist"
  "apps/agent/src-tauri/macos/system-extension/profiles/developer-id-profile-template.plist"
)

for asset in "${required_assets[@]}"; do
  if [[ ! -f "$asset" ]]; then
    echo "[notarize] missing required packaging asset: $asset" >&2
    exit 1
  fi
done

validate_source_packaging_assets

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
OUT_DIR="${NOTARIZE_OUT_DIR:-${TMPDIR:-/tmp}/clawdstrike-notarization-${TS}}"
mkdir -p "$OUT_DIR"

echo "[notarize] building signed app+dmg"
pushd apps/agent/src-tauri >/dev/null
APPLE_SIGNING_IDENTITY="$SIGNING_IDENTITY" \
APPLE_TEAM_ID="$TEAM_ID" \
CLAWDSTRIKE_REQUIRE_CONCRETE_MACOS_PACKAGING=1 \
cargo tauri build --bundles app,dmg
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
validate_embedded_system_extension "$APP_PATH" "$OUT_DIR"
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
