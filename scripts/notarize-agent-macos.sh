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

plist_value_optional() {
  local plist_path="$1"
  local key="$2"
  plutil -extract "$key" raw -o - "$plist_path" 2>/dev/null || true
}

system_extension_bundle_content_sha256() {
  local sysext_path="$1"
  python3 - "$sysext_path" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
digest = hashlib.sha256()
for path in sorted(candidate for candidate in root.rglob("*") if candidate.is_file()):
    relative = path.relative_to(root).as_posix().encode("utf-8")
    digest.update(relative)
    digest.update(b"\0")
    digest.update(hashlib.sha256(path.read_bytes()).hexdigest().encode("ascii"))
    digest.update(b"\0")
print(digest.hexdigest())
PY
}

validate_codesign_team_identifier() {
  local signed_path="$1"
  local expected_team_id="$2"
  local label="$3"
  local details_path="$4"
  local actual_team_id

  if [[ -z "$expected_team_id" ]]; then
    echo "[notarize] expected Apple team ID is required before validating ${label}" >&2
    exit 1
  fi

  if ! codesign -dv --verbose=4 "$signed_path" > "$details_path" 2>&1; then
    cat "$details_path" >&2
    echo "[notarize] failed to inspect ${label} code signature" >&2
    exit 1
  fi

  if grep -q '^Signature=adhoc$' "$details_path"; then
    echo "[notarize] ${label} must be signed with a Developer ID team identity, not an ad-hoc signature" \
      >&2
    exit 1
  fi

  actual_team_id="$(
    awk -F= '/^TeamIdentifier=/{
      value=$2
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      print value
      exit
    }' "$details_path"
  )"
  if [[ -z "$actual_team_id" ]]; then
    echo "[notarize] ${label} code signature is missing TeamIdentifier" >&2
    exit 1
  fi
  if [[ "$actual_team_id" != "$expected_team_id" ]]; then
    {
      echo "[notarize] ${label} TeamIdentifier does not match APPLE_TEAM_ID"
      echo "[notarize] expected: $expected_team_id"
      echo "[notarize] actual:   $actual_team_id"
    } >&2
    exit 1
  fi
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

validate_prebuilt_system_extension_bundle() {
  local sysext_path="$1"
  local out_dir="$2"
  local sysext_info="$sysext_path/Contents/Info.plist"
  local expected_system_extension_bundle_id
  local expected_system_extension_version
  local actual_system_extension_bundle_id
  local actual_system_extension_version
  local expected_system_extension_digest
  local actual_system_extension_digest
  local usage_description
  local executable
  local executable_path

  if [[ ! -d "$sysext_path" ]]; then
    echo "[notarize] CLAWDSTRIKE_SYSTEM_EXTENSION_BUNDLE_PATH must reference an existing .systemextension directory: $sysext_path" >&2
    exit 1
  fi
  if [[ "$sysext_path" != *.systemextension ]]; then
    echo "[notarize] CLAWDSTRIKE_SYSTEM_EXTENSION_BUNDLE_PATH must end in .systemextension: $sysext_path" >&2
    exit 1
  fi
  if [[ ! -f "$sysext_info" ]]; then
    echo "[notarize] prebuilt system extension is missing Contents/Info.plist: $sysext_path" >&2
    exit 1
  fi

  expected_system_extension_bundle_id="$(plist_value apps/agent/src-tauri/macos/system-extension/plists/combined-system-extension-template.plist CFBundleIdentifier)"
  expected_system_extension_version="$(plist_value apps/agent/src-tauri/macos/system-extension/plists/combined-system-extension-template.plist CFBundleVersion)"
  actual_system_extension_bundle_id="$(plist_value "$sysext_info" CFBundleIdentifier)"
  actual_system_extension_version="$(plist_value "$sysext_info" CFBundleVersion)"

  if [[ "$actual_system_extension_bundle_id" != "$expected_system_extension_bundle_id" ]]; then
    echo "[notarize] prebuilt system extension bundle identifier does not match packaging source metadata" >&2
    exit 1
  fi
  if [[ "$actual_system_extension_version" != "$expected_system_extension_version" ]]; then
    echo "[notarize] prebuilt system extension version does not match packaging source metadata" >&2
    exit 1
  fi

  usage_description="$(plist_value_optional "$sysext_info" NSSystemExtensionUsageDescription)"
  if [[ -z "$usage_description" ]]; then
    echo "[notarize] prebuilt system extension is missing NSSystemExtensionUsageDescription" >&2
    exit 1
  fi

  expected_system_extension_digest="${CLAWDSTRIKE_SYSTEM_EXTENSION_BUNDLE_SHA256:-}"
  expected_system_extension_digest="${expected_system_extension_digest#sha256:}"
  expected_system_extension_digest="$(printf '%s' "$expected_system_extension_digest" | tr '[:upper:]' '[:lower:]')"
  if ! [[ "$expected_system_extension_digest" =~ ^[0-9a-f]{64}$ ]]; then
    echo "[notarize] CLAWDSTRIKE_SYSTEM_EXTENSION_BUNDLE_SHA256 must be set to the expected content digest for the prebuilt .systemextension bundle" >&2
    exit 1
  fi
  actual_system_extension_digest="$(system_extension_bundle_content_sha256 "$sysext_path")"
  printf '%s\n' "$actual_system_extension_digest" > "$out_dir/prebuilt-system-extension-content-sha256.txt"
  if [[ "$actual_system_extension_digest" != "$expected_system_extension_digest" ]]; then
    {
      echo "[notarize] prebuilt system extension content digest mismatch"
      echo "[notarize] expected: $expected_system_extension_digest"
      echo "[notarize] actual:   $actual_system_extension_digest"
    } >&2
    exit 1
  fi

  executable="$(plist_value_optional "$sysext_info" CFBundleExecutable)"
  if [[ -z "$executable" ]]; then
    echo "[notarize] prebuilt system extension is missing CFBundleExecutable" >&2
    exit 1
  fi
  executable_path="$sysext_path/Contents/MacOS/$executable"
  if [[ ! -f "$executable_path" || ! -x "$executable_path" ]]; then
    echo "[notarize] prebuilt system extension executable is missing or not executable: $executable_path" >&2
    exit 1
  fi

  if ! codesign --verify --verbose=2 "$sysext_path" > "$out_dir/prebuilt-system-extension-codesign-verify.txt" 2>&1; then
    cat "$out_dir/prebuilt-system-extension-codesign-verify.txt" >&2
    echo "[notarize] prebuilt system extension must be signed before embedding" >&2
    exit 1
  fi
  validate_codesign_team_identifier \
    "$sysext_path" \
    "$TEAM_ID" \
    "prebuilt system extension" \
    "$out_dir/prebuilt-system-extension-codesign-details.txt"
}

embed_system_extension_bundle() {
  local app_path="$1"
  local source_sysext_path="$2"
  local system_extensions_dir="$app_path/Contents/Library/SystemExtensions"
  local embedded_path="$system_extensions_dir/$(basename "$source_sysext_path")"

  mkdir -p "$system_extensions_dir"
  rm -rf "$embedded_path"
  ditto "$source_sysext_path" "$embedded_path"
  echo "$embedded_path"
}

sign_embedded_app_bundle() {
  local app_path="$1"
  local sysext_path="$2"
  local signing_identity="$3"

  codesign \
    --force \
    --options runtime \
    --timestamp \
    --sign "$signing_identity" \
    --entitlements apps/agent/src-tauri/macos/system-extension/entitlements/combined-system-extension.entitlements \
    "$sysext_path"

  codesign \
    --force \
    --options runtime \
    --timestamp \
    --sign "$signing_identity" \
    --entitlements apps/agent/src-tauri/macos/system-extension/entitlements/agent-app.entitlements \
    "$app_path"
}

create_signed_dmg() {
  local app_path="$1"
  local out_dir="$2"
  local signing_identity="$3"
  local bundle_dir="apps/agent/src-tauri/target/release/bundle/dmg"
  local dmg_path="$bundle_dir/clawdstrike-agent-${TS}.dmg"

  mkdir -p "$bundle_dir"
  rm -f "$dmg_path"
  hdiutil create \
    -volname "ClawdStrike Agent" \
    -srcfolder "$app_path" \
    -ov \
    -format UDZO \
    "$dmg_path" > "$out_dir/hdiutil-create-dmg.txt"
  codesign --force --timestamp --sign "$signing_identity" "$dmg_path" > "$out_dir/codesign-dmg.txt" 2>&1
  echo "$dmg_path"
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

  if [[ -z "$(plist_value_optional "$sysext_info" NSSystemExtensionUsageDescription)" ]]; then
    echo "[notarize] embedded system extension is missing NSSystemExtensionUsageDescription" >&2
    exit 1
  fi

  codesign --verify --verbose=2 "$sysext_path" | tee "$out_dir/codesign-verify-system-extension.txt"
  validate_codesign_team_identifier \
    "$app_path" \
    "$TEAM_ID" \
    "signed app bundle" \
    "$out_dir/app-codesign-details.txt"
  validate_codesign_team_identifier \
    "$sysext_path" \
    "$TEAM_ID" \
    "embedded system extension" \
    "$out_dir/system-extension-codesign-details.txt"
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
require_cmd ditto
require_cmd hdiutil

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
SYSTEM_EXTENSION_BUNDLE_PATH="${CLAWDSTRIKE_SYSTEM_EXTENSION_BUNDLE_PATH:-}"

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

while [[ "$SYSTEM_EXTENSION_BUNDLE_PATH" == */ && "$SYSTEM_EXTENSION_BUNDLE_PATH" != "/" ]]; do
  SYSTEM_EXTENSION_BUNDLE_PATH="${SYSTEM_EXTENSION_BUNDLE_PATH%/}"
done
if [[ -n "$SYSTEM_EXTENSION_BUNDLE_PATH" && "$SYSTEM_EXTENSION_BUNDLE_PATH" != /* ]]; then
  SYSTEM_EXTENSION_BUNDLE_PATH="$(pwd)/$SYSTEM_EXTENSION_BUNDLE_PATH"
fi

if [[ -z "$SYSTEM_EXTENSION_BUNDLE_PATH" ]]; then
  echo "[notarize] CLAWDSTRIKE_SYSTEM_EXTENSION_BUNDLE_PATH is required and must point to a prebuilt signed .systemextension bundle" >&2
  exit 1
fi
validate_prebuilt_system_extension_bundle "$SYSTEM_EXTENSION_BUNDLE_PATH" "$OUT_DIR"

echo "[notarize] building signed app bundle"
pushd apps/agent/src-tauri >/dev/null
APPLE_SIGNING_IDENTITY="$SIGNING_IDENTITY" \
APPLE_TEAM_ID="$TEAM_ID" \
CLAWDSTRIKE_SYSTEM_EXTENSION_TEAM_ID="$TEAM_ID" \
CLAWDSTRIKE_REQUIRE_CONCRETE_MACOS_PACKAGING=1 \
CLAWDSTRIKE_SYSTEM_EXTENSION_BUNDLE_PATH="$SYSTEM_EXTENSION_BUNDLE_PATH" \
cargo tauri build --bundles app
popd >/dev/null

APP_PATH="$(ls -t apps/agent/src-tauri/target/release/bundle/macos/*.app | head -n 1)"

if [[ -z "$APP_PATH" ]]; then
  echo "[notarize] failed to locate built app artifact" >&2
  exit 1
fi

echo "[notarize] embedding prebuilt system extension"
EMBEDDED_SYSTEM_EXTENSION_PATH="$(embed_system_extension_bundle "$APP_PATH" "$SYSTEM_EXTENSION_BUNDLE_PATH")"

echo "[notarize] signing embedded system extension and host app"
sign_embedded_app_bundle "$APP_PATH" "$EMBEDDED_SYSTEM_EXTENSION_PATH" "$SIGNING_IDENTITY"

echo "[notarize] verify codesign"
codesign --verify --deep --strict --verbose=2 "$APP_PATH" | tee "$OUT_DIR/codesign-verify.txt"
codesign -dv --verbose=4 "$APP_PATH" 2>&1 | tee "$OUT_DIR/codesign-details.txt"
validate_embedded_system_extension "$APP_PATH" "$OUT_DIR"
if ! spctl -a -vv "$APP_PATH" 2>&1 | tee "$OUT_DIR/spctl-before.txt"; then
  echo "[notarize] pre-submit Gatekeeper assessment did not accept the unstapled app; continuing to notarization" >&2
fi

echo "[notarize] creating signed dmg"
DMG_PATH="$(create_signed_dmg "$APP_PATH" "$OUT_DIR" "$SIGNING_IDENTITY")"

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
