#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   TEAM_ID=ABCDE12345 \
#     render-mdm-profiles.sh \
#       --org-identifier ORG_ID \
#       --out-dir OUT_DIR \
#       [--team-id TEAM_ID] \
#       [--app-bundle-id APP_ID] \
#       [--extension-bundle-id EXT_ID]
#
# TEAM_ID MUST be supplied either via the TEAM_ID environment variable or the
# --team-id flag. There is no hard-coded default; the previous hard-coded value
# was tied to a single Apple Developer account and has been removed.
#
# APP_BUNDLE_ID defaults to dev.clawdstrike.agent.
# SYSTEM_EXTENSION_BUNDLE_ID defaults to dev.clawdstrike.agent.system-extension.

usage() {
  cat >&2 <<'USAGE'
Usage:
  TEAM_ID=ABCDE12345 render-mdm-profiles.sh \
    --org-identifier ORG_ID \
    --out-dir OUT_DIR \
    [--team-id TEAM_ID] \
    [--app-bundle-id APP_ID] \
    [--extension-bundle-id EXT_ID]

TEAM_ID is required (env var or --team-id flag); the Apple Developer Team ID
must be a 10-character uppercase alphanumeric string.

Defaults:
  APP_ID defaults to dev.clawdstrike.agent when --app-bundle-id is omitted.
  EXT_ID defaults to dev.clawdstrike.agent.system-extension when --extension-bundle-id is omitted.
USAGE
}

# Read TEAM_ID from environment if set, otherwise leave empty so that
# the --team-id flag or the required-check below can pick it up.
TEAM_ID="${TEAM_ID:-}"
APP_BUNDLE_ID="dev.clawdstrike.agent"
SYSTEM_EXTENSION_BUNDLE_ID="dev.clawdstrike.agent.system-extension"
ORG_IDENTIFIER=""
OUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --team-id)
      TEAM_ID="${2:-}"
      shift 2
      ;;
    --app-bundle-id)
      APP_BUNDLE_ID="${2:-}"
      shift 2
      ;;
    --extension-bundle-id)
      SYSTEM_EXTENSION_BUNDLE_ID="${2:-}"
      shift 2
      ;;
    --org-identifier)
      ORG_IDENTIFIER="${2:-}"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[mdm-profiles] unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$ORG_IDENTIFIER" || -z "$OUT_DIR" ]]; then
  echo "[mdm-profiles] --org-identifier and --out-dir are required" >&2
  usage
  exit 2
fi

if [[ -z "$TEAM_ID" ]]; then
  echo "[mdm-profiles] TEAM_ID is required (set TEAM_ID env var or pass --team-id)" >&2
  usage
  exit 2
fi

if [[ ! "$TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]; then
  echo "[mdm-profiles] invalid Team ID: $TEAM_ID" >&2
  exit 2
fi

if [[ ! "$APP_BUNDLE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
  echo "[mdm-profiles] invalid app bundle ID: $APP_BUNDLE_ID" >&2
  exit 2
fi

if [[ ! "$SYSTEM_EXTENSION_BUNDLE_ID" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
  echo "[mdm-profiles] invalid extension bundle ID: $SYSTEM_EXTENSION_BUNDLE_ID" >&2
  exit 2
fi

if [[ ! "$ORG_IDENTIFIER" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]]; then
  echo "[mdm-profiles] invalid organization identifier: $ORG_IDENTIFIER" >&2
  exit 2
fi

if ! command -v uuidgen >/dev/null 2>&1; then
  echo "[mdm-profiles] uuidgen is required" >&2
  exit 1
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUT_DIR"

sed_escape() {
  printf '%s' "$1" | sed -e 's/[\/&|]/\\&/g'
}

render_template() {
  local template="$1"
  local target="$2"
  local profile_uuid
  local payload_uuid
  local app_code_requirement
  local extension_code_requirement

  profile_uuid="$(uuidgen)"
  payload_uuid="$(uuidgen)"
  app_code_requirement="identifier \"${APP_BUNDLE_ID}\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = \"${TEAM_ID}\""
  extension_code_requirement="identifier \"${SYSTEM_EXTENSION_BUNDLE_ID}\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = \"${TEAM_ID}\""

  sed \
    -e "s|{{TEAM_ID}}|$(sed_escape "$TEAM_ID")|g" \
    -e "s|{{APP_BUNDLE_ID}}|$(sed_escape "$APP_BUNDLE_ID")|g" \
    -e "s|{{SYSTEM_EXTENSION_BUNDLE_ID}}|$(sed_escape "$SYSTEM_EXTENSION_BUNDLE_ID")|g" \
    -e "s|{{ORG_IDENTIFIER}}|$(sed_escape "$ORG_IDENTIFIER")|g" \
    -e "s|{{PROFILE_UUID}}|$(sed_escape "$profile_uuid")|g" \
    -e "s|{{PAYLOAD_UUID}}|$(sed_escape "$payload_uuid")|g" \
    -e "s|{{APP_CODE_REQUIREMENT}}|$(sed_escape "$app_code_requirement")|g" \
    -e "s|{{SYSTEM_EXTENSION_CODE_REQUIREMENT}}|$(sed_escape "$extension_code_requirement")|g" \
    "$template" > "$target"
}

render_template "$script_dir/system-extension-approval.mobileconfig.in" "$OUT_DIR/clawdstrike-system-extension-approval.mobileconfig"
render_template "$script_dir/full-disk-access.mobileconfig.in" "$OUT_DIR/clawdstrike-full-disk-access.mobileconfig"
render_template "$script_dir/network-content-filter.mobileconfig.in" "$OUT_DIR/clawdstrike-network-content-filter.mobileconfig"

# Render the developer-id-profile-template.plist (uses @@TEAM_ID@@ placeholder
# rather than the {{...}} convention used by the .mobileconfig.in templates).
if [[ -f "$script_dir/developer-id-profile-template.plist" ]]; then
  sed "s|@@TEAM_ID@@|$(sed_escape "$TEAM_ID")|g" \
    "$script_dir/developer-id-profile-template.plist" \
    > "$OUT_DIR/developer-id-profile.plist"
fi

if grep -R "{{" "$OUT_DIR" >/dev/null; then
  echo "[mdm-profiles] rendered profiles still contain template tokens" >&2
  exit 1
fi

if grep -R "@@TEAM_ID@@" "$OUT_DIR" >/dev/null; then
  echo "[mdm-profiles] rendered profiles still contain @@TEAM_ID@@ placeholder" >&2
  exit 1
fi

for profile in "$OUT_DIR"/*.mobileconfig; do
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$profile" >/dev/null
  elif command -v xmllint >/dev/null 2>&1; then
    xmllint --noout "$profile"
  fi
done

cat > "$OUT_DIR/manifest.txt" <<MANIFEST
team_id: $TEAM_ID
app_bundle_id: $APP_BUNDLE_ID
system_extension_bundle_id: $SYSTEM_EXTENSION_BUNDLE_ID
org_identifier: $ORG_IDENTIFIER
profiles:
  - clawdstrike-system-extension-approval.mobileconfig
  - clawdstrike-full-disk-access.mobileconfig
  - clawdstrike-network-content-filter.mobileconfig
MANIFEST

echo "[mdm-profiles] wrote profiles to $OUT_DIR"
