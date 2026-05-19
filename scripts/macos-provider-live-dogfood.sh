#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
preflight_only="${CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_PREFLIGHT_ONLY:-0}"
self_test=0
case "${1:-}" in
  --preflight)
    preflight_only=1
    shift
    ;;
  --self-test)
    self_test=1
    shift
    ;;
esac
target_input="${1:-${CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_TARGET:-}}"
run_id="$(date -u '+%Y%m%dT%H%M%SZ')"
run_root="${CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_OUTPUT_DIR:-$repo_root/output/dogfood/macos-provider-live/$run_id}"
replace_output="${CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_REPLACE_OUTPUT:-0}"
max_run_skew_seconds="${CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_MAX_RUN_SKEW_SECONDS:-3600}"
host_id="${CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_HOST_ID:-$(hostname -s 2>/dev/null || hostname)}"
user_id="${CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_USER_ID:-${USER:-operator}}"
provider_bundle_path="${CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH:-}"
team_id="${CLAWDSTRIKE_MACOS_PROVIDER_TEAM_ID:-JB6682CJY9}"
app_bundle_id="${CLAWDSTRIKE_MACOS_PROVIDER_APP_BUNDLE_ID:-dev.clawdstrike.agent}"
system_extension_bundle_id="${CLAWDSTRIKE_MACOS_PROVIDER_SYSTEM_EXTENSION_BUNDLE_ID:-dev.clawdstrike.agent.system-extension}"

log() {
  printf '[macos-provider-dogfood] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

require_readable_file() {
  [[ -r "$1" && -f "$1" ]] || die "required file is not readable: $1"
}

require_executable_file() {
  [[ -x "$1" && -f "$1" ]] || die "required file is not executable: $1"
}

require_run_id() {
  local name="$1"
  local value="$2"
  [[ "$value" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || die "$name must use YYYYMMDDTHHMMSSZ, got: $value"
}

is_enabled() {
  case "$1" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    0|false|FALSE|no|NO|off|OFF|"") return 1 ;;
    *) die "boolean flag must be one of 1/0/true/false/yes/no/on/off, got: $1" ;;
  esac
}

validate_target() {
  local target="$1"
  python3 - "$target" <<'PY' >/dev/null || die "invalid target: $target"
import re
import sys

target = sys.argv[1].strip()
if target.startswith("["):
    end = target.find("]")
    if end == -1 or len(target) <= end + 2 or target[end + 1] != ":":
        raise SystemExit("bracketed IPv6 targets must use [addr]:port")
    host = target[1:end]
    port = target[end + 2:]
else:
    if ":" not in target:
        raise SystemExit("target must be HOST:PORT")
    host, port = target.rsplit(":", 1)
host = host.strip()
if not host:
    raise SystemExit("target host must not be empty")
try:
    port_int = int(port)
except ValueError as exc:
    raise SystemExit("target port must be an integer") from exc
if port_int < 1 or port_int > 65535:
    raise SystemExit("target port must be between 1 and 65535")
if host.lower() == "localhost" or host in {"127.0.0.1", "::1", "0.0.0.0"}:
    raise SystemExit("refusing loopback/local target; use an external test host")
if re.search(r"\s", host):
    raise SystemExit("target host must not contain whitespace")
PY
}

validate_run_root() {
  local replace_enabled=0
  if is_enabled "$replace_output"; then
    replace_enabled=1
  fi
  python3 - "$run_root" "$repo_root" "$replace_enabled" <<'PY' || die "invalid output root: $run_root"
import os
import pathlib
import sys

run_root = pathlib.Path(sys.argv[1]).expanduser().resolve()
repo_root = pathlib.Path(sys.argv[2]).expanduser().resolve()
replace_enabled = sys.argv[3] == "1"
protected = {
    pathlib.Path(run_root.anchor).resolve(),
    pathlib.Path.home().resolve(),
    repo_root,
    repo_root / "scripts",
}
if run_root in protected:
    raise SystemExit(f"refusing protected output root: {run_root}")
if run_root.exists() and not run_root.is_dir():
    raise SystemExit(f"output root exists but is not a directory: {run_root}")
parent = run_root.parent
while not parent.exists() and parent != parent.parent:
    parent = parent.parent
if not parent.is_dir():
    raise SystemExit(f"output root parent exists but is not a directory: {parent}")
if not os.access(parent, os.W_OK):
    raise SystemExit(f"output root parent is not writable: {parent}")
if run_root.exists() and any(run_root.iterdir()) and not replace_enabled:
    raise SystemExit("output root must be empty or set CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_REPLACE_OUTPUT=1")
PY
}

prepare_run_root() {
  validate_run_root
  local replace_enabled=0
  if is_enabled "$replace_output"; then
    replace_enabled=1
  fi
  if [[ "$replace_enabled" == "1" ]]; then
    python3 - "$run_root" "$repo_root" <<'PY' || die "failed to replace output root: $run_root"
import pathlib
import shutil
import sys

run_root = pathlib.Path(sys.argv[1]).expanduser().resolve()
repo_root = pathlib.Path(sys.argv[2]).expanduser().resolve()
protected = {
    pathlib.Path(run_root.anchor).resolve(),
    pathlib.Path.home().resolve(),
    repo_root,
    repo_root / "scripts",
}
if run_root in protected:
    raise SystemExit(f"refusing protected output root: {run_root}")
if run_root.exists():
    if not run_root.is_dir():
        raise SystemExit(f"output root exists but is not a directory: {run_root}")
    for child in run_root.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()
PY
  fi
  mkdir -p "$run_root"
}

run_self_test() {
  require_cmd mktemp
  require_cmd mkdir
  require_cmd rm

  local temp_dir
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/clawdstrike-macos-provider-live.XXXXXX")"
  local bundle_path="$temp_dir/ClawdStrike.app"
  local output_dir="$temp_dir/output"
  local script_path="$repo_root/scripts/macos-provider-live-dogfood.sh"

  mkdir -p "$bundle_path"

  if ! CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path/" \
    CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_OUTPUT_DIR="$output_dir" \
    "$script_path" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected argv preflight with trailing slash bundle path to pass"
  fi

  if [[ -e "$output_dir" ]]; then
    rm -rf "$temp_dir"
    die "self-test expected preflight not to create the output directory"
  fi

  if ! CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_OUTPUT_DIR="$output_dir" \
    CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_PREFLIGHT_ONLY=yes \
    "$script_path" example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected env preflight to pass"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$temp_dir/Missing.app" \
    "$script_path" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected missing bundle path to fail"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    "$script_path" --preflight localhost:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected loopback target to fail"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_MAX_RUN_SKEW_SECONDS=invalid \
    "$script_path" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected invalid skew setting to fail"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_PREFLIGHT_ONLY=maybe \
    "$script_path" example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected invalid preflight flag to fail"
  fi

  local stale_output="$temp_dir/stale-output"
  mkdir -p "$stale_output"
  : >"$stale_output/old-manifest.json"
  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_OUTPUT_DIR="$stale_output" \
    "$script_path" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected non-empty output root to fail without replace opt-in"
  fi

  if ! CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_OUTPUT_DIR="$stale_output" \
    CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_REPLACE_OUTPUT=1 \
    "$script_path" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected replace-output preflight to accept non-empty output root"
  fi
  if [[ ! -f "$stale_output/old-manifest.json" ]]; then
    rm -rf "$temp_dir"
    die "self-test expected replace-output preflight not to delete stale output"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_REPLACE_OUTPUT=maybe \
    "$script_path" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected invalid replace-output flag to fail"
  fi

  run_root="$stale_output"
  replace_output=1
  prepare_run_root
  if [[ -e "$stale_output/old-manifest.json" ]]; then
    rm -rf "$temp_dir"
    die "self-test expected runtime replace-output to clear stale output files"
  fi
  if [[ ! -d "$stale_output" ]]; then
    rm -rf "$temp_dir"
    die "self-test expected runtime replace-output to recreate output root"
  fi

  rm -rf "$temp_dir"
  log "self-test passed"
}

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/macos-provider-live-dogfood.sh HOST:PORT
  scripts/macos-provider-live-dogfood.sh --preflight HOST:PORT
  scripts/macos-provider-live-dogfood.sh --self-test

Environment:
  CLAWDSTRIKE_AGENT_URL                                  default: http://127.0.0.1:9878
  CLAWDSTRIKE_AGENT_TOKEN                                bearer token; otherwise child scripts read token file
  CLAWDSTRIKE_AGENT_TOKEN_FILE                           token file for child scripts
  CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_TARGET              HOST:PORT when not passed as argv
  CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_PREFLIGHT_ONLY      1/true/yes/on exits after input/tool checks
  CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_OUTPUT_DIR          output root for the combined run
  CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_REPLACE_OUTPUT      1/true/yes/on permits replacing non-empty output root
  CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_MAX_RUN_SKEW_SECONDS default: 3600
  CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_HOST_ID             shared host ID for ES/NE summaries
  CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_USER_ID             shared user ID for ES/NE summaries
  CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH                 required signed/notarized .app bundle path
  CLAWDSTRIKE_MACOS_PROVIDER_TEAM_ID                     default: JB6682CJY9
  CLAWDSTRIKE_MACOS_PROVIDER_APP_BUNDLE_ID               default: dev.clawdstrike.agent
  CLAWDSTRIKE_MACOS_PROVIDER_SYSTEM_EXTENSION_BUNDLE_ID  default: dev.clawdstrike.agent.system-extension

This is the one-command deployed macOS provider gate. It runs the
signed/notarized deployment evidence check, EndpointSecurity live delivery
dogfood, and NetworkExtension live containment dogfood against HOST:PORT, then
verifies all summaries with scripts/macos-provider-dogfood-gate.py. It passes a
single run ID through deployment, EndpointSecurity, NetworkExtension, gate, and
manifest artifacts. A passing gate result is written to gate-result.json under
the output root, and manifest.json is verified by rehashing every bundled
artifact, checking the saved gate-result bindings, and rerunning the combined
gate before the script reports success.

Use --preflight or CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_PREFLIGHT_ONLY=1 to
validate required commands, child tools, run ID shape, bundle path, target
syntax, and numeric inputs without collecting deployment evidence or running
EndpointSecurity/NetworkExtension dogfood.

Use --self-test to regression-check the preflight-only path without running
deployment evidence collection or live EndpointSecurity/NetworkExtension flows.
USAGE
}

if [[ "$self_test" == "1" ]]; then
  run_self_test
  exit 0
fi

if [[ "$target_input" == "-h" || "$target_input" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$target_input" ]]; then
  usage
  exit 2
fi

require_cmd date
require_cmd hostname
require_cmd mkdir
require_cmd python3

require_readable_file "$repo_root/scripts/macos-provider-deployment-evidence.py"
require_executable_file "$repo_root/scripts/endpoint-security-live-dogfood.sh"
require_executable_file "$repo_root/scripts/network-extension-live-dogfood.sh"
require_readable_file "$repo_root/scripts/macos-provider-dogfood-gate.py"
require_readable_file "$repo_root/scripts/macos-provider-dogfood-manifest.py"
require_run_id "generated run ID" "$run_id"
validate_run_root

if [[ ! "$max_run_skew_seconds" =~ ^[0-9]+$ ]]; then
  die "CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_MAX_RUN_SKEW_SECONDS must be a non-negative integer"
fi

if [[ -z "$provider_bundle_path" ]]; then
  die "CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH is required to prove signing/notarization/deployment"
fi

while [[ "$provider_bundle_path" == */ && "$provider_bundle_path" != "/" ]]; do
  provider_bundle_path="${provider_bundle_path%/}"
done

if [[ "$provider_bundle_path" != *.app ]]; then
  die "CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH must point to a .app bundle"
fi

if [[ ! -d "$provider_bundle_path" ]]; then
  die "CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH must reference an existing .app directory: $provider_bundle_path"
fi

validate_target "$target_input"

if is_enabled "$preflight_only"; then
  log "Preflight passed"
  log "Target: $target_input"
  log "Bundle: $provider_bundle_path"
  log "Output root that would be used: $run_root"
  exit 0
fi

deployment_output_dir="$run_root/deployment-evidence"
es_output_dir="$run_root/endpoint-security"
ne_output_dir="$run_root/network-extension"
deployment_summary="$deployment_output_dir/summary.json"
gate_result="$run_root/gate-result.json"
manifest_file="$run_root/manifest.json"

prepare_run_root

log "Output root: $run_root"
log "Collecting signed/notarized deployment evidence"
python3 "$repo_root/scripts/macos-provider-deployment-evidence.py" \
  --collect \
  --output-dir "$deployment_output_dir" \
  --run-id "$run_id" \
  --host-id "$host_id" \
  --user-id "$user_id" \
  --bundle-path "$provider_bundle_path" \
  --team-id "$team_id" \
  --app-bundle-id "$app_bundle_id" \
  --system-extension-bundle-id "$system_extension_bundle_id" \
  >/dev/null

log "Running EndpointSecurity live dogfood"
CLAWDSTRIKE_ES_DOGFOOD_OUTPUT_DIR="$es_output_dir" \
CLAWDSTRIKE_ES_DOGFOOD_RUN_ID="$run_id" \
CLAWDSTRIKE_ES_DOGFOOD_HOST_ID="$host_id" \
CLAWDSTRIKE_ES_DOGFOOD_USER_ID="$user_id" \
  "$repo_root/scripts/endpoint-security-live-dogfood.sh"

log "Running NetworkExtension live dogfood against $target_input"
CLAWDSTRIKE_NE_DOGFOOD_OUTPUT_DIR="$ne_output_dir" \
CLAWDSTRIKE_NE_DOGFOOD_RUN_ID="$run_id" \
CLAWDSTRIKE_NE_DOGFOOD_HOST_ID="$host_id" \
CLAWDSTRIKE_NE_DOGFOOD_USER_ID="$user_id" \
  "$repo_root/scripts/network-extension-live-dogfood.sh" "$target_input"

es_summary="$es_output_dir/summary.json"
ne_summary="$ne_output_dir/summary.json"

log "Running combined macOS provider gate"
python3 "$repo_root/scripts/macos-provider-dogfood-gate.py" \
  --deployment-evidence-summary "$deployment_summary" \
  --endpoint-security-summary "$es_summary" \
  --network-extension-summary "$ne_summary" \
  --max-run-skew-seconds "$max_run_skew_seconds" \
  >"$gate_result"

python3 "$repo_root/scripts/macos-provider-dogfood-manifest.py" \
  --manifest "$manifest_file" \
  --evidence-mode live \
  --run-id "$run_id" \
  --run-root "$run_root" \
  --target "$target_input" \
  --host-id "$host_id" \
  --user-id "$user_id" \
  --deployment-evidence-summary "$deployment_summary" \
  --endpoint-security-summary "$es_summary" \
  --network-extension-summary "$ne_summary" \
  --gate-result "$gate_result" \
  --max-run-skew-seconds "$max_run_skew_seconds"

python3 "$repo_root/scripts/macos-provider-dogfood-manifest.py" \
  --verify \
  --manifest "$manifest_file" \
  >/dev/null

log "macOS provider live dogfood passed"
log "Gate result: $gate_result"
log "Manifest: $manifest_file"
