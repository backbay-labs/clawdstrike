#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
preflight_only="${CLAWDSTRIKE_EDE_QUALIFICATION_PREFLIGHT_ONLY:-0}"
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
bundle_dir="${CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR:-$repo_root/output/dogfood/endpoint-decision-engine-qualification/$run_id}"
macos_provider_dir="${CLAWDSTRIKE_EDE_QUALIFICATION_MACOS_PROVIDER_DIR:-$bundle_dir/macos-provider}"
proof_root="${CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT:-$bundle_dir/supplemental-proofs}"
audit_output="${CLAWDSTRIKE_EDE_QUALIFICATION_AUDIT_OUTPUT:-$bundle_dir/endpoint-decision-engine-readiness-audit.json}"
summary_output="${CLAWDSTRIKE_EDE_QUALIFICATION_SUMMARY_OUTPUT:-$bundle_dir/qualification-summary.json}"
supplemental_bundle_output="${CLAWDSTRIKE_EDE_SUPPLEMENTAL_PROOF_BUNDLE_OUTPUT:-$bundle_dir/supplemental-proof-bundle-result.json}"
supplemental_replace_output="${CLAWDSTRIKE_EDE_SUPPLEMENTAL_PROOF_REPLACE_OUTPUT:-0}"
macos_provider_replace_output="${CLAWDSTRIKE_EDE_MACOS_PROVIDER_REPLACE_OUTPUT:-${CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_REPLACE_OUTPUT:-0}}"
supplemental_source_vars=(
  CLAWDSTRIKE_EDE_POLICY_EVENTS
  CLAWDSTRIKE_EDE_POLICY_IMPACT_JSON
  CLAWDSTRIKE_EDE_POLICY_PROPOSED_HASH
  CLAWDSTRIKE_EDE_POLICY_EPOCH
  CLAWDSTRIKE_EDE_AI_AGENT_COVERAGE_JSON
  CLAWDSTRIKE_EDE_ENDPOINT_DECEPTION_COVERAGE_JSON
  CLAWDSTRIKE_EDE_SUPPLY_CHAIN_COVERAGE_JSON
  CLAWDSTRIKE_EDE_PRIVACY_COVERAGE_JSON
  CLAWDSTRIKE_EDE_OPERATOR_WORKFLOWS_COVERAGE_JSON
  CLAWDSTRIKE_EDE_SENSOR_BREADTH_COVERAGE_JSON
)

log() {
  printf '[ede-qualification] %s\n' "$*" >&2
}

die() {
  log "ERROR: $*"
  exit 1
}

is_enabled() {
  case "$1" in
    1|true|TRUE|yes|YES|on|ON) return 0 ;;
    0|false|FALSE|no|NO|off|OFF|"") return 1 ;;
    *) die "boolean flag must be one of 1/0/true/false/yes/no/on/off, got: $1" ;;
  esac
}

bool_string() {
  if is_enabled "$1"; then
    printf 'true'
  else
    printf 'false'
  fi
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

require_creatable_parent() {
  local path="$1"
  local label="$2"
  local parent
  parent="$(dirname "$path")"
  while [[ ! -e "$parent" && "$parent" != "/" ]]; do
    parent="$(dirname "$parent")"
  done
  [[ -d "$parent" ]] || die "$label parent exists but is not a directory: $parent"
  [[ -w "$parent" ]] || die "$label parent is not writable: $parent"
}

path_inside_dir() {
  python3 -c 'import pathlib, sys
path = pathlib.Path(sys.argv[1]).expanduser().resolve()
root = pathlib.Path(sys.argv[2]).expanduser().resolve()
sys.exit(0 if path != root and root in path.parents else 1)' "$1" "$2"
}

paths_overlap() {
  python3 -c 'import pathlib, sys
left = pathlib.Path(sys.argv[1]).expanduser().resolve()
right = pathlib.Path(sys.argv[2]).expanduser().resolve()
sys.exit(0 if left == right or left in right.parents or right in left.parents else 1)' "$1" "$2"
}

paths_equal() {
  python3 -c 'import pathlib, sys
left = pathlib.Path(sys.argv[1]).expanduser().resolve()
right = pathlib.Path(sys.argv[2]).expanduser().resolve()
sys.exit(0 if left == right else 1)' "$1" "$2"
}

require_bundle_child_path() {
  local path="$1"
  local label="$2"
  path_inside_dir "$path" "$bundle_dir" || die "$label must be inside bundle dir: $path"
}

require_output_file_path() {
  local path="$1"
  local label="$2"
  [[ ! -d "$path" ]] || die "$label must be a file path, not a directory: $path"
  require_bundle_child_path "$path" "$label"
  require_creatable_parent "$path" "$label"
}

require_not_under_dir() {
  local path="$1"
  local dir="$2"
  local label="$3"
  local dir_label="$4"
  if paths_equal "$path" "$dir" || path_inside_dir "$path" "$dir"; then
    die "$label must not be inside $dir_label: $path"
  fi
}

validate_bundle_layout() {
  require_bundle_child_path "$macos_provider_dir" "macOS provider dir"
  require_bundle_child_path "$proof_root" "proof root"
  if paths_overlap "$macos_provider_dir" "$proof_root"; then
    die "macOS provider dir and proof root must not overlap"
  fi

  require_output_file_path "$audit_output" "audit output"
  require_output_file_path "$summary_output" "summary output"
  require_output_file_path "$supplemental_bundle_output" "supplemental proof bundle output"
  require_not_under_dir "$audit_output" "$macos_provider_dir" "audit output" "macOS provider dir"
  require_not_under_dir "$audit_output" "$proof_root" "audit output" "proof root"
  require_not_under_dir "$summary_output" "$macos_provider_dir" "summary output" "macOS provider dir"
  require_not_under_dir "$summary_output" "$proof_root" "summary output" "proof root"
  require_not_under_dir "$supplemental_bundle_output" "$macos_provider_dir" \
    "supplemental proof bundle output" "macOS provider dir"
  require_not_under_dir "$supplemental_bundle_output" "$proof_root" \
    "supplemental proof bundle output" "proof root"

  if paths_equal "$audit_output" "$summary_output" \
    || paths_equal "$audit_output" "$supplemental_bundle_output" \
    || paths_equal "$summary_output" "$supplemental_bundle_output"; then
    die "audit, qualification summary, and supplemental bundle outputs must be distinct files"
  fi
}

prepare_live_output_dirs() {
  mkdir -p "$bundle_dir" "$macos_provider_dir" "$proof_root"
  mkdir -p "$(dirname "$audit_output")" \
    "$(dirname "$summary_output")" \
    "$(dirname "$supplemental_bundle_output")"
}

supplemental_sources_configured() {
  local present=0
  local missing=()
  local var
  for var in "${supplemental_source_vars[@]}"; do
    if [[ -n "${!var:-}" ]]; then
      present=$((present + 1))
    else
      missing+=("$var")
    fi
  done
  if [[ "$present" -eq 0 ]]; then
    return 1
  fi
  if [[ "$present" -ne "${#supplemental_source_vars[@]}" ]]; then
    die "partial supplemental proof source configuration; missing: ${missing[*]}"
  fi
  return 0
}

run_supplemental_proof_bundle_preflight() {
  if is_enabled "$supplemental_replace_output"; then
    python3 "$repo_root/scripts/endpoint-decision-engine-supplemental-proof-bundle.py" \
      --preflight \
      --replace-output \
      --evidence-mode live \
      --out-dir "$proof_root" \
      --policy-events "${CLAWDSTRIKE_EDE_POLICY_EVENTS:-}" \
      --policy-impact-json "${CLAWDSTRIKE_EDE_POLICY_IMPACT_JSON:-}" \
      --policy-current-ref "${CLAWDSTRIKE_EDE_POLICY_CURRENT_REF:-captured-current-policy}" \
      --policy-proposed-ref "${CLAWDSTRIKE_EDE_POLICY_PROPOSED_REF:-captured-proposed-policy}" \
      --policy-proposed-hash "${CLAWDSTRIKE_EDE_POLICY_PROPOSED_HASH:-}" \
      --policy-epoch "${CLAWDSTRIKE_EDE_POLICY_EPOCH:-0}" \
      --ai-agent-coverage-json "${CLAWDSTRIKE_EDE_AI_AGENT_COVERAGE_JSON:-}" \
      --endpoint-deception-coverage-json "${CLAWDSTRIKE_EDE_ENDPOINT_DECEPTION_COVERAGE_JSON:-}" \
      --supply-chain-coverage-json "${CLAWDSTRIKE_EDE_SUPPLY_CHAIN_COVERAGE_JSON:-}" \
      --privacy-coverage-json "${CLAWDSTRIKE_EDE_PRIVACY_COVERAGE_JSON:-}" \
      --operator-workflows-coverage-json "${CLAWDSTRIKE_EDE_OPERATOR_WORKFLOWS_COVERAGE_JSON:-}" \
      --sensor-breadth-coverage-json "${CLAWDSTRIKE_EDE_SENSOR_BREADTH_COVERAGE_JSON:-}" \
      >/dev/null
    return
  fi
  python3 "$repo_root/scripts/endpoint-decision-engine-supplemental-proof-bundle.py" \
    --preflight \
    --evidence-mode live \
    --out-dir "$proof_root" \
    --policy-events "${CLAWDSTRIKE_EDE_POLICY_EVENTS:-}" \
    --policy-impact-json "${CLAWDSTRIKE_EDE_POLICY_IMPACT_JSON:-}" \
    --policy-current-ref "${CLAWDSTRIKE_EDE_POLICY_CURRENT_REF:-captured-current-policy}" \
    --policy-proposed-ref "${CLAWDSTRIKE_EDE_POLICY_PROPOSED_REF:-captured-proposed-policy}" \
    --policy-proposed-hash "${CLAWDSTRIKE_EDE_POLICY_PROPOSED_HASH:-}" \
    --policy-epoch "${CLAWDSTRIKE_EDE_POLICY_EPOCH:-0}" \
    --ai-agent-coverage-json "${CLAWDSTRIKE_EDE_AI_AGENT_COVERAGE_JSON:-}" \
    --endpoint-deception-coverage-json "${CLAWDSTRIKE_EDE_ENDPOINT_DECEPTION_COVERAGE_JSON:-}" \
    --supply-chain-coverage-json "${CLAWDSTRIKE_EDE_SUPPLY_CHAIN_COVERAGE_JSON:-}" \
    --privacy-coverage-json "${CLAWDSTRIKE_EDE_PRIVACY_COVERAGE_JSON:-}" \
    --operator-workflows-coverage-json "${CLAWDSTRIKE_EDE_OPERATOR_WORKFLOWS_COVERAGE_JSON:-}" \
    --sensor-breadth-coverage-json "${CLAWDSTRIKE_EDE_SENSOR_BREADTH_COVERAGE_JSON:-}" \
    >/dev/null
}

run_supplemental_proof_bundle() {
  if is_enabled "$supplemental_replace_output"; then
    python3 "$repo_root/scripts/endpoint-decision-engine-supplemental-proof-bundle.py" \
      --replace-output \
      --evidence-mode live \
      --out-dir "$proof_root" \
      --policy-events "${CLAWDSTRIKE_EDE_POLICY_EVENTS:-}" \
      --policy-impact-json "${CLAWDSTRIKE_EDE_POLICY_IMPACT_JSON:-}" \
      --policy-current-ref "${CLAWDSTRIKE_EDE_POLICY_CURRENT_REF:-captured-current-policy}" \
      --policy-proposed-ref "${CLAWDSTRIKE_EDE_POLICY_PROPOSED_REF:-captured-proposed-policy}" \
      --policy-proposed-hash "${CLAWDSTRIKE_EDE_POLICY_PROPOSED_HASH:-}" \
      --policy-epoch "${CLAWDSTRIKE_EDE_POLICY_EPOCH:-0}" \
      --ai-agent-coverage-json "${CLAWDSTRIKE_EDE_AI_AGENT_COVERAGE_JSON:-}" \
      --endpoint-deception-coverage-json "${CLAWDSTRIKE_EDE_ENDPOINT_DECEPTION_COVERAGE_JSON:-}" \
      --supply-chain-coverage-json "${CLAWDSTRIKE_EDE_SUPPLY_CHAIN_COVERAGE_JSON:-}" \
      --privacy-coverage-json "${CLAWDSTRIKE_EDE_PRIVACY_COVERAGE_JSON:-}" \
      --operator-workflows-coverage-json "${CLAWDSTRIKE_EDE_OPERATOR_WORKFLOWS_COVERAGE_JSON:-}" \
      --sensor-breadth-coverage-json "${CLAWDSTRIKE_EDE_SENSOR_BREADTH_COVERAGE_JSON:-}" \
      >"$supplemental_bundle_output"
    return
  fi
  python3 "$repo_root/scripts/endpoint-decision-engine-supplemental-proof-bundle.py" \
    --out-dir "$proof_root" \
    --evidence-mode live \
    --policy-events "${CLAWDSTRIKE_EDE_POLICY_EVENTS:-}" \
    --policy-impact-json "${CLAWDSTRIKE_EDE_POLICY_IMPACT_JSON:-}" \
    --policy-current-ref "${CLAWDSTRIKE_EDE_POLICY_CURRENT_REF:-captured-current-policy}" \
    --policy-proposed-ref "${CLAWDSTRIKE_EDE_POLICY_PROPOSED_REF:-captured-proposed-policy}" \
    --policy-proposed-hash "${CLAWDSTRIKE_EDE_POLICY_PROPOSED_HASH:-}" \
    --policy-epoch "${CLAWDSTRIKE_EDE_POLICY_EPOCH:-0}" \
    --ai-agent-coverage-json "${CLAWDSTRIKE_EDE_AI_AGENT_COVERAGE_JSON:-}" \
    --endpoint-deception-coverage-json "${CLAWDSTRIKE_EDE_ENDPOINT_DECEPTION_COVERAGE_JSON:-}" \
    --supply-chain-coverage-json "${CLAWDSTRIKE_EDE_SUPPLY_CHAIN_COVERAGE_JSON:-}" \
    --privacy-coverage-json "${CLAWDSTRIKE_EDE_PRIVACY_COVERAGE_JSON:-}" \
    --operator-workflows-coverage-json "${CLAWDSTRIKE_EDE_OPERATOR_WORKFLOWS_COVERAGE_JSON:-}" \
    --sensor-breadth-coverage-json "${CLAWDSTRIKE_EDE_SENSOR_BREADTH_COVERAGE_JSON:-}" \
    >"$supplemental_bundle_output"
}

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/endpoint-decision-engine-live-qualification.sh HOST:PORT
  scripts/endpoint-decision-engine-live-qualification.sh --preflight HOST:PORT
  scripts/endpoint-decision-engine-live-qualification.sh --self-test

Environment:
  CLAWDSTRIKE_EDE_QUALIFICATION_PREFLIGHT_ONLY       1/true/yes/on exits after input/tool checks
  CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR           final qualification evidence bundle root
  CLAWDSTRIKE_EDE_QUALIFICATION_MACOS_PROVIDER_DIR   macOS provider dogfood output directory
  CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT           strict supplemental proof directory
  CLAWDSTRIKE_EDE_QUALIFICATION_AUDIT_OUTPUT         persisted readiness audit JSON path
  CLAWDSTRIKE_EDE_QUALIFICATION_SUMMARY_OUTPUT       qualification summary JSON path
  CLAWDSTRIKE_EDE_SUPPLEMENTAL_PROOF_BUNDLE_OUTPUT   proof-bundle builder summary JSON path
  CLAWDSTRIKE_EDE_MACOS_PROVIDER_REPLACE_OUTPUT      1/true/yes/on permits replacing stale macOS provider output
  CLAWDSTRIKE_EDE_SUPPLEMENTAL_PROOF_REPLACE_OUTPUT  1/true/yes/on permits replacing non-empty proof root
  CLAWDSTRIKE_EDE_POLICY_EVENTS                      policy replay event JSONL
  CLAWDSTRIKE_EDE_POLICY_IMPACT_JSON                 captured policy impact JSON
  CLAWDSTRIKE_EDE_POLICY_PROPOSED_HASH               sha256:<hex> proposed policy hash
  CLAWDSTRIKE_EDE_POLICY_EPOCH                       positive policy epoch
  CLAWDSTRIKE_EDE_POLICY_CURRENT_REF                 optional current policy reference label
  CLAWDSTRIKE_EDE_POLICY_PROPOSED_REF                optional proposed policy reference label
  CLAWDSTRIKE_EDE_AI_AGENT_COVERAGE_JSON             AI-agent/developer coverage JSON
  CLAWDSTRIKE_EDE_ENDPOINT_DECEPTION_COVERAGE_JSON   endpoint deception coverage JSON
  CLAWDSTRIKE_EDE_SUPPLY_CHAIN_COVERAGE_JSON         supply-chain runtime coverage JSON
  CLAWDSTRIKE_EDE_PRIVACY_COVERAGE_JSON              privacy telemetry coverage JSON
  CLAWDSTRIKE_EDE_OPERATOR_WORKFLOWS_COVERAGE_JSON   operator workflow coverage JSON
  CLAWDSTRIKE_EDE_SENSOR_BREADTH_COVERAGE_JSON       cross-platform sensor coverage JSON

This is the end-to-end QA-host qualification driver for the Endpoint Decision
Engine north-star gate. It fixes the evidence layout, runs the deployed macOS
provider live dogfood into the bundle, then verifies the bundle with
scripts/endpoint-decision-engine-qualification-bundle.py.

The script does not fabricate supplemental proofs. Either stage strict proof
JSON files under CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT or provide all
CLAWDSTRIKE_EDE_* source coverage variables above so the script can build the
proof root with scripts/endpoint-decision-engine-supplemental-proof-bundle.py.
Otherwise the final readiness audit will remain red for the missing non-macOS
proof keys.

Use --preflight or CLAWDSTRIKE_EDE_QUALIFICATION_PREFLIGHT_ONLY=1 to validate
commands, script permissions, live dogfood preflight, output paths, and proof
root reachability without creating the bundle or running live provider dogfood.
USAGE
}

run_preflight() {
  local target="$1"
  require_cmd date
  require_cmd mkdir
  require_cmd python3
  require_readable_file "$repo_root/scripts/endpoint-decision-engine-qualification-bundle.py"
  require_readable_file "$repo_root/scripts/endpoint-decision-engine-supplemental-proof-bundle.py"
  require_executable_file "$repo_root/scripts/macos-provider-live-dogfood.sh"
  require_executable_file "$repo_root/scripts/endpoint-security-live-dogfood.sh"
  require_executable_file "$repo_root/scripts/network-extension-live-dogfood.sh"

  CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_OUTPUT_DIR="$macos_provider_dir" \
  CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_REPLACE_OUTPUT="$macos_provider_replace_output" \
    "$repo_root/scripts/macos-provider-live-dogfood.sh" --preflight "$target"

  if [[ -e "$proof_root" && ! -d "$proof_root" ]]; then
    die "proof root exists but is not a directory: $proof_root"
  fi
  require_creatable_parent "$bundle_dir" "bundle dir"
  require_creatable_parent "$macos_provider_dir" "macOS provider dir"
  require_creatable_parent "$proof_root" "proof root"
  validate_bundle_layout
  if is_enabled "$macos_provider_replace_output"; then
    :
  fi
  if is_enabled "$supplemental_replace_output"; then
    :
  fi
  if supplemental_sources_configured; then
    run_supplemental_proof_bundle_preflight
  fi

  log "Preflight passed"
  log "Bundle dir: $bundle_dir"
  log "macOS provider dir: $macos_provider_dir"
  log "Supplemental proof root: $proof_root"
  log "Audit output: $audit_output"
}

run_self_test() {
  require_cmd mktemp
  require_cmd mkdir
  require_cmd rm

  local temp_dir
  temp_dir="$(mktemp -d "${TMPDIR:-/tmp}/clawdstrike-ede-live-qualification.XXXXXX")"
  local bundle_path="$temp_dir/ClawdStrike.app"
  local bundle_output="$temp_dir/qualification"
  local proof_root_output="$bundle_output/supplemental-proofs"
  local source_root="$temp_dir/source"
  mkdir -p "$bundle_path" "$proof_root_output"
  mkdir -p "$source_root"

  if ! CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path/" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected preflight with trailing slash bundle path to pass"
  fi

  if [[ -e "$bundle_output/macos-provider" ]]; then
    rm -rf "$temp_dir"
    die "self-test expected preflight not to create the macOS provider output directory"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight localhost:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected loopback target to fail"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$temp_dir/Missing.app" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected missing provider bundle to fail"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    CLAWDSTRIKE_EDE_SUPPLEMENTAL_PROOF_REPLACE_OUTPUT=maybe \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected invalid replace-output boolean to fail"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    CLAWDSTRIKE_EDE_MACOS_PROVIDER_REPLACE_OUTPUT=maybe \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected invalid macOS provider replace-output boolean to fail"
  fi

  local proof_root_file="$temp_dir/not-a-dir"
  : >"$proof_root_file"
  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_file/proofs" \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected non-directory proof-root parent to fail"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$temp_dir/outside-proofs" \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected proof root outside bundle to fail"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_MACOS_PROVIDER_DIR="$proof_root_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected overlapping provider/proof directories to fail"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_AUDIT_OUTPUT="$proof_root_output/audit.json" \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected audit output inside proof root to fail"
  fi

  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_SUMMARY_OUTPUT="$bundle_output/shared-summary.json" \
    CLAWDSTRIKE_EDE_SUPPLEMENTAL_PROOF_BUNDLE_OUTPUT="$bundle_output/shared-summary.json" \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected duplicate output paths to fail"
  fi

  local stale_provider_dir="$bundle_output/macos-provider"
  mkdir -p "$stale_provider_dir"
  : >"$stale_provider_dir/old-manifest.json"
  if CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected stale macOS provider output to fail without replace opt-in"
  fi

  if ! CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    CLAWDSTRIKE_EDE_MACOS_PROVIDER_REPLACE_OUTPUT=1 \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected stale macOS provider output to pass with replace opt-in"
  fi
  if [[ ! -f "$stale_provider_dir/old-manifest.json" ]]; then
    rm -rf "$temp_dir"
    die "self-test expected macOS provider replace preflight not to delete stale output"
  fi
  rm -rf "$stale_provider_dir"

  python3 - "$repo_root" "$source_root" <<'PY'
import importlib.util
import json
import pathlib
import sys

repo_root = pathlib.Path(sys.argv[1])
source_root = pathlib.Path(sys.argv[2])
script_dir = repo_root / "scripts"


def load_module(path):
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


bundle = load_module(script_dir / "endpoint-decision-engine-supplemental-proof-bundle.py")
bundle.fixture_policy_inputs(source_root)
coverage_files = {
    "ai-agent.json": "ai_agent_developer_workstation",
    "deception.json": "endpoint_deception",
    "supply-chain.json": "supply_chain_runtime_guard",
    "privacy.json": "privacy_preserving_telemetry",
    "operator.json": "operator_workflows",
    "sensors.json": "cross_platform_sensor_breadth",
}
for filename, key in coverage_files.items():
    module = load_module(script_dir / bundle.EXPECTED_PROOFS[key])
    (source_root / filename).write_text(
        json.dumps(module.fixture_coverage(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
PY

  if ! CLAWDSTRIKE_MACOS_PROVIDER_BUNDLE_PATH="$bundle_path" \
    CLAWDSTRIKE_EDE_QUALIFICATION_BUNDLE_DIR="$bundle_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_PROOF_ROOT="$proof_root_output" \
    CLAWDSTRIKE_EDE_QUALIFICATION_AUDIT_OUTPUT="$bundle_output/nested/audits/audit.json" \
    CLAWDSTRIKE_EDE_QUALIFICATION_SUMMARY_OUTPUT="$bundle_output/nested/summaries/summary.json" \
    CLAWDSTRIKE_EDE_SUPPLEMENTAL_PROOF_BUNDLE_OUTPUT="$bundle_output/nested/supplemental/bundle.json" \
    CLAWDSTRIKE_EDE_POLICY_EVENTS="$source_root/policy-events.jsonl" \
    CLAWDSTRIKE_EDE_POLICY_IMPACT_JSON="$source_root/policy-impact.json" \
    CLAWDSTRIKE_EDE_POLICY_PROPOSED_HASH="sha256:abababababababababababababababababababababababababababababababab" \
    CLAWDSTRIKE_EDE_POLICY_EPOCH=7 \
    CLAWDSTRIKE_EDE_AI_AGENT_COVERAGE_JSON="$source_root/ai-agent.json" \
    CLAWDSTRIKE_EDE_ENDPOINT_DECEPTION_COVERAGE_JSON="$source_root/deception.json" \
    CLAWDSTRIKE_EDE_SUPPLY_CHAIN_COVERAGE_JSON="$source_root/supply-chain.json" \
    CLAWDSTRIKE_EDE_PRIVACY_COVERAGE_JSON="$source_root/privacy.json" \
    CLAWDSTRIKE_EDE_OPERATOR_WORKFLOWS_COVERAGE_JSON="$source_root/operator.json" \
    CLAWDSTRIKE_EDE_SENSOR_BREADTH_COVERAGE_JSON="$source_root/sensors.json" \
    "$repo_root/scripts/endpoint-decision-engine-live-qualification.sh" --preflight example.com:443 >/dev/null 2>&1; then
    rm -rf "$temp_dir"
    die "self-test expected source-artifact preflight to pass"
  fi

  bundle_dir="$bundle_output"
  macos_provider_dir="$bundle_output/macos-provider"
  proof_root="$proof_root_output"
  audit_output="$bundle_output/nested/audits/audit.json"
  summary_output="$bundle_output/nested/summaries/summary.json"
  supplemental_bundle_output="$bundle_output/nested/supplemental/bundle.json"
  prepare_live_output_dirs
  for expected_dir in \
    "$bundle_output/macos-provider" \
    "$proof_root_output" \
    "$bundle_output/nested/audits" \
    "$bundle_output/nested/summaries" \
    "$bundle_output/nested/supplemental"; do
    if [[ ! -d "$expected_dir" ]]; then
      rm -rf "$temp_dir"
      die "self-test expected runtime output preparation to create: $expected_dir"
    fi
  done

  rm -rf "$temp_dir"
  log "self-test passed"
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

run_preflight "$target_input"

if is_enabled "$preflight_only"; then
  exit 0
fi

prepare_live_output_dirs

supplemental_sources_enabled=0
if supplemental_sources_configured; then
  supplemental_sources_enabled=1
  log "Building supplemental proof bundle"
  run_supplemental_proof_bundle
fi

CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_OUTPUT_DIR="$macos_provider_dir" \
CLAWDSTRIKE_MACOS_PROVIDER_DOGFOOD_REPLACE_OUTPUT="$macos_provider_replace_output" \
  "$repo_root/scripts/macos-provider-live-dogfood.sh" "$target_input"

set +e
python3 "$repo_root/scripts/endpoint-decision-engine-qualification-bundle.py" \
  --bundle-dir "$bundle_dir" \
  --manifest "$macos_provider_dir/manifest.json" \
  --proof-root "$proof_root" \
  --output "$audit_output" \
  --metadata driver=endpoint-decision-engine-live-qualification.sh \
  --metadata "target=$target_input" \
  --metadata "macos_provider_replace_output=$(bool_string "$macos_provider_replace_output")" \
  --metadata "supplemental_proof_replace_output=$(bool_string "$supplemental_replace_output")" \
  --metadata "supplemental_sources_configured=$(bool_string "$supplemental_sources_enabled")" \
  >"$summary_output"
qualification_status=$?
set -e

if [[ "$qualification_status" -ne 0 ]]; then
  log "Endpoint Decision Engine qualification failed"
  log "Summary: $summary_output"
  log "Readiness audit: $audit_output"
  exit "$qualification_status"
fi

log "Endpoint Decision Engine qualification passed"
log "Summary: $summary_output"
log "Readiness audit: $audit_output"
