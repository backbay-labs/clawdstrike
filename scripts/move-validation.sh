#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LEGACY_PATHS=(
  "apps/cloud-dashboard"
  "packages/cloud-dashboard"
  "spine"
  "spine/reticulum"
  "HomebrewFormula"
  "crates/hush-core"
  "crates/hush-proxy"
  "crates/clawdstrike"
  "crates/hush-certification"
  "crates/hush-multi-agent"
  "crates/hush-wasm"
  "crates/spine"
  "crates/hush-cli"
  "crates/hushd"
  "crates/spine-cli"
  "crates/cloud-api"
  "crates/services/cloud-api"
  "crates/eas-anchor"
  "crates/tetragon-bridge"
  "crates/hubble-bridge"
  "crates/sdr-integration-tests"
  "packages/hush-ts"
  "packages/hush-py"
  "packages/clawdstrike-policy"
  "packages/clawdstrike-adapter-core"
  "packages/clawdstrike-claude"
  "packages/clawdstrike-openai"
  "packages/clawdstrike-langchain"
  "packages/clawdstrike-openclaw"
  "packages/clawdstrike-opencode"
  "packages/clawdstrike-vercel-ai"
  "packages/clawdstrike-hush-cli-engine"
  "packages/clawdstrike-hushd-engine"
  "deploy"
  "docker"
  "vendor"
)

TARGET_PATHS=(
  "apps/control-console"
  "integrations/transports/reticulum"
  "infra/packaging/HomebrewFormula"
  "crates/libs/hush-core"
  "crates/libs/hush-proxy"
  "crates/libs/clawdstrike"
  "crates/libs/hush-certification"
  "crates/libs/hush-multi-agent"
  "crates/libs/hush-wasm"
  "crates/libs/spine"
  "crates/services/hush-cli"
  "crates/services/hushd"
  "crates/services/spine-cli"
  "crates/services/control-api"
  "crates/services/eas-anchor"
  "crates/bridges/tetragon-bridge"
  "crates/bridges/hubble-bridge"
  "crates/tests/sdr-integration-tests"
  "packages/sdk/hush-ts"
  "packages/sdk/hush-py"
  "packages/policy/clawdstrike-policy"
  "packages/adapters/clawdstrike-adapter-core"
  "packages/adapters/clawdstrike-claude"
  "packages/adapters/clawdstrike-openai"
  "packages/adapters/clawdstrike-langchain"
  "packages/adapters/clawdstrike-openclaw"
  "packages/adapters/clawdstrike-opencode"
  "packages/adapters/clawdstrike-vercel-ai"
  "packages/adapters/clawdstrike-hush-cli-engine"
  "packages/adapters/clawdstrike-hushd-engine"
  "infra/deploy"
  "infra/docker"
  "infra/vendor"
)

fail=0

ensure_legacy_empty() {
  local path="$1"
  local matches
  matches="$(git ls-files -- "$path" "$path/**" | sed '/^$/d')"
  if [[ -n "$matches" ]]; then
    echo "[move-validation] legacy path still tracked: $path"
    echo "$matches"
    echo
    fail=1
  fi
}

ensure_legacy_absent_on_disk() {
  local path="$1"
  if [[ -e "$path" ]]; then
    echo "[move-validation] legacy path still exists on disk: $path"
    echo "  remove it locally to avoid contributor confusion"
    echo
    fail=1
  fi
}

ensure_target_present() {
  local path="$1"
  local matches
  matches="$(git ls-files -- "$path" "$path/**" | sed '/^$/d')"
  if [[ -z "$matches" ]]; then
    echo "[move-validation] expected target path missing tracked files: $path"
    echo
    fail=1
  fi
}

for path in "${LEGACY_PATHS[@]}"; do
  ensure_legacy_empty "$path"
  ensure_legacy_absent_on_disk "$path"
done

for path in "${TARGET_PATHS[@]}"; do
  ensure_target_present "$path"
done

if [[ "$fail" -ne 0 ]]; then
  echo "[move-validation] FAIL"
  exit 1
fi

echo "[move-validation] OK"
