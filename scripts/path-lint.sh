#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

SEARCH_PATHS=(
  .github
  scripts
  tools/scripts
  Cargo.toml
  package.json
  package-lock.json
  AGENTS.md
  CLAUDE.md
  CONTRIBUTING.md
  README.md
  SECURITY.md
  docs/DOCS_MAP.md
  docs/src
)

# Old paths that should not appear in operational configs/docs after repo moves.
FIXED_PATTERNS=(
  "packages/cloud-dashboard"
  "spine/reticulum"
  "crates/hush-core"
  "crates/hush-proxy"
  "crates/clawdstrike"
  "crates/hush-certification"
  "crates/hush-cli"
  "crates/hushd"
  "crates/hush-wasm"
  "crates/hush-multi-agent"
  "crates/spine"
  "crates/spine-cli"
  "crates/tetragon-bridge"
  "crates/hubble-bridge"
  "crates/eas-anchor"
  "crates/sdr-integration-tests"
  "crates/cloud-api"
  "packages/hush-ts"
  "packages/hush-py"
  "packages/clawdstrike-policy"
  "packages/clawdstrike-adapter-core"
  "packages/clawdstrike-claude"
  "packages/clawdstrike-openai"
  "packages/clawdstrike-vercel-ai"
  "packages/clawdstrike-langchain"
  "packages/clawdstrike-openclaw"
  "packages/clawdstrike-opencode"
  "packages/clawdstrike-hush-cli-engine"
  "packages/clawdstrike-hushd-engine"
)

# Top-level HomebrewFormula references should be moved under infra/packaging.
REGEX_PATTERNS=(
  "(^|[[:space:]\"'(])HomebrewFormula/"
)

EXCLUDE_GLOBS=(
  "--glob" "!**/node_modules/**"
  "--glob" "!**/dist/**"
  "--glob" "!**/.venv/**"
  "--glob" "!**/__pycache__/**"
  "--glob" "!scripts/path-lint.sh"
  "--glob" "!scripts/move-validation.sh"
  "--glob" "!scripts/cleanup-legacy-paths.sh"
  "--glob" "!docs/REPO_MAP.md"
  "--glob" "!docs/HANDOFF.md"
  "--glob" "!crates/*/README.md"
  "--glob" "!packages/*/README.md"
)

fail=0

check_fixed_pattern() {
  local pattern="$1"
  local matches
  matches="$({ rg --fixed-strings --line-number --color never "${EXCLUDE_GLOBS[@]}" "$pattern" "${SEARCH_PATHS[@]}" 2>/dev/null || true; } | sed '/^$/d')"
  if [[ -n "$matches" ]]; then
    echo "[path-lint] stale path reference found: $pattern"
    echo "$matches"
    echo
    fail=1
  fi
}

check_regex_pattern() {
  local pattern="$1"
  local matches
  matches="$({ rg --line-number --color never "${EXCLUDE_GLOBS[@]}" -e "$pattern" "${SEARCH_PATHS[@]}" 2>/dev/null || true; } | sed '/^$/d')"
  if [[ -n "$matches" ]]; then
    echo "[path-lint] stale path reference found (regex): $pattern"
    echo "$matches"
    echo
    fail=1
  fi
}

for pattern in "${FIXED_PATTERNS[@]}"; do
  check_fixed_pattern "$pattern"
done

for pattern in "${REGEX_PATTERNS[@]}"; do
  check_regex_pattern "$pattern"
done

if [[ "$fail" -ne 0 ]]; then
  echo "[path-lint] FAIL"
  exit 1
fi

echo "[path-lint] OK"
