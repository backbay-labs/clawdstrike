#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

bold() { printf "\n=== %s ===\n" "$1"; }

detect_base() {
  if [[ -n "${CI_CHANGED_BASE:-}" ]] && git rev-parse --verify "${CI_CHANGED_BASE}" >/dev/null 2>&1; then
    git merge-base "${CI_CHANGED_BASE}" HEAD
    return
  fi
  if git rev-parse --verify origin/main >/dev/null 2>&1; then
    git merge-base origin/main HEAD
    return
  fi
  if git rev-parse --verify main >/dev/null 2>&1; then
    git merge-base main HEAD
    return
  fi
  if git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
    git rev-parse HEAD~1
    return
  fi
  git rev-parse HEAD
}

matches() {
  local pattern="$1"
  printf "%s\n" "$CHANGED" | rg -q "$pattern"
}

BASE_SHA="$(detect_base)"
CHANGED="$(git diff --name-only "${BASE_SHA}"...HEAD || true)"

bold "Static path guards"
bash scripts/path-lint.sh
bash scripts/move-validation.sh
bash scripts/architecture-guardrails.sh

if [[ -z "$CHANGED" ]]; then
  echo "[ci:changed] no changed files detected beyond base ${BASE_SHA}"
  exit 0
fi

echo "[ci:changed] base=${BASE_SHA}"
echo "[ci:changed] changed files:"
printf "%s\n" "$CHANGED"

run_rust=0
run_apps=0
run_ts=0
run_py=0
run_docs=0
run_infra=0

if matches "^(crates/|Cargo.toml$|Cargo.lock$|clippy.toml$|deny.toml$|scripts/cargo-offline.sh$)"; then
  run_rust=1
fi
if matches "^apps/"; then
  run_apps=1
fi
if matches "^(packages/(sdk/hush-ts|adapters|policy)/|package.json$|package-lock.json$|scripts/smoke-ts-file-deps.sh$)"; then
  run_ts=1
fi
if matches "^packages/sdk/hush-py/"; then
  run_py=1
fi
if matches "^(docs/|README.md$|CONTRIBUTING.md$|AGENTS.md$)"; then
  run_docs=1
fi
if matches "^(infra/|Dockerfile.hushd$|\\.github/workflows/|scripts/(path-lint|move-validation|architecture-guardrails|ci-changed).sh$)"; then
  run_infra=1
fi

if [[ "$run_rust" -eq 1 ]]; then
  bold "Rust"
  mise run test:rust
fi

if [[ "$run_apps" -eq 1 ]]; then
  bold "Apps"
  mise run test:apps
fi

if [[ "$run_ts" -eq 1 ]]; then
  bold "TypeScript packages"
  mise run test:packages:ts
fi

if [[ "$run_py" -eq 1 ]]; then
  bold "Python package"
  mise run test:packages:py
fi

if [[ "$run_docs" -eq 1 ]]; then
  bold "Docs"
  tools/scripts/validate-docs
fi

if [[ "$run_infra" -eq 1 ]]; then
  bold "Infra"
  docker compose -f infra/docker/docker-compose.services.yaml config > /dev/null
fi

echo
echo "[ci:changed] OK"
