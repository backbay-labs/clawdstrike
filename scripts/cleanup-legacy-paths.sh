#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LEGACY_PATHS=(
  "packages/cloud-dashboard"
  "spine/reticulum"
  "spine"
  "HomebrewFormula"
  "deploy"
  "docker"
  "vendor"
)

removed=0

for path in "${LEGACY_PATHS[@]}"; do
  if [[ -e "$path" ]]; then
    rm -rf "$path"
    echo "[cleanup-legacy-paths] removed: $path"
    removed=1
  fi
done

if [[ "$removed" -eq 0 ]]; then
  echo "[cleanup-legacy-paths] no legacy paths found"
fi
