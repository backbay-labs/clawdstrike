#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$REPO_ROOT"

cargo build -p hush-cli

export HUSH_PATH="$REPO_ROOT/target/debug/hush"
export HUSH_E2E=1

cd "$REPO_ROOT/packages/clawdstrike-hush-cli-engine"
if [[ ! -d node_modules ]]; then
  npm install
fi

npm test

