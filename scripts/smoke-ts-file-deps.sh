#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[smoke] Building adapter-core (file dependency source)"
npm --prefix packages/adapters/clawdstrike-adapter-core ci
npm --prefix packages/adapters/clawdstrike-adapter-core run build

echo "[smoke] Verifying @clawdstrike/policy clean install + tests"
npm --prefix packages/policy/clawdstrike-policy ci
npm --prefix packages/policy/clawdstrike-policy test
npm --prefix packages/policy/clawdstrike-policy run typecheck

echo "[smoke] Verifying @clawdstrike/sdk clean install + tests"
npm --prefix packages/sdk/hush-ts ci
npm --prefix packages/sdk/hush-ts test
npm --prefix packages/sdk/hush-ts run typecheck

echo "[smoke] OK"
