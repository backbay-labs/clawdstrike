#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

bold() { printf "\n=== %s ===\n" "$1"; }

bold "Go SDK conformance vectors"
(
  cd packages/sdk/hush-go
  go test ./policy -run TestPolicyConformanceVectors
  go test ./canonical
)

bold "TypeScript SDK conformance vectors"
npm --prefix packages/sdk/hush-ts ci
npm --prefix packages/sdk/hush-ts test -- tests/policy-conformance.test.ts tests/canonical.test.ts

bold "Python SDK conformance vectors"
VENV_DIR="${VENV_DIR:-/tmp/hush-sdk-conformance-venv}"
if [[ ! -d "$VENV_DIR" ]]; then
  python3 -m venv "$VENV_DIR"
  "$VENV_DIR/bin/python" -m pip install -U pip
fi
"$VENV_DIR/bin/python" -m pip install -e "packages/sdk/hush-py[dev]"
"$VENV_DIR/bin/python" -m pytest -q \
  packages/sdk/hush-py/tests/test_policy_conformance.py \
  packages/sdk/hush-py/tests/test_canonical.py

bold "SDK conformance complete"
