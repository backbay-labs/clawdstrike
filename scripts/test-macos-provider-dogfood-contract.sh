#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

bold() { printf "\n=== %s ===\n" "$1"; }

bold "macOS provider dogfood shell syntax"
bash -n \
  scripts/macos-provider-live-dogfood.sh \
  scripts/endpoint-decision-engine-live-qualification.sh \
  scripts/endpoint-security-live-dogfood.sh \
  scripts/network-extension-live-dogfood.sh

bold "macOS provider dogfood Python compile"
python3 -m py_compile \
  scripts/macos-provider-deployment-evidence.py \
  scripts/macos-provider-dogfood-gate.py \
  scripts/macos-provider-dogfood-manifest.py \
  scripts/endpoint-security-live-dogfood-verify.py \
  scripts/network-extension-live-dogfood-verify.py \
  scripts/endpoint-decision-engine-readiness-audit.py \
  scripts/endpoint-decision-engine-qualification-bundle.py \
  scripts/endpoint-decision-engine-supplemental-proof-bundle.py \
  scripts/policy-simulation-impact-proof.py \
  scripts/ai-agent-developer-workstation-proof.py \
  scripts/endpoint-deception-proof.py \
  scripts/supply-chain-runtime-guard-proof.py \
  scripts/privacy-preserving-telemetry-proof.py \
  scripts/operator-workflows-proof.py \
  scripts/cross-platform-sensor-breadth-proof.py

bold "live evidence-mode wiring"
python3 - <<'PY'
from pathlib import Path

checks = [
    (
        "macOS provider manifest writer",
        Path("scripts/macos-provider-live-dogfood.sh"),
        "--evidence-mode live",
        1,
    ),
    (
        "Endpoint Decision Engine supplemental proof builder",
        Path("scripts/endpoint-decision-engine-live-qualification.sh"),
        "--evidence-mode live",
        4,
    ),
    (
        "Endpoint Decision Engine qualification fail-closed logging",
        Path("scripts/endpoint-decision-engine-live-qualification.sh"),
        "Endpoint Decision Engine qualification failed",
        1,
    ),
    (
        "Endpoint Decision Engine qualification exit-code preservation",
        Path("scripts/endpoint-decision-engine-live-qualification.sh"),
        "exit \"$qualification_status\"",
        1,
    ),
]

for label, path, needle, minimum in checks:
    count = path.read_text(encoding="utf-8").count(needle)
    if count < minimum:
        raise SystemExit(
            f"{label} must pass {needle!r} at least {minimum} time(s); found {count}"
        )
PY

bold "macOS provider live wrapper self-test"
scripts/macos-provider-live-dogfood.sh --self-test
scripts/endpoint-decision-engine-live-qualification.sh --self-test

bold "macOS provider artifact verifier self-tests"
python3 scripts/endpoint-security-live-dogfood-verify.py --self-test
python3 scripts/network-extension-live-dogfood-verify.py --self-test
python3 scripts/macos-provider-deployment-evidence.py --self-test
python3 scripts/macos-provider-dogfood-gate.py --self-test
python3 scripts/macos-provider-dogfood-manifest.py --self-test

bold "Endpoint decision engine readiness audit self-test"
python3 scripts/endpoint-decision-engine-readiness-audit.py --self-test
python3 scripts/endpoint-decision-engine-qualification-bundle.py --self-test
python3 scripts/endpoint-decision-engine-supplemental-proof-bundle.py --self-test
python3 scripts/policy-simulation-impact-proof.py --self-test
python3 scripts/ai-agent-developer-workstation-proof.py --self-test
python3 scripts/endpoint-deception-proof.py --self-test
python3 scripts/supply-chain-runtime-guard-proof.py --self-test
python3 scripts/privacy-preserving-telemetry-proof.py --self-test
python3 scripts/operator-workflows-proof.py --self-test
python3 scripts/cross-platform-sensor-breadth-proof.py --self-test

echo
echo "[macos-provider-dogfood-contract] OK"
