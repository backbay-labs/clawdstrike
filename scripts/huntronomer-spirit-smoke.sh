#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
desktop_dir="$repo_root/apps/desktop"

run_id="$(date -u +%Y%m%dT%H%M%SZ)"
output_dir="$repo_root/output/tests/huntronomer-spirit-smoke/$run_id"
mkdir -p "$output_dir"

log_file="$output_dir/vitest.log"
summary_file="$output_dir/summary.json"

tests=(
  "src/shell/workbench/spirit/spiritVerification.smoke.test.tsx"
  "src/shell/workbench/spirit-bind/SpiritBindSheet.test.tsx"
  "src/shell/workbench/spirit/components/SpiritIdentity.test.tsx"
  "src/features/forensics/components/hunt-spirit/runtime.test.ts"
  "src/features/cyber-nexus/scene/spirits/runtime.test.ts"
)

(
  cd "$desktop_dir"
  npm test -- --run "${tests[@]}"
) | tee "$log_file"

export HUNTRONOMER_SPIRIT_SMOKE_SUMMARY_FILE="$summary_file"
export HUNTRONOMER_SPIRIT_SMOKE_LOG_FILE="$log_file"
export HUNTRONOMER_SPIRIT_SMOKE_RUN_ID="$run_id"
export HUNTRONOMER_SPIRIT_SMOKE_OUTPUT_DIR="$output_dir"
export HUNTRONOMER_SPIRIT_SMOKE_TESTS="$(printf '%s\n' "${tests[@]}")"

python3 - <<'PY'
import json
import os
from pathlib import Path

summary = {
    "status": "ok",
    "run_id": os.environ["HUNTRONOMER_SPIRIT_SMOKE_RUN_ID"],
    "output_dir": os.environ["HUNTRONOMER_SPIRIT_SMOKE_OUTPUT_DIR"],
    "tests": [line for line in os.environ["HUNTRONOMER_SPIRIT_SMOKE_TESTS"].splitlines() if line],
    "artifacts": {
        "vitest_log": os.environ["HUNTRONOMER_SPIRIT_SMOKE_LOG_FILE"],
    },
}

Path(os.environ["HUNTRONOMER_SPIRIT_SMOKE_SUMMARY_FILE"]).write_text(
    json.dumps(summary, indent=2) + "\n",
    encoding="utf-8",
)
print(json.dumps(summary, indent=2))
PY
