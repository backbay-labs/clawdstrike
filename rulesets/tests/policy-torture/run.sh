#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"

mkdir -p rulesets/tests/policy-torture/reports

if [ ! -x target/debug/hush ]; then
  cargo build -p hush-cli
fi

BIN="target/debug/hush"
REPORTS_DIR="rulesets/tests/policy-torture/reports"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

run_expected_policy_load_failure() {
  local case_id="$1"
  local policy_path="$2"
  local expected_error="$3"
  local suite_file="${TMP_DIR}/${case_id}.policy-test.yaml"

  cat > "$suite_file" <<EOF
name: "Policy Torture ${case_id}"
policy: ${policy_path}
suites:
  - name: "Load validation"
    tests:
      - name: "policy load should fail before evaluation"
        input:
          eventType: custom
          data:
            type: custom
            customType: untrusted_text
            text: "hello"
        expect:
          allowed: true
EOF

  set +e
  local output
  output="$("$BIN" policy test "$suite_file" --resolve --format json 2>&1)"
  local status=$?
  set -e

  printf "%s\n" "$output" > "${REPORTS_DIR}/${case_id}.log"

  if [ "$status" -eq 0 ]; then
    echo "Expected policy load failure for ${case_id}, but command succeeded" >&2
    return 1
  fi

  if ! printf "%s\n" "$output" | grep -qi -- "$expected_error"; then
    echo "Expected error '${expected_error}' was not found for ${case_id}" >&2
    return 1
  fi
}

run_extends_depth_loop_stress() {
  local stress_dir="${TMP_DIR}/extends-stress"
  mkdir -p "$stress_dir"

  # Loop case: A -> B -> A
  cat > "${stress_dir}/loop-a.yaml" <<EOF
version: "1.1.0"
name: "LoopA"
extends: ${stress_dir}/loop-b.yaml
EOF

  cat > "${stress_dir}/loop-b.yaml" <<EOF
version: "1.1.0"
name: "LoopB"
extends: ${stress_dir}/loop-a.yaml
EOF

  # Depth-limit case: build a chain beyond MAX_POLICY_EXTENDS_DEPTH.
  # Root -> p0 ... -> p39 forces resolver depth overflow.
  for i in $(seq 0 39); do
    local next=$((i + 1))
    if [ "$i" -lt 39 ]; then
      cat > "${stress_dir}/p${i}.yaml" <<EOF
version: "1.1.0"
name: "p${i}"
extends: ${stress_dir}/p${next}.yaml
EOF
    else
      cat > "${stress_dir}/p${i}.yaml" <<EOF
version: "1.1.0"
name: "p${i}"
EOF
    fi
  done

  cat > "${stress_dir}/depth-root.yaml" <<EOF
version: "1.1.0"
name: "DepthRoot"
extends: ${stress_dir}/p0.yaml
EOF

  run_expected_policy_load_failure \
    "05-extends-loop-stress" \
    "${stress_dir}/loop-a.yaml" \
    "Circular policy extension detected"

  run_expected_policy_load_failure \
    "05-extends-depth-stress" \
    "${stress_dir}/depth-root.yaml" \
    "Policy extends depth exceeded"

  cat > "${REPORTS_DIR}/05-extends-depth-loop-stress.txt" <<EOF
Policy test: Policy Torture 05 - Extends Depth/Loop Stress
Cases:
  - extends-loop-stress: PASS (Circular policy extension detected)
  - extends-depth-stress: PASS (Policy extends depth exceeded)
Exit: 0
EOF

  cat > "${REPORTS_DIR}/05-extends-depth-loop-stress.json" <<EOF
{
  "name": "Policy Torture 05 - Extends Depth/Loop Stress",
  "total": 2,
  "passed": 2,
  "failed": 0,
  "cases": [
    {
      "name": "extends-loop-stress",
      "status": "pass",
      "expected_error": "Circular policy extension detected",
      "log": "rulesets/tests/policy-torture/reports/05-extends-loop-stress.log"
    },
    {
      "name": "extends-depth-stress",
      "status": "pass",
      "expected_error": "Policy extends depth exceeded",
      "log": "rulesets/tests/policy-torture/reports/05-extends-depth-stress.log"
    }
  ],
  "exit_code": 0
}
EOF
}

run_mixed_path_precedence_edge_case() {
  cargo test -p clawdstrike --lib \
    irm::fs::tests::filesystem_irm_prefers_object_path_over_pathlike_string_arg \
    -- --exact

  cat > "${REPORTS_DIR}/06-mixed-path-precedence.txt" <<EOF
Policy test: Policy Torture 06 - Mixed Path Token Precedence
Case:
  - filesystem_irm_prefers_object_path_over_pathlike_string_arg: PASS
Exit: 0
EOF

  cat > "${REPORTS_DIR}/06-mixed-path-precedence.json" <<EOF
{
  "name": "Policy Torture 06 - Mixed Path Token Precedence",
  "total": 1,
  "passed": 1,
  "failed": 0,
  "cases": [
    {
      "name": "filesystem_irm_prefers_object_path_over_pathlike_string_arg",
      "status": "pass",
      "command": "cargo test -p clawdstrike --lib irm::fs::tests::filesystem_irm_prefers_object_path_over_pathlike_string_arg -- --exact"
    }
  ],
  "exit_code": 0
}
EOF
}

run_suite() {
  local suite="$1"
  local report_base
  report_base="${REPORTS_DIR}/$(basename "$suite" .policy-test.yaml)"

  echo "=== Running $suite ==="
  "$BIN" policy test "$suite" \
    --resolve \
    --coverage \
    --format text \
    --output "${report_base}.txt"

  "$BIN" policy test "$suite" \
    --resolve \
    --coverage \
    --format json \
    --output "${report_base}.json"
}

run_suite rulesets/tests/policy-torture/suites/01-deep-merge.policy-test.yaml
run_suite rulesets/tests/policy-torture/suites/02-replace.policy-test.yaml
run_suite rulesets/tests/policy-torture/suites/03-posture-escalation.policy-test.yaml

# Gauntlet is hard-gated at 100% guard coverage.
"$BIN" policy test rulesets/tests/policy-torture/suites/04-guard-gauntlet.policy-test.yaml \
  --resolve \
  --coverage \
  --min-coverage 100 \
  --format text \
  --output rulesets/tests/policy-torture/reports/04-guard-gauntlet.txt

"$BIN" policy test rulesets/tests/policy-torture/suites/04-guard-gauntlet.policy-test.yaml \
  --resolve \
  --coverage \
  --min-coverage 100 \
  --format json \
  --output "${REPORTS_DIR}/04-guard-gauntlet.json"

run_extends_depth_loop_stress
run_mixed_path_precedence_edge_case

echo "All policy-torture suites completed successfully."
