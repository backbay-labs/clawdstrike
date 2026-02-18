#!/usr/bin/env python3
"""Pass #12 validator for CUA policy evaluation suite.

Runs deterministic checks over fixtures/policy-events/policy-evaluation/v1/cases.json
using the CUA policy evaluation suite definition. Validates that every CUA action
path resolves to a deterministic evaluation stage pipeline and guard result set,
approval tokens bind correctly, and unknown/invalid inputs fail closed.

Fail-closed error codes:
  POL_ACTION_UNKNOWN           - action not in suite action_paths
  POL_CONTEXT_MISSING          - required context field (session_id, agent_id) absent
  POL_APPROVAL_EXPIRED         - approval token past expiry window
  POL_APPROVAL_DIGEST_MISMATCH - current evidence digest differs from approval token digest
  POL_STAGE_UNRESOLVED         - action maps to zero guards across all stages
  POL_PARITY_VIOLATION         - cross-language parity check failed
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #12 CUA policy evaluation validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/policy-evaluation/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass12-cua-policy-evaluation-report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def fail_code(suite: Dict[str, Any], key: str, default: str) -> str:
    fail_closed = suite.get("fail_closed_codes", {})
    if isinstance(fail_closed, dict):
        code = fail_closed.get(key)
        if isinstance(code, str) and code:
            return code
    return default


def validate_suite_structure(suite: Dict[str, Any]) -> Optional[str]:
    """Validate that the suite YAML has required structure."""
    required_top = {
        "suite_id",
        "suite_version",
        "action_paths",
        "evaluation_stages",
        "action_stage_map",
        "approval_token",
        "enforcement_modes",
        "fail_closed_codes",
        "context_requirements",
    }
    if not required_top.issubset(suite.keys()):
        return "SUITE_STRUCTURE_INVALID"

    action_paths = suite.get("action_paths")
    if not isinstance(action_paths, list) or not action_paths:
        return "SUITE_STRUCTURE_INVALID"

    evaluation_stages = suite.get("evaluation_stages")
    if not isinstance(evaluation_stages, dict):
        return "SUITE_STRUCTURE_INVALID"
    for stage_name in ("fast_path", "std_path", "deep_path"):
        stage = evaluation_stages.get(stage_name)
        if not isinstance(stage, dict):
            return "SUITE_STRUCTURE_INVALID"
        if not isinstance(stage.get("guards"), list):
            return "SUITE_STRUCTURE_INVALID"

    action_stage_map = suite.get("action_stage_map")
    if not isinstance(action_stage_map, dict):
        return "SUITE_STRUCTURE_INVALID"
    for action in action_paths:
        entry = action_stage_map.get(action)
        if not isinstance(entry, dict):
            return "SUITE_STRUCTURE_INVALID"
        for stage_name in ("fast_path", "std_path", "deep_path"):
            if not isinstance(entry.get(stage_name), list):
                return "SUITE_STRUCTURE_INVALID"

    approval_token = suite.get("approval_token")
    if not isinstance(approval_token, dict):
        return "SUITE_STRUCTURE_INVALID"
    required_fields = approval_token.get("required_fields")
    if not isinstance(required_fields, list) or not required_fields:
        return "SUITE_STRUCTURE_INVALID"
    for field in ("evidence_digest", "policy_hash", "action_intent", "expiry_window_secs", "approver_identity"):
        if field not in required_fields:
            return "SUITE_STRUCTURE_INVALID"

    enforcement_modes = suite.get("enforcement_modes")
    if not isinstance(enforcement_modes, list):
        return "SUITE_STRUCTURE_INVALID"
    for mode in ("observe", "guardrail", "fail_closed"):
        if mode not in enforcement_modes:
            return "SUITE_STRUCTURE_INVALID"

    fail_closed_codes = suite.get("fail_closed_codes")
    if not isinstance(fail_closed_codes, dict):
        return "SUITE_STRUCTURE_INVALID"
    for key in ("action_unknown", "context_missing", "approval_expired",
                "approval_digest_mismatch", "stage_unresolved", "parity_violation"):
        if not isinstance(fail_closed_codes.get(key), str) or not fail_closed_codes.get(key):
            return "SUITE_STRUCTURE_INVALID"

    context_requirements = suite.get("context_requirements")
    if not isinstance(context_requirements, dict):
        return "SUITE_STRUCTURE_INVALID"
    if not isinstance(context_requirements.get("required_fields"), list):
        return "SUITE_STRUCTURE_INVALID"

    return None


def validate_context(suite: Dict[str, Any], context: Dict[str, Any]) -> Optional[str]:
    """Check that required context fields are present."""
    required = suite.get("context_requirements", {}).get("required_fields", [])
    for field in required:
        if field not in context or context[field] is None or context[field] == "":
            return fail_code(suite, "context_missing", "POL_CONTEXT_MISSING")
    return None


def validate_approval(suite: Dict[str, Any], approval: Dict[str, Any]) -> Optional[str]:
    """Check approval token bindings: expiry and digest match."""
    # Check expiry
    issued_at = approval.get("issued_at_epoch")
    current = approval.get("current_epoch")
    expiry_window = approval.get("expiry_window_secs")

    if isinstance(issued_at, (int, float)) and isinstance(current, (int, float)) and isinstance(expiry_window, (int, float)):
        elapsed = current - issued_at
        if elapsed > expiry_window:
            return fail_code(suite, "approval_expired", "POL_APPROVAL_EXPIRED")

    # Check evidence digest binding
    token_digest = approval.get("evidence_digest")
    current_digest = approval.get("current_evidence_digest")
    if isinstance(token_digest, str) and isinstance(current_digest, str):
        if token_digest != current_digest:
            return fail_code(suite, "approval_digest_mismatch", "POL_APPROVAL_DIGEST_MISMATCH")

    # Check policy hash binding
    token_policy = approval.get("policy_hash")
    current_policy = approval.get("current_policy_hash")
    if isinstance(token_policy, str) and isinstance(current_policy, str):
        if token_policy != current_policy:
            return fail_code(suite, "approval_digest_mismatch", "POL_APPROVAL_DIGEST_MISMATCH")

    return None


def resolve_stages(
    suite: Dict[str, Any],
    action: str,
    override_stage_map: Optional[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, List[str]]], Optional[str]]:
    """Resolve the evaluation stages for an action.

    Returns (stages_dict, error_code).
    """
    action_paths = suite.get("action_paths", [])
    if action not in action_paths:
        return None, fail_code(suite, "action_unknown", "POL_ACTION_UNKNOWN")

    # Use override stage map if provided (for testing unresolved stage)
    if override_stage_map is not None and action in override_stage_map:
        stage_map_entry = override_stage_map[action]
    else:
        action_stage_map = suite.get("action_stage_map", {})
        stage_map_entry = action_stage_map.get(action, {})

    stages: Dict[str, List[str]] = {
        "fast_path": list(stage_map_entry.get("fast_path", [])),
        "std_path": list(stage_map_entry.get("std_path", [])),
        "deep_path": list(stage_map_entry.get("deep_path", [])),
    }

    total_guards = sum(len(v) for v in stages.values())
    if total_guards == 0:
        return None, fail_code(suite, "stage_unresolved", "POL_STAGE_UNRESOLVED")

    return stages, None


def evaluate_case(
    suite: Dict[str, Any],
    case: Dict[str, Any],
) -> Tuple[str, Optional[str], Optional[Dict[str, List[str]]]]:
    """Evaluate a single test case against the suite rules.

    Returns (result, error_code, stages_resolved).
    """
    query = case.get("query", {})
    action = query.get("action")
    context = query.get("context", {})
    approval = query.get("approval")
    override_stage_map = query.get("override_stage_map")

    # 1. Validate context requirements
    context_err = validate_context(suite, context)
    if context_err is not None:
        return "fail", context_err, None

    # 2. Validate action is known and resolve stages
    stages, stage_err = resolve_stages(suite, action, override_stage_map)
    if stage_err is not None:
        return "fail", stage_err, None

    # 3. If approval token is present, validate its bindings
    if approval is not None and isinstance(approval, dict):
        approval_err = validate_approval(suite, approval)
        if approval_err is not None:
            return "fail", approval_err, None

    return "pass", None, stages


def expected_matches(expected: Dict[str, Any], actual: Dict[str, Any]) -> bool:
    """Check if the actual result matches expected."""
    if expected.get("result") != actual.get("result"):
        return False

    if expected.get("error_code") != actual.get("error_code"):
        return False

    expected_stages = expected.get("stages_resolved")
    actual_stages = actual.get("stages_resolved")

    if expected_stages is not None and actual_stages is not None:
        for stage_name in ("fast_path", "std_path", "deep_path"):
            expected_guards = expected_stages.get(stage_name, [])
            actual_guards = actual_stages.get(stage_name, [])
            if expected_guards != actual_guards:
                return False
    elif expected_stages is None and actual_stages is not None:
        return False
    elif expected_stages is not None and actual_stages is None:
        return False

    return True


def main() -> int:
    args = parse_args()

    cases_path = (REPO_ROOT / args.cases).resolve()
    cases_doc = json.loads(cases_path.read_text(encoding="utf-8"))

    suite_path = (REPO_ROOT / cases_doc["suite"]).resolve()
    suite = yaml.safe_load(suite_path.read_text(encoding="utf-8"))

    report: Dict[str, Any] = {
        "suite": str(suite_path.relative_to(REPO_ROOT)),
        "results": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }

    # Validate suite structure first
    structure_error = validate_suite_structure(suite)
    if structure_error is not None:
        report["summary"] = {"total": 1, "passed": 0, "failed": 1}
        report["results"].append(
            {
                "id": "suite_structure",
                "ok": False,
                "expected": {"result": "pass"},
                "actual": {"result": "fail", "error_code": structure_error},
            }
        )
        report_path = (REPO_ROOT / args.report).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[FAIL] suite_structure -> {{'result': 'fail', 'error_code': '{structure_error}'}}")
        print(f"\nSummary: 0/1 checks passed. Report: {report_path.relative_to(REPO_ROOT)}")
        return 1

    all_ok = True
    for case in cases_doc["cases"]:
        case_id = case["id"]
        expected = case["expected"]

        result, error_code, stages_resolved = evaluate_case(suite, case)

        actual: Dict[str, Any] = {"result": result}
        if error_code is not None:
            actual["error_code"] = error_code
        else:
            actual["error_code"] = None
        if stages_resolved is not None:
            actual["stages_resolved"] = stages_resolved
        else:
            actual["stages_resolved"] = None

        ok = expected_matches(expected, actual)
        all_ok = all_ok and ok

        report["summary"]["total"] += 1
        if ok:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

        report["results"].append(
            {
                "id": case_id,
                "ok": ok,
                "expected": expected,
                "actual": actual,
            }
        )

        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {case_id} -> {actual}")

    report_path = (REPO_ROOT / args.report).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        f"\nSummary: {report['summary']['passed']}/{report['summary']['total']} checks passed. "
        f"Report: {report_path.relative_to(REPO_ROOT)}"
    )

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
