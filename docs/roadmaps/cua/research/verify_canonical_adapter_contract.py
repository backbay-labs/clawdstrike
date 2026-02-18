#!/usr/bin/env python3
"""Pass #13 validator for canonical adapter-core CUA contract.

Runs deterministic checks over fixtures/policy-events/adapter-contract/v1/cases.json
using the canonical adapter CUA contract suite definition. Validates that every
adapter output resolves to a valid flow surface, canonical outcome, recognized
reason code, bound policy event reference, and well-formed guard result set.
Unknown flows, invalid outcomes, missing policy refs, malformed guard results,
and unrecognized reason codes fail closed with stable error codes.

Fail-closed error codes:
  ADC_FLOW_UNKNOWN           - flow not in suite flow_surfaces
  ADC_OUTCOME_INVALID        - outcome not in suite canonical_outcomes
  ADC_MISSING_POLICY_REF     - policy_event_ref is null or empty
  ADC_GUARD_RESULT_MALFORMED - guard_results entry missing guard or decision
  ADC_REASON_CODE_UNKNOWN    - reason_code not in suite reason_codes
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #13 canonical adapter contract validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/adapter-contract/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass13-canonical-adapter-contract-report.json",
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
        "flow_surfaces",
        "canonical_outcomes",
        "reason_codes",
        "required_adapter_output_fields",
        "flow_policy_event_map",
        "fail_closed_codes",
    }
    if not required_top.issubset(suite.keys()):
        return "SUITE_STRUCTURE_INVALID"

    flow_surfaces = suite.get("flow_surfaces")
    if not isinstance(flow_surfaces, list) or not flow_surfaces:
        return "SUITE_STRUCTURE_INVALID"

    canonical_outcomes = suite.get("canonical_outcomes")
    if not isinstance(canonical_outcomes, list) or not canonical_outcomes:
        return "SUITE_STRUCTURE_INVALID"
    for outcome in ("accepted", "applied", "verified", "denied", "unknown"):
        if outcome not in canonical_outcomes:
            return "SUITE_STRUCTURE_INVALID"

    reason_codes = suite.get("reason_codes")
    if not isinstance(reason_codes, list) or not reason_codes:
        return "SUITE_STRUCTURE_INVALID"
    for rc in (
        "ADC_POLICY_ALLOW",
        "ADC_POLICY_WARN",
        "ADC_POLICY_DENY",
        "ADC_GUARD_ERROR",
        "ADC_PROBE_VERIFIED",
        "ADC_PROBE_FAILED",
    ):
        if rc not in reason_codes:
            return "SUITE_STRUCTURE_INVALID"

    required_fields = suite.get("required_adapter_output_fields")
    if not isinstance(required_fields, list) or not required_fields:
        return "SUITE_STRUCTURE_INVALID"
    for field in ("flow", "outcome", "reason_code", "policy_event_ref", "guard_results", "audit_ref"):
        if field not in required_fields:
            return "SUITE_STRUCTURE_INVALID"

    flow_policy_event_map = suite.get("flow_policy_event_map")
    if not isinstance(flow_policy_event_map, dict):
        return "SUITE_STRUCTURE_INVALID"
    for flow in flow_surfaces:
        entry = flow_policy_event_map.get(flow)
        if not isinstance(entry, dict):
            return "SUITE_STRUCTURE_INVALID"
        if not isinstance(entry.get("policy_event_ref"), str):
            return "SUITE_STRUCTURE_INVALID"
        if not isinstance(entry.get("guard_expectations"), list):
            return "SUITE_STRUCTURE_INVALID"

    fail_closed_codes = suite.get("fail_closed_codes")
    if not isinstance(fail_closed_codes, dict):
        return "SUITE_STRUCTURE_INVALID"
    for key in ("flow_unknown", "outcome_invalid", "missing_policy_ref",
                "guard_result_malformed", "reason_code_unknown"):
        if not isinstance(fail_closed_codes.get(key), str) or not fail_closed_codes.get(key):
            return "SUITE_STRUCTURE_INVALID"

    return None


def validate_flow(suite: Dict[str, Any], flow: str) -> Optional[str]:
    """Check that the flow is a recognized flow surface."""
    flow_surfaces = suite.get("flow_surfaces", [])
    if flow not in flow_surfaces:
        return fail_code(suite, "flow_unknown", "ADC_FLOW_UNKNOWN")
    return None


def validate_outcome(suite: Dict[str, Any], outcome: str) -> Optional[str]:
    """Check that the outcome is a canonical outcome."""
    canonical_outcomes = suite.get("canonical_outcomes", [])
    if outcome not in canonical_outcomes:
        return fail_code(suite, "outcome_invalid", "ADC_OUTCOME_INVALID")
    return None


def validate_reason_code(suite: Dict[str, Any], reason_code: str) -> Optional[str]:
    """Check that the reason code is recognized."""
    reason_codes = suite.get("reason_codes", [])
    if reason_code not in reason_codes:
        return fail_code(suite, "reason_code_unknown", "ADC_REASON_CODE_UNKNOWN")
    return None


def validate_policy_event_ref(suite: Dict[str, Any], policy_event_ref: Any) -> Optional[str]:
    """Check that the policy_event_ref is present and non-empty."""
    if policy_event_ref is None or (isinstance(policy_event_ref, str) and policy_event_ref == ""):
        return fail_code(suite, "missing_policy_ref", "ADC_MISSING_POLICY_REF")
    return None


def validate_guard_results(suite: Dict[str, Any], guard_results: Any) -> Optional[str]:
    """Check that guard_results entries are well-formed."""
    if not isinstance(guard_results, list):
        return fail_code(suite, "guard_result_malformed", "ADC_GUARD_RESULT_MALFORMED")
    for entry in guard_results:
        if not isinstance(entry, dict):
            return fail_code(suite, "guard_result_malformed", "ADC_GUARD_RESULT_MALFORMED")
        if not isinstance(entry.get("guard"), str) or not entry.get("guard"):
            return fail_code(suite, "guard_result_malformed", "ADC_GUARD_RESULT_MALFORMED")
        if not isinstance(entry.get("decision"), str) or not entry.get("decision"):
            return fail_code(suite, "guard_result_malformed", "ADC_GUARD_RESULT_MALFORMED")
    return None


def resolve_adapter_output(
    suite: Dict[str, Any],
    flow: str,
    guard_results: List[Dict[str, str]],
) -> Tuple[Optional[str], Optional[List[str]]]:
    """Resolve the expected policy event and guard names for a valid flow.

    Returns (policy_event_ref, guard_names).
    """
    flow_map = suite.get("flow_policy_event_map", {})
    entry = flow_map.get(flow, {})
    policy_event_ref = entry.get("policy_event_ref")
    guard_names = [g["guard"] for g in guard_results]
    return policy_event_ref, guard_names


def evaluate_case(
    suite: Dict[str, Any],
    case: Dict[str, Any],
) -> Tuple[str, Optional[str], Optional[str], Optional[List[str]]]:
    """Evaluate a single test case against the suite rules.

    Returns (result, error_code, resolved_policy_event, resolved_guards).
    """
    query = case.get("query", {})
    flow = query.get("flow", "")
    outcome = query.get("outcome", "")
    reason_code = query.get("reason_code", "")
    policy_event_ref = query.get("policy_event_ref")
    guard_results = query.get("guard_results", [])

    # 1. Validate flow surface
    flow_err = validate_flow(suite, flow)
    if flow_err is not None:
        return "fail", flow_err, None, None

    # 2. Validate outcome
    outcome_err = validate_outcome(suite, outcome)
    if outcome_err is not None:
        return "fail", outcome_err, None, None

    # 3. Validate reason code
    reason_err = validate_reason_code(suite, reason_code)
    if reason_err is not None:
        return "fail", reason_err, None, None

    # 4. Validate policy event ref
    ref_err = validate_policy_event_ref(suite, policy_event_ref)
    if ref_err is not None:
        return "fail", ref_err, None, None

    # 5. Validate guard results structure
    guard_err = validate_guard_results(suite, guard_results)
    if guard_err is not None:
        return "fail", guard_err, None, None

    # 6. Resolve adapter output
    resolved_event, resolved_guards = resolve_adapter_output(suite, flow, guard_results)

    return "pass", None, resolved_event, resolved_guards


def expected_matches(expected: Dict[str, Any], actual: Dict[str, Any]) -> bool:
    """Check if the actual result matches expected."""
    if expected.get("result") != actual.get("result"):
        return False

    if expected.get("error_code") != actual.get("error_code"):
        return False

    expected_event = expected.get("resolved_policy_event")
    actual_event = actual.get("resolved_policy_event")
    if expected_event != actual_event:
        return False

    expected_guards = expected.get("resolved_guards")
    actual_guards = actual.get("resolved_guards")
    if expected_guards != actual_guards:
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

        result, error_code, resolved_event, resolved_guards = evaluate_case(suite, case)

        actual: Dict[str, Any] = {"result": result}
        actual["error_code"] = error_code
        actual["resolved_policy_event"] = resolved_event
        actual["resolved_guards"] = resolved_guards

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
