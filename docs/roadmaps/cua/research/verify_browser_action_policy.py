#!/usr/bin/env python3
"""Pass #12 validator for browser action policy fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #12 browser action policy validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/browser-actions/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass12-browser-action-policy-report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def fail_code(suite: Dict[str, Any], key: str, default: str) -> str:
    fail_closed = suite.get("fail_closed_codes", {})
    if isinstance(fail_closed, dict):
        value = fail_closed.get(key)
        if isinstance(value, str) and value:
            return value
    return default


def validate_suite_structure(suite: Dict[str, Any]) -> Optional[str]:
    """Validate the suite YAML has all required top-level keys and correct structure."""
    required_top = {
        "suite_id",
        "suite_version",
        "browser_action_types",
        "selector_strategies",
        "required_evidence_fields",
        "protocol_types",
        "fail_closed_codes",
        "redaction",
    }
    if not required_top.issubset(suite.keys()):
        return "SUITE_STRUCTURE_INVALID"

    action_types = suite.get("browser_action_types")
    if not isinstance(action_types, list) or len(action_types) == 0:
        return "SUITE_STRUCTURE_INVALID"

    selector_strategies = suite.get("selector_strategies")
    if not isinstance(selector_strategies, list) or len(selector_strategies) == 0:
        return "SUITE_STRUCTURE_INVALID"

    # Verify canonical fallback order
    expected_order = ["ax_query", "stable_test_id", "css_selector", "coordinate"]
    if selector_strategies != expected_order:
        return "SUITE_STRUCTURE_INVALID"

    evidence_fields = suite.get("required_evidence_fields")
    if not isinstance(evidence_fields, list) or len(evidence_fields) == 0:
        return "SUITE_STRUCTURE_INVALID"
    for field in ("pre_hash", "action_record", "post_hash", "policy_decision_id",
                  "selector_strategy_used", "selector_strategy_reason"):
        if field not in evidence_fields:
            return "SUITE_STRUCTURE_INVALID"

    protocol_types = suite.get("protocol_types")
    if not isinstance(protocol_types, list) or len(protocol_types) == 0:
        return "SUITE_STRUCTURE_INVALID"

    fail_closed = suite.get("fail_closed_codes")
    if not isinstance(fail_closed, dict):
        return "SUITE_STRUCTURE_INVALID"
    for key in (
        "action_unknown",
        "selector_ambiguous",
        "protocol_unsupported",
        "evidence_incomplete",
        "replay_mismatch",
        "transport_failure",
    ):
        if not isinstance(fail_closed.get(key), str) or not fail_closed.get(key):
            return "SUITE_STRUCTURE_INVALID"

    redaction = suite.get("redaction")
    if not isinstance(redaction, dict):
        return "SUITE_STRUCTURE_INVALID"
    if redaction.get("default_sensitivity") != "sensitive":
        return "SUITE_STRUCTURE_INVALID"

    return None


def evaluate_action(
    suite: Dict[str, Any],
    action: Dict[str, Any],
) -> Tuple[str, Optional[str]]:
    """Evaluate a single browser action against the suite policy.

    Returns (outcome, error_code) where outcome is 'pass' or 'fail'.
    """
    action_types: List[str] = suite["browser_action_types"]
    protocol_types: List[str] = suite["protocol_types"]

    action_type = action.get("action_type")
    protocol = action.get("protocol")
    evidence = action.get("evidence", {})
    replay_evidence = action.get("replay_evidence")
    selector_strategy_used = action.get("selector_strategy_used")

    # 1. Fail closed on unknown action type
    if action_type not in action_types:
        return "fail", fail_code(suite, "action_unknown", "BRW_ACTION_UNKNOWN")

    # 2. Fail closed on unsupported protocol
    if protocol not in protocol_types:
        return "fail", fail_code(suite, "protocol_unsupported", "BRW_PROTOCOL_UNSUPPORTED")

    # 3. Fail closed on ambiguous selector (selector_strategy_used is None for
    #    actions that DO require a selector -- i.e., not navigate/screenshot/evaluate)
    actions_without_selector = {"navigate", "screenshot", "evaluate"}
    if action_type not in actions_without_selector:
        if selector_strategy_used is None:
            return "fail", fail_code(suite, "selector_ambiguous", "BRW_SELECTOR_AMBIGUOUS")

    # 4. Fail closed on incomplete evidence
    required_non_null = ["pre_hash", "action_record", "policy_decision_id"]
    # post_hash is always required
    required_non_null.append("post_hash")
    for field in required_non_null:
        if evidence.get(field) is None:
            return "fail", fail_code(suite, "evidence_incomplete", "BRW_EVIDENCE_INCOMPLETE")

    # 5. Replay mismatch detection
    if replay_evidence is not None:
        replay_post_hash = replay_evidence.get("post_hash")
        original_post_hash = evidence.get("post_hash")
        if replay_post_hash is not None and replay_post_hash != original_post_hash:
            return "fail", fail_code(suite, "replay_mismatch", "BRW_REPLAY_MISMATCH")

    return "pass", None


def expected_matches(
    expected_outcome: str,
    expected_error_code: Optional[str],
    actual_outcome: str,
    actual_error_code: Optional[str],
) -> bool:
    if expected_outcome != actual_outcome:
        return False
    if expected_error_code != actual_error_code:
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
        action = case["action"]
        case_expected_outcome = case["expected_outcome"]
        case_expected_error_code = case.get("expected_error_code")

        actual_outcome, actual_error_code = evaluate_action(suite, action)

        ok = expected_matches(
            case_expected_outcome,
            case_expected_error_code,
            actual_outcome,
            actual_error_code,
        )
        all_ok = all_ok and ok

        report["summary"]["total"] += 1
        if ok:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

        actual: Dict[str, Any] = {"result": actual_outcome}
        if actual_error_code is not None:
            actual["error_code"] = actual_error_code

        report["results"].append(
            {
                "id": case_id,
                "ok": ok,
                "expected": {
                    "result": case_expected_outcome,
                    **({"error_code": case_expected_error_code} if case_expected_error_code is not None else {}),
                },
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
