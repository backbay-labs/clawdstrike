#!/usr/bin/env python3
"""Pass #17 validator for remote-desktop matrix-to-ruleset alignment.

Validates that rulesets/remote-desktop.yaml enforces the feature defaults declared
in docs/roadmaps/cua/research/remote_desktop_policy_matrix.yaml for a fixed
threat tier + mode fixture profile.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]

SIDE_CHANNEL_FLAG_BY_FEATURE = {
    "clipboard": "clipboard_enabled",
    "file_transfer": "file_transfer_enabled",
    "audio": "audio_enabled",
    "drive_mapping": "drive_mapping_enabled",
    "printing": "printing_enabled",
    "session_share": "session_share_enabled",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run pass #17 remote desktop matrix-to-ruleset alignment validator"
    )
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/remote-desktop-ruleset-alignment/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass17-remote-desktop-ruleset-alignment-report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def as_dict(value: Any, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {} if default is None else default


def normalize_matrix_decision(matrix_decision: str) -> str:
    if matrix_decision in ("allow", "require_approval"):
        return "allow"
    return "deny"


def evaluate_case(
    matrix: Dict[str, Any],
    ruleset: Dict[str, Any],
    tier: str,
    mode: str,
    case: Dict[str, Any],
) -> Dict[str, Any]:
    query = as_dict(case.get("query"))
    expected = as_dict(case.get("expected"))

    feature = query.get("feature")
    if not isinstance(feature, str) or not feature:
        return {"result": "fail", "error_code": "RDS_CASE_QUERY_INVALID"}

    required_features = matrix.get("required_features")
    if not isinstance(required_features, list) or feature not in required_features:
        return {
            "result": "fail",
            "error_code": "RDS_FEATURE_UNKNOWN",
            "feature": feature,
        }

    tier_map = as_dict(matrix.get("threat_tiers"))
    tier_entry = as_dict(tier_map.get(tier))
    mode_map = as_dict(tier_entry.get("modes"))
    mode_entry = as_dict(mode_map.get(mode))

    matrix_decision = mode_entry.get(feature)
    if not isinstance(matrix_decision, str):
        return {
            "result": "fail",
            "error_code": "RDS_MATRIX_DECISION_MISSING",
            "feature": feature,
        }

    expected_effective = normalize_matrix_decision(matrix_decision)
    expected_decision = expected.get("decision")
    if expected_decision != expected_effective:
        return {
            "result": "fail",
            "error_code": "RDS_CASE_EXPECTATION_DRIFT",
            "feature": feature,
            "expected_decision": expected_decision,
            "matrix_decision": matrix_decision,
            "matrix_effective": expected_effective,
        }

    feature_defs = as_dict(matrix.get("feature_definitions"))
    feature_def = as_dict(feature_defs.get(feature))
    event_type = feature_def.get("policy_event")
    if not isinstance(event_type, str) or not event_type:
        return {
            "result": "fail",
            "error_code": "RDS_MATRIX_FEATURE_DEF_INVALID",
            "feature": feature,
        }

    guards = as_dict(ruleset.get("guards"))
    computer_use = as_dict(guards.get("computer_use"))
    allowed_actions = computer_use.get("allowed_actions")
    if not isinstance(allowed_actions, list):
        return {
            "result": "fail",
            "error_code": "RDS_RULESET_ALLOWED_ACTIONS_INVALID",
            "feature": feature,
        }

    side_channel = as_dict(guards.get("remote_desktop_side_channel"))
    side_flag_name = SIDE_CHANNEL_FLAG_BY_FEATURE.get(feature)
    side_flag_value = side_channel.get(side_flag_name) if side_flag_name is not None else None

    action_allowed = event_type in {str(v) for v in allowed_actions}
    side_guard_enabled = side_channel.get("enabled", True)
    side_allowed = True
    if side_flag_name is not None:
        if side_guard_enabled is False:
            side_allowed = False
        elif side_flag_value is False:
            side_allowed = False

    actual_decision = "allow" if (action_allowed and side_allowed) else "deny"

    if actual_decision != expected_effective:
        return {
            "result": "fail",
            "error_code": "RDS_RULESET_MATRIX_DRIFT",
            "feature": feature,
            "matrix_decision": matrix_decision,
            "expected_effective": expected_effective,
            "actual_decision": actual_decision,
            "event_type": event_type,
            "action_allowed": action_allowed,
            "side_channel_flag": side_flag_name,
            "side_channel_value": side_flag_value,
            "side_channel_enabled": side_guard_enabled,
        }

    return {
        "result": "pass",
        "feature": feature,
        "matrix_decision": matrix_decision,
        "actual_decision": actual_decision,
        "event_type": event_type,
    }


def main() -> int:
    args = parse_args()

    cases_path = (REPO_ROOT / args.cases).resolve()
    cases_doc = json.loads(cases_path.read_text(encoding="utf-8"))

    matrix_path = (REPO_ROOT / str(cases_doc.get("matrix", ""))).resolve()
    ruleset_path = (REPO_ROOT / str(cases_doc.get("ruleset", ""))).resolve()

    matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))
    ruleset = yaml.safe_load(ruleset_path.read_text(encoding="utf-8"))

    tier = cases_doc.get("tier")
    mode = cases_doc.get("mode")
    if not isinstance(tier, str) or not isinstance(mode, str):
        raise SystemExit("cases.json must define string fields: tier, mode")

    report = {
        "matrix": str(matrix_path.relative_to(REPO_ROOT)),
        "ruleset": str(ruleset_path.relative_to(REPO_ROOT)),
        "tier": tier,
        "mode": mode,
        "total": 0,
        "passed": 0,
        "failed": 0,
        "results": [],
    }

    failed = False
    for case in cases_doc.get("cases", []):
        case_id = case.get("id", "unknown")
        expected = as_dict(case.get("expected"))
        actual = evaluate_case(matrix, ruleset, tier, mode, as_dict(case))

        passed = expected.get("result") == actual.get("result")
        if expected.get("decision") is not None and actual.get("actual_decision") is not None:
            passed = passed and expected.get("decision") == actual.get("actual_decision")

        if not passed:
            failed = True

        report["total"] += 1
        report["passed"] += 1 if passed else 0
        report["failed"] += 0 if passed else 1
        report["results"].append(
            {
                "id": case_id,
                "expected": expected,
                "actual": actual,
                "pass": passed,
            }
        )

        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {case_id} -> {actual}")

    report_path = (REPO_ROOT / args.report).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    if failed:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
