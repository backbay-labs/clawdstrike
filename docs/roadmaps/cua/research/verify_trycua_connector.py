#!/usr/bin/env python3
"""Pass #14 validator for E4 trycua/cua connector evaluation.

Runs deterministic checks over fixtures/policy-events/trycua-connector/v1/cases.json
using the trycua connector suite definition. Validates that trycua actions map correctly
to canonical flow surfaces, and that unsupported/ambiguous/unknown actions fail closed.

Connector-specific fail-closed codes:
  TCC_ACTION_UNKNOWN       - trycua action type not in connector mapping
  TCC_FLOW_UNSUPPORTED     - canonical flow surface has no trycua equivalent
  TCC_DIRECTION_AMBIGUOUS  - cannot determine direction for bidirectional action
  TCC_EVIDENCE_MISSING     - required evidence fields not extractable
  TCC_SESSION_ID_MISSING   - cannot populate stable session identifier
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #14 E4 trycua connector validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/trycua-connector/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/trycua_connector_report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def fail_code(suite: Dict[str, Any], key: str, default: str) -> str:
    codes = suite.get("fail_closed_codes", {})
    if isinstance(codes, dict):
        code = codes.get(key)
        if isinstance(code, str) and code:
            return code
    return default


def validate_suite_structure(suite: Dict[str, Any]) -> Optional[str]:
    """Validate that the connector suite YAML has required structure."""
    required_top = {
        "suite_id",
        "suite_version",
        "canonical_flow_surfaces",
        "trycua_known_actions",
        "action_flow_map",
        "unsupported_flows",
        "flow_support_matrix",
        "required_output_fields",
        "fail_closed_codes",
    }
    if not required_top.issubset(suite.keys()):
        return "SUITE_STRUCTURE_INVALID"

    flow_surfaces = suite.get("canonical_flow_surfaces")
    if not isinstance(flow_surfaces, list) or not flow_surfaces:
        return "SUITE_STRUCTURE_INVALID"

    known_actions = suite.get("trycua_known_actions")
    if not isinstance(known_actions, list) or not known_actions:
        return "SUITE_STRUCTURE_INVALID"

    action_map = suite.get("action_flow_map")
    if not isinstance(action_map, dict):
        return "SUITE_STRUCTURE_INVALID"
    for action in known_actions:
        entry = action_map.get(action)
        if not isinstance(entry, dict):
            return "SUITE_STRUCTURE_INVALID"
        if "canonical_flow" not in entry:
            return "SUITE_STRUCTURE_INVALID"
        if "policy_event_ref" not in entry:
            return "SUITE_STRUCTURE_INVALID"
        if "cuaAction" not in entry:
            return "SUITE_STRUCTURE_INVALID"
        if "status" not in entry:
            return "SUITE_STRUCTURE_INVALID"

    unsupported = suite.get("unsupported_flows")
    if not isinstance(unsupported, list):
        return "SUITE_STRUCTURE_INVALID"

    flow_matrix = suite.get("flow_support_matrix")
    if not isinstance(flow_matrix, dict):
        return "SUITE_STRUCTURE_INVALID"
    for flow in flow_surfaces:
        if flow not in flow_matrix:
            return "SUITE_STRUCTURE_INVALID"

    fail_codes = suite.get("fail_closed_codes")
    if not isinstance(fail_codes, dict):
        return "SUITE_STRUCTURE_INVALID"
    for key in ("action_unknown", "flow_unsupported", "direction_ambiguous",
                "evidence_missing", "session_id_missing"):
        if not isinstance(fail_codes.get(key), str) or not fail_codes.get(key):
            return "SUITE_STRUCTURE_INVALID"

    return None


def translate_trycua_action(
    suite: Dict[str, Any],
    query: Dict[str, Any],
) -> Dict[str, Any]:
    """Translate a trycua action to canonical form using the suite mapping.

    Handles:
    - Unknown actions -> TCC_ACTION_UNKNOWN
    - Forced unsupported flows -> TCC_FLOW_UNSUPPORTED
    - Ambiguous direction (clipboard_sync without direction) -> TCC_DIRECTION_AMBIGUOUS
    - Missing evidence (file_copy without metadata) -> TCC_EVIDENCE_MISSING
    - Supported actions -> canonical event dict
    """
    trycua_action = query.get("trycua_action")
    trycua_input = query.get("trycua_input", {})
    force_flow = query.get("force_flow")

    known_actions = suite.get("trycua_known_actions", [])
    action_map = suite.get("action_flow_map", {})
    unsupported_flows = suite.get("unsupported_flows", [])

    # Check for forced unsupported flow first
    if force_flow is not None:
        if force_flow in unsupported_flows:
            return {
                "result": "fail",
                "error_code": fail_code(suite, "flow_unsupported", "TCC_FLOW_UNSUPPORTED"),
            }

    # Check action is known
    if trycua_action not in known_actions:
        return {
            "result": "fail",
            "error_code": fail_code(suite, "action_unknown", "TCC_ACTION_UNKNOWN"),
        }

    entry = action_map[trycua_action]

    # Check for direction ambiguity on clipboard_sync
    if trycua_action == "clipboard_sync":
        direction = trycua_input.get("direction")
        if direction is None:
            return {
                "result": "fail",
                "error_code": fail_code(suite, "direction_ambiguous", "TCC_DIRECTION_AMBIGUOUS"),
            }

    # Check for missing evidence on file_copy
    if trycua_action == "file_copy":
        has_path = "source_path" in trycua_input or "dest_path" in trycua_input
        has_hash = "file_hash" in trycua_input
        has_size = "file_size" in trycua_input
        if not (has_path and has_hash and has_size):
            return {
                "result": "fail",
                "error_code": fail_code(suite, "evidence_missing", "TCC_EVIDENCE_MISSING"),
            }

    canonical_flow = entry.get("canonical_flow")
    if canonical_flow is None:
        # Action exists but has no deterministic flow mapping
        return {
            "result": "fail",
            "error_code": fail_code(suite, "direction_ambiguous", "TCC_DIRECTION_AMBIGUOUS"),
        }

    return {
        "result": "pass",
        "canonical": {
            "flow": canonical_flow,
            "eventType": entry["policy_event_ref"],
            "data": {
                "cuaAction": entry["cuaAction"],
                "direction": entry.get("direction"),
            },
        },
    }


def expected_matches(expected: Dict[str, Any], actual: Dict[str, Any]) -> bool:
    """Check if the actual result matches expected."""
    if expected.get("result") != actual.get("result"):
        return False

    # Check error_code if present in expected
    if "error_code" in expected:
        if expected["error_code"] != actual.get("error_code"):
            return False

    # Check canonical output if present in expected
    expected_canonical = expected.get("canonical")
    actual_canonical = actual.get("canonical")
    if expected_canonical is not None:
        if actual_canonical is None:
            return False
        if expected_canonical.get("flow") != actual_canonical.get("flow"):
            return False
        if expected_canonical.get("eventType") != actual_canonical.get("eventType"):
            return False
        expected_data = expected_canonical.get("data", {})
        actual_data = actual_canonical.get("data", {})
        if expected_data.get("cuaAction") != actual_data.get("cuaAction"):
            return False
        if expected_data.get("direction") != actual_data.get("direction"):
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

        actual = translate_trycua_action(suite, case.get("query", {}))
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
