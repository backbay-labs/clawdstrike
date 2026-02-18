#!/usr/bin/env python3
"""Pass #9 B3 validator for policy-event mapping."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #9 B3 policy-event mapping validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/policy-mapping/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass9-policy-event-mapping-report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def mapping_error(mapping: Dict[str, Any], key: str) -> str:
    codes = mapping.get("fail_closed_codes", {})
    default_map = {
        "mapping_invalid": "PEMAP_MAPPING_INVALID",
        "mapping_incomplete": "PEMAP_MAPPING_INCOMPLETE",
        "flow_unknown": "PEMAP_FLOW_UNKNOWN",
        "side_effect_unknown": "PEMAP_SIDE_EFFECT_UNKNOWN",
        "flow_side_effect_mismatch": "PEMAP_FLOW_SIDE_EFFECT_MISMATCH",
    }
    return codes.get(key, default_map[key])


def validate_mapping_structure(mapping: Dict[str, Any]) -> Optional[str]:
    required_top = {
        "mapping_id",
        "mapping_version",
        "required_flows",
        "required_side_effects",
        "flow_mappings",
        "fail_closed_codes",
        "defaults",
    }
    if not required_top.issubset(mapping.keys()):
        return mapping_error(mapping, "mapping_invalid")

    required_flows = mapping.get("required_flows")
    required_side_effects = mapping.get("required_side_effects")
    flow_mappings = mapping.get("flow_mappings")

    if not isinstance(required_flows, list) or not isinstance(required_side_effects, list):
        return mapping_error(mapping, "mapping_invalid")
    if not isinstance(flow_mappings, dict):
        return mapping_error(mapping, "mapping_invalid")

    seen_side_effects = set()

    for flow in required_flows:
        entry = flow_mappings.get(flow)
        if not isinstance(entry, dict):
            return mapping_error(mapping, "mapping_incomplete")

        side_effect = entry.get("side_effect")
        preflight = entry.get("preflight")
        post_action = entry.get("post_action")

        if not isinstance(side_effect, str):
            return mapping_error(mapping, "mapping_invalid")
        seen_side_effects.add(side_effect)

        if not isinstance(preflight, dict) or not isinstance(post_action, dict):
            return mapping_error(mapping, "mapping_invalid")

        if not isinstance(preflight.get("policy_event"), str):
            return mapping_error(mapping, "mapping_invalid")
        if preflight.get("fail_closed") is not True:
            return mapping_error(mapping, "mapping_invalid")

        guard_checks = preflight.get("guard_checks")
        if not isinstance(guard_checks, list) or len(guard_checks) == 0:
            return mapping_error(mapping, "mapping_incomplete")

        for g in guard_checks:
            if not isinstance(g, dict):
                return mapping_error(mapping, "mapping_invalid")
            if not isinstance(g.get("guard"), str) or not isinstance(g.get("stage"), str):
                return mapping_error(mapping, "mapping_invalid")

        if not isinstance(post_action.get("audit_event"), str):
            return mapping_error(mapping, "mapping_invalid")

        artifacts = post_action.get("receipt_artifacts")
        if not isinstance(artifacts, list) or len(artifacts) == 0:
            return mapping_error(mapping, "mapping_incomplete")
        if not all(isinstance(a, str) for a in artifacts):
            return mapping_error(mapping, "mapping_invalid")

    for side_effect in required_side_effects:
        if side_effect not in seen_side_effects:
            return mapping_error(mapping, "mapping_incomplete")

    return None


def resolve_query(mapping: Dict[str, Any], query: Dict[str, Any]) -> Dict[str, Any]:
    flow = query.get("flow")
    side_effect = query.get("side_effect")

    required_flows = set(mapping.get("required_flows", []))
    required_side_effects = set(mapping.get("required_side_effects", []))

    if flow not in required_flows:
        return {
            "result": "fail",
            "error_code": mapping_error(mapping, "flow_unknown"),
        }

    if side_effect is not None and side_effect not in required_side_effects:
        return {
            "result": "fail",
            "error_code": mapping_error(mapping, "side_effect_unknown"),
        }

    entry = mapping["flow_mappings"][flow]
    mapped_side_effect = entry["side_effect"]

    if side_effect is not None and side_effect != mapped_side_effect:
        return {
            "result": "fail",
            "error_code": mapping_error(mapping, "flow_side_effect_mismatch"),
        }

    guards: List[str] = [g["guard"] for g in entry["preflight"]["guard_checks"]]
    artifacts: List[str] = list(entry["post_action"]["receipt_artifacts"])

    return {
        "result": "pass",
        "flow": flow,
        "side_effect": mapped_side_effect,
        "policy_event": entry["preflight"]["policy_event"],
        "audit_event": entry["post_action"]["audit_event"],
        "guards": guards,
        "receipt_artifacts": artifacts,
    }


def expected_matches(expected: Dict[str, Any], actual: Dict[str, Any]) -> bool:
    if expected.get("result") != actual.get("result"):
        return False

    if expected.get("error_code") != actual.get("error_code"):
        return False

    for key in ("policy_event", "audit_event"):
        if key in expected and expected[key] != actual.get(key):
            return False

    expected_guards = expected.get("guards")
    if isinstance(expected_guards, list):
        if actual.get("guards") != expected_guards:
            return False

    expected_guard = expected.get("required_guard")
    if isinstance(expected_guard, str):
        if expected_guard not in (actual.get("guards") or []):
            return False

    expected_artifact = expected.get("required_artifact")
    if isinstance(expected_artifact, str):
        if expected_artifact not in (actual.get("receipt_artifacts") or []):
            return False

    return True


def main() -> int:
    args = parse_args()

    cases_path = (REPO_ROOT / args.cases).resolve()
    cases_doc = json.loads(cases_path.read_text(encoding="utf-8"))

    mapping_path = (REPO_ROOT / cases_doc["mapping"]).resolve()
    mapping = yaml.safe_load(mapping_path.read_text(encoding="utf-8"))

    report: Dict[str, Any] = {
        "mapping": str(mapping_path.relative_to(REPO_ROOT)),
        "results": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }

    structure_error = validate_mapping_structure(mapping)
    if structure_error is not None:
        report["summary"] = {"total": 1, "passed": 0, "failed": 1}
        report["results"].append(
            {
                "id": "mapping_structure",
                "ok": False,
                "expected": {"result": "pass"},
                "actual": {"result": "fail", "error_code": structure_error},
            }
        )
        report_path = (REPO_ROOT / args.report).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[FAIL] mapping_structure -> {{'result': 'fail', 'error_code': '{structure_error}'}}")
        print(f"\nSummary: 0/1 checks passed. Report: {report_path.relative_to(REPO_ROOT)}")
        return 1

    all_ok = True
    for case in cases_doc["cases"]:
        case_id = case["id"]
        query = case["query"]
        expected = case["expected"]

        actual = resolve_query(mapping, query)
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
