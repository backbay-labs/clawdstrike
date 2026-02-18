#!/usr/bin/env python3
"""Pass #10 C1 validator for deterministic post-condition probe fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import jsonschema
import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #10 C1 post-condition probe validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/postcondition-probes/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass10-postcondition-probes-report.json",
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


def digest(seed: str) -> str:
    return f"sha256:{hashlib.sha256(seed.encode('utf-8')).hexdigest()}"


def validate_suite_structure(suite: Dict[str, Any], schema: Dict[str, Any], manifest: Dict[str, Any]) -> Optional[str]:
    invalid = fail_code(suite, "suite_invalid", "PRB_SUITE_INVALID")

    required_top = {
        "suite_id",
        "suite_version",
        "schema_ref",
        "capability_manifest_ref",
        "required_action_kinds",
        "state_classification",
        "scenarios",
        "fail_closed_codes",
        "probe_profiles",
    }
    if not required_top.issubset(suite.keys()):
        return invalid

    required_actions = suite.get("required_action_kinds")
    if not isinstance(required_actions, list) or len(required_actions) == 0:
        return invalid
    if len(required_actions) != len(set(required_actions)):
        return invalid
    if not all(isinstance(action, str) and action for action in required_actions):
        return invalid

    # C1 acceptance requires deterministic probes for these action kinds.
    for action in ("click", "type", "scroll", "key_chord"):
        if action not in required_actions:
            return invalid

    schema_states = set(
        schema.get("properties", {})
        .get("state", {})
        .get("enum", [])
    )
    if not schema_states:
        return invalid

    classification = suite.get("state_classification")
    if not isinstance(classification, dict):
        return invalid
    success_states = classification.get("success_states")
    failure_states = classification.get("failure_states")
    if not isinstance(success_states, list) or not isinstance(failure_states, list):
        return invalid
    if not all(isinstance(state, str) for state in success_states + failure_states):
        return invalid
    if set(success_states + failure_states) - schema_states:
        return invalid

    scenarios = suite.get("scenarios")
    if not isinstance(scenarios, dict) or len(scenarios) == 0:
        return invalid

    allowed_probe_status = {"pass", "fail", "skipped"}
    for scenario_id, scenario in scenarios.items():
        if not isinstance(scenario_id, str) or not isinstance(scenario, dict):
            return invalid
        final_state = scenario.get("final_state")
        reason_code = scenario.get("reason_code")
        probe_status = scenario.get("probe_status")
        if final_state not in (set(success_states) | set(failure_states)):
            return invalid
        if not isinstance(reason_code, str) or not reason_code:
            return invalid
        if probe_status not in allowed_probe_status:
            return invalid

    fail_closed = suite.get("fail_closed_codes")
    if not isinstance(fail_closed, dict):
        return invalid
    for key in (
        "suite_invalid",
        "action_unknown",
        "scenario_unknown",
        "invalid_outcome",
        "outcome_not_success",
    ):
        if not isinstance(fail_closed.get(key), str) or not fail_closed.get(key):
            return invalid

    probe_profiles = suite.get("probe_profiles")
    if not isinstance(probe_profiles, dict):
        return invalid
    for action in required_actions:
        profile = probe_profiles.get(action)
        if not isinstance(profile, dict):
            return invalid
        checks = profile.get("required_probe_checks")
        if not isinstance(checks, list) or len(checks) == 0:
            return invalid
        if not all(isinstance(check, str) and check for check in checks):
            return invalid

    if not isinstance(manifest.get("backends"), dict):
        return invalid

    return None


def build_outcome(
    *,
    suite: Dict[str, Any],
    schema: Dict[str, Any],
    manifest: Dict[str, Any],
    query: Dict[str, Any],
    timestamp: str,
) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
    action_unknown = fail_code(suite, "action_unknown", "PRB_ACTION_UNKNOWN")
    scenario_unknown = fail_code(suite, "scenario_unknown", "PRB_SCENARIO_UNKNOWN")
    invalid_outcome = fail_code(suite, "invalid_outcome", "PRB_INVALID_OUTCOME")
    not_success = fail_code(suite, "outcome_not_success", "PRB_OUTCOME_NOT_SUCCESS")
    suite_invalid = fail_code(suite, "suite_invalid", "PRB_SUITE_INVALID")

    action_kind = query.get("action_kind")
    scenario_name = query.get("scenario")
    backend_id = query.get("backend_id")
    target_mode = query.get("target_mode")

    required_actions = set(suite["required_action_kinds"])
    scenarios = suite["scenarios"]

    if action_kind not in required_actions:
        return "fail", action_unknown, None

    if scenario_name not in scenarios:
        return "fail", scenario_unknown, None

    backends = manifest.get("backends", {})
    backend = backends.get(backend_id)
    if not isinstance(backend, dict):
        return "fail", suite_invalid, None

    if not isinstance(target_mode, str) or not target_mode:
        return "fail", suite_invalid, None

    scenario = scenarios[scenario_name]
    final_state = scenario["final_state"]
    reason_code = scenario["reason_code"]

    profile = suite["probe_profiles"][action_kind]
    probe_checks = list(profile["required_probe_checks"])

    outcome: Dict[str, Any] = {
        "outcome_version": "1.0.0",
        "backend_id": backend_id,
        "platform": backend.get("platform", "cross_platform"),
        "action_kind": action_kind,
        "target_mode": target_mode,
        "state": final_state,
        "reason_code": reason_code,
        "timestamp": timestamp,
        "policy": {
            "event": "input.inject",
            "decision": "allow" if final_state in set(suite["state_classification"]["success_states"]) else "deny",
        },
        "evidence": {
            "pre_action_hash": digest(f"{backend_id}:{action_kind}:{scenario_name}:pre")
        },
        "probe": {
            "name": "postcondition_probe",
            "status": scenario["probe_status"],
            "detail": ",".join(probe_checks),
        },
        "details": {
            "message": f"post-condition scenario={scenario_name}",
            "extensions": {
                "scenario": scenario_name,
                "required_probe_checks": probe_checks,
            },
        },
        "timing_ms": {
            "accepted": 1.0,
        },
    }

    if final_state in {"applied", "verified"}:
        outcome["evidence"]["post_action_hash"] = digest(f"{backend_id}:{action_kind}:{scenario_name}:post")
        outcome["timing_ms"]["applied"] = 3.0
    if final_state == "verified":
        outcome["timing_ms"]["verified"] = 7.0

    try:
        jsonschema.validate(outcome, schema)
    except jsonschema.ValidationError:
        return "fail", invalid_outcome, None

    if final_state in set(suite["state_classification"]["success_states"]):
        return "pass", None, outcome

    return "fail", not_success, outcome


def expected_matches(
    expected: Dict[str, Any],
    result: str,
    error_code: Optional[str],
    outcome: Optional[Dict[str, Any]],
) -> bool:
    if expected.get("result") != result:
        return False

    if expected.get("error_code") != error_code:
        return False

    expected_outcome = expected.get("outcome")
    if isinstance(expected_outcome, dict):
        if not isinstance(outcome, dict):
            return False
        for key, value in expected_outcome.items():
            if outcome.get(key) != value:
                return False

    return True


def main() -> int:
    args = parse_args()

    cases_path = (REPO_ROOT / args.cases).resolve()
    cases_doc = json.loads(cases_path.read_text(encoding="utf-8"))

    suite_path = (REPO_ROOT / cases_doc["suite"]).resolve()
    suite = yaml.safe_load(suite_path.read_text(encoding="utf-8"))

    schema_path = (REPO_ROOT / suite["schema_ref"]).resolve()
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    manifest_path = (REPO_ROOT / suite["capability_manifest_ref"]).resolve()
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    report: Dict[str, Any] = {
        "suite": str(suite_path.relative_to(REPO_ROOT)),
        "schema": str(schema_path.relative_to(REPO_ROOT)),
        "manifest": str(manifest_path.relative_to(REPO_ROOT)),
        "results": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }

    structure_error = validate_suite_structure(suite, schema, manifest)
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

    timestamp = cases_doc.get("evaluation_context", {}).get("timestamp", "2026-02-18T00:00:00Z")

    all_ok = True
    for case in cases_doc["cases"]:
        case_id = case["id"]
        query = case["query"]
        expected = case["expected"]

        result, error_code, outcome = build_outcome(
            suite=suite,
            schema=schema,
            manifest=manifest,
            query=query,
            timestamp=timestamp,
        )

        ok = expected_matches(expected, result, error_code, outcome)
        all_ok = all_ok and ok

        report["summary"]["total"] += 1
        if ok:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

        actual: Dict[str, Any] = {"result": result}
        if error_code is not None:
            actual["error_code"] = error_code
        if outcome is not None:
            actual["outcome"] = {
                "state": outcome.get("state"),
                "reason_code": outcome.get("reason_code"),
            }

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
