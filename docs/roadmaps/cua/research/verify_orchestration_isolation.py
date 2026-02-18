#!/usr/bin/env python3
"""Pass #12 validator for orchestration/containerization isolation fixtures."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #12 orchestration isolation validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/orchestration/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass12-orchestration-isolation-report.json",
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
    invalid = fail_code(suite, "suite_invalid", "ORC_SUITE_INVALID")

    required_top = {
        "suite_id",
        "suite_version",
        "research_ref",
        "isolation_tiers",
        "session_lifecycle_states",
        "launch_validation_fields",
        "side_effect_channels",
        "teardown_artifacts",
        "scenarios",
        "fail_closed_codes",
    }
    if not required_top.issubset(suite.keys()):
        return invalid

    tiers = suite.get("isolation_tiers")
    if not isinstance(tiers, list) or len(tiers) == 0:
        return invalid
    required_tiers = {
        "process",
        "container_runc",
        "sandboxed_container_gvisor",
        "microvm_firecracker",
        "full_vm_qemu",
    }
    if not required_tiers.issubset(set(tiers)):
        return invalid

    states = suite.get("session_lifecycle_states")
    if not isinstance(states, list) or len(states) == 0:
        return invalid
    required_states = {
        "pending_launch",
        "validating",
        "running",
        "teardown",
        "disposed",
    }
    if not required_states.issubset(set(states)):
        return invalid

    launch_fields = suite.get("launch_validation_fields")
    if not isinstance(launch_fields, list) or len(launch_fields) == 0:
        return invalid
    for field in ("runtime_policy_digest", "image_digest", "network_profile", "isolation_tier"):
        if field not in launch_fields:
            return invalid

    channels = suite.get("side_effect_channels")
    if not isinstance(channels, dict):
        return invalid
    broker = channels.get("broker_path")
    if not isinstance(broker, dict) or broker.get("allowed") is not True:
        return invalid
    for denied_channel in ("direct_filesystem", "direct_network", "direct_process"):
        ch = channels.get(denied_channel)
        if not isinstance(ch, dict) or ch.get("allowed") is not False:
            return invalid

    teardown_arts = suite.get("teardown_artifacts")
    if not isinstance(teardown_arts, list) or len(teardown_arts) == 0:
        return invalid
    for art in ("workspace_disposal_marker", "data_wipe_hash", "cleanup_timestamp"):
        if art not in teardown_arts:
            return invalid

    scenarios = suite.get("scenarios")
    if not isinstance(scenarios, dict) or len(scenarios) == 0:
        return invalid

    tiers_set = set(tiers)
    states_set = set(states)
    for scenario_name, scenario in scenarios.items():
        if not isinstance(scenario_name, str) or not isinstance(scenario, dict):
            return invalid
        tier = scenario.get("isolation_tier")
        end_state = scenario.get("lifecycle_end_state")
        expected_result = scenario.get("expected_result")
        reason_code = scenario.get("reason_code")
        # Unknown tiers are allowed in scenarios (that is the test), but known
        # tiers must be from the set, and unknown tiers must map to a fail scenario
        if expected_result not in {"pass", "fail"}:
            return invalid
        if not isinstance(reason_code, str) or not reason_code:
            return invalid
        if tier in tiers_set and end_state not in states_set:
            return invalid
        if tier not in tiers_set and expected_result != "fail":
            return invalid

    fail_closed = suite.get("fail_closed_codes")
    if not isinstance(fail_closed, dict):
        return invalid
    for key in (
        "suite_invalid",
        "tier_unknown",
        "launch_validation_failed",
        "direct_io_denied",
        "teardown_incomplete",
        "breakout_detected",
        "image_digest_mismatch",
        "scenario_unknown",
    ):
        if not isinstance(fail_closed.get(key), str) or not fail_closed.get(key):
            return invalid

    return None


def validate_launch(
    suite: Dict[str, Any],
    launch: Dict[str, Any],
) -> Optional[str]:
    """Validate launch parameters against suite constraints. Returns error code or None."""
    tier_unknown = fail_code(suite, "tier_unknown", "ORC_TIER_UNKNOWN")
    launch_failed = fail_code(suite, "launch_validation_failed", "ORC_LAUNCH_VALIDATION_FAILED")
    digest_mismatch = fail_code(suite, "image_digest_mismatch", "ORC_IMAGE_DIGEST_MISMATCH")

    tiers_set = set(suite["isolation_tiers"])

    tier = launch.get("isolation_tier")
    if tier not in tiers_set:
        return tier_unknown

    for field in ("runtime_policy_digest", "image_digest", "network_profile"):
        value = launch.get(field)
        if not isinstance(value, str) or not value:
            return launch_failed

    for digest_field in ("runtime_policy_digest", "image_digest"):
        value = launch.get(digest_field)
        if not DIGEST_RE.match(value):
            return launch_failed

    expected_digest = launch.get("expected_image_digest")
    if expected_digest is not None:
        actual_digest = launch.get("image_digest")
        if expected_digest != actual_digest:
            return digest_mismatch

    return None


def validate_side_effect_channel(
    suite: Dict[str, Any],
    channel: str,
) -> Optional[str]:
    """Validate that the side-effect channel is allowed. Returns error code or None."""
    direct_io_denied = fail_code(suite, "direct_io_denied", "ORC_DIRECT_IO_DENIED")

    channels = suite["side_effect_channels"]
    ch_def = channels.get(channel)
    if not isinstance(ch_def, dict):
        return direct_io_denied
    if ch_def.get("allowed") is not True:
        return direct_io_denied

    return None


def validate_teardown(
    suite: Dict[str, Any],
    teardown: Dict[str, Any],
) -> Optional[str]:
    """Validate teardown artifacts. Returns error code or None."""
    incomplete = fail_code(suite, "teardown_incomplete", "ORC_TEARDOWN_INCOMPLETE")

    if not teardown.get("workspace_disposal_marker"):
        return incomplete

    data_wipe = teardown.get("data_wipe_hash")
    if not isinstance(data_wipe, str) or not DIGEST_RE.match(data_wipe):
        return incomplete

    cleanup_ts = teardown.get("cleanup_timestamp")
    if not isinstance(cleanup_ts, str) or not cleanup_ts:
        return incomplete

    return None


def validate_breakout(
    suite: Dict[str, Any],
    breakout: Dict[str, Any],
) -> Optional[str]:
    """Detect breakout attempt. Always returns error code if breakout present."""
    detected = fail_code(suite, "breakout_detected", "ORC_BREAKOUT_DETECTED")

    if isinstance(breakout, dict) and breakout.get("type"):
        return detected

    return None


def evaluate_case(
    suite: Dict[str, Any],
    query: Dict[str, Any],
) -> Tuple[str, Optional[str], str, str]:
    """Evaluate a single case. Returns (result, error_code, lifecycle_state, reason_code)."""
    scenario_unknown = fail_code(suite, "scenario_unknown", "ORC_SCENARIO_UNKNOWN")

    scenarios = suite["scenarios"]
    scenario_name = query.get("scenario")

    if scenario_name not in scenarios:
        return "fail", scenario_unknown, "pending_launch", scenario_unknown

    scenario = scenarios[scenario_name]
    expected_lifecycle = scenario["lifecycle_end_state"]
    expected_reason = scenario["reason_code"]

    launch = query.get("launch")
    if not isinstance(launch, dict):
        launch_failed = fail_code(suite, "launch_validation_failed", "ORC_LAUNCH_VALIDATION_FAILED")
        return "fail", launch_failed, "pending_launch", launch_failed

    # Step 1: Validate launch parameters
    launch_error = validate_launch(suite, launch)
    if launch_error is not None:
        return "fail", launch_error, expected_lifecycle, launch_error

    # Step 2: Check for breakout attempts
    breakout = query.get("breakout_attempt")
    if breakout is not None:
        breakout_error = validate_breakout(suite, breakout)
        if breakout_error is not None:
            return "fail", breakout_error, expected_lifecycle, breakout_error

    # Step 3: Validate side-effect channel
    channel = query.get("side_effect_channel")
    if isinstance(channel, str):
        channel_error = validate_side_effect_channel(suite, channel)
        if channel_error is not None:
            return "fail", channel_error, expected_lifecycle, channel_error

    # Step 4: If teardown scenario, validate teardown artifacts
    teardown = query.get("teardown")
    if teardown is not None:
        teardown_error = validate_teardown(suite, teardown)
        if teardown_error is not None:
            return "fail", teardown_error, expected_lifecycle, teardown_error

    # All checks passed
    return "pass", None, expected_lifecycle, expected_reason


def expected_matches(
    expected: Dict[str, Any],
    result: str,
    error_code: Optional[str],
    lifecycle_state: str,
    reason_code: str,
) -> bool:
    if expected.get("result") != result:
        return False
    if expected.get("error_code") != error_code:
        return False
    if expected.get("lifecycle_state") != lifecycle_state:
        return False
    if expected.get("reason_code") != reason_code:
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
        query = case["query"]
        expected = case["expected"]

        result, error_code, lifecycle_state, reason_code = evaluate_case(suite, query)

        ok = expected_matches(expected, result, error_code, lifecycle_state, reason_code)
        all_ok = all_ok and ok

        report["summary"]["total"] += 1
        if ok:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

        actual: Dict[str, Any] = {
            "result": result,
            "lifecycle_state": lifecycle_state,
            "reason_code": reason_code,
        }
        if error_code is not None:
            actual["error_code"] = error_code

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
