#!/usr/bin/env python3
"""Pass #11 D1 validator for repeatable latency harness benchmark fixtures."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #11 D1 repeatable latency harness validator")
    parser.add_argument(
        "--cases",
        default="fixtures/benchmarks/remote-latency/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass11-latency-harness-report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def fail_code(harness: Dict[str, Any], key: str, default: str) -> str:
    fail_closed = harness.get("fail_closed_codes", {})
    if isinstance(fail_closed, dict):
        code = fail_closed.get(key)
        if isinstance(code, str) and code:
            return code
    return default


def validate_harness_structure(harness: Dict[str, Any]) -> Optional[str]:
    required_top = {
        "schema_version",
        "harness_id",
        "harness_version",
        "host_classes",
        "codecs",
        "frame_sizes",
        "scenarios",
        "metrics",
        "reproducibility_thresholds",
        "required_environment_metadata",
        "fail_closed_codes",
    }
    if not required_top.issubset(harness.keys()):
        return "HARNESS_STRUCTURE_INVALID"

    if harness.get("schema_version") != "1.0.0":
        return "HARNESS_STRUCTURE_INVALID"

    for section in ("host_classes", "codecs", "frame_sizes", "scenarios"):
        if not isinstance(harness.get(section), dict) or not harness[section]:
            return "HARNESS_STRUCTURE_INVALID"

    metrics = harness.get("metrics")
    if not isinstance(metrics, list) or not metrics:
        return "HARNESS_STRUCTURE_INVALID"

    thresholds = harness.get("reproducibility_thresholds")
    if not isinstance(thresholds, dict):
        return "HARNESS_STRUCTURE_INVALID"
    for key in ("cv_max_warm", "cv_max_cold"):
        if not isinstance(thresholds.get(key), (int, float)):
            return "HARNESS_STRUCTURE_INVALID"

    env_fields = harness.get("required_environment_metadata")
    if not isinstance(env_fields, list) or not env_fields:
        return "HARNESS_STRUCTURE_INVALID"

    fail_closed = harness.get("fail_closed_codes")
    if not isinstance(fail_closed, dict):
        return "HARNESS_STRUCTURE_INVALID"
    for key in ("host_unknown", "codec_unknown", "frame_unknown", "variance_exceeded", "env_incomplete"):
        if not isinstance(fail_closed.get(key), str) or not fail_closed.get(key):
            return "HARNESS_STRUCTURE_INVALID"

    return None


def compute_cv(values: List[float]) -> float:
    """Compute coefficient of variation (std / mean). Returns inf if mean is zero."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    if mean == 0.0:
        return float("inf")
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    std = math.sqrt(variance)
    return std / mean


def evaluate_case(
    harness: Dict[str, Any],
    case: Dict[str, Any],
) -> Tuple[str, Optional[str], Dict[str, Any]]:
    host_unknown = fail_code(harness, "host_unknown", "LAT_HOST_UNKNOWN")
    codec_unknown = fail_code(harness, "codec_unknown", "LAT_CODEC_UNKNOWN")
    frame_unknown = fail_code(harness, "frame_unknown", "LAT_FRAME_UNKNOWN")
    variance_exceeded = fail_code(harness, "variance_exceeded", "LAT_VARIANCE_EXCEEDED")
    env_incomplete = fail_code(harness, "env_incomplete", "LAT_ENV_INCOMPLETE")

    host_class = case.get("host_class")
    codec = case.get("codec")
    frame_size = case.get("frame_size")
    scenario = case.get("scenario")
    environment = case.get("environment", {})
    runs = case.get("simulated_runs", [])

    allowed_hosts = set(harness.get("host_classes", {}).keys())
    allowed_codecs = set(harness.get("codecs", {}).keys())
    allowed_frames = set(harness.get("frame_sizes", {}).keys())

    # Fail-closed: unknown host class
    if host_class not in allowed_hosts:
        return "fail", host_unknown, {"host_class": host_class}

    # Fail-closed: unknown codec
    if codec not in allowed_codecs:
        return "fail", codec_unknown, {"codec": codec}

    # Fail-closed: unknown frame size
    if frame_size not in allowed_frames:
        return "fail", frame_unknown, {"frame_size": frame_size}

    # Fail-closed: incomplete environment metadata
    required_fields = harness.get("required_environment_metadata", [])
    missing_fields = [f for f in required_fields if f not in environment]
    if missing_fields:
        return "fail", env_incomplete, {"missing_fields": missing_fields}

    # Compute variance for each metric
    thresholds = harness.get("reproducibility_thresholds", {})
    if scenario == "cold_cache":
        cv_max = thresholds.get("cv_max_cold", 0.25)
    else:
        cv_max = thresholds.get("cv_max_warm", 0.15)

    metrics = harness.get("metrics", [])
    metric_cvs: Dict[str, float] = {}
    exceeded: List[Dict[str, Any]] = []

    for metric in metrics:
        values = [run.get(metric, 0.0) for run in runs if isinstance(run, dict)]
        cv = compute_cv(values)
        metric_cvs[metric] = round(cv, 6)
        if cv > cv_max:
            exceeded.append({"metric": metric, "cv": round(cv, 6), "threshold": cv_max})

    if exceeded:
        return "fail", variance_exceeded, {
            "scenario": scenario,
            "metric_cvs": metric_cvs,
            "exceeded": exceeded,
        }

    return "pass", None, {
        "scenario": scenario,
        "host_class": host_class,
        "codec": codec,
        "frame_size": frame_size,
        "metric_cvs": metric_cvs,
    }


def expected_matches(expected_outcome: str, expected_error: Optional[str], result: str, error_code: Optional[str]) -> bool:
    if expected_outcome != result:
        return False
    if expected_error != error_code:
        return False
    return True


def main() -> int:
    args = parse_args()

    cases_path = (REPO_ROOT / args.cases).resolve()
    cases_doc = json.loads(cases_path.read_text(encoding="utf-8"))

    harness_path = (REPO_ROOT / cases_doc["harness"]).resolve()
    harness = yaml.safe_load(harness_path.read_text(encoding="utf-8"))

    report: Dict[str, Any] = {
        "harness": str(harness_path.relative_to(REPO_ROOT)),
        "cases": str(cases_path.relative_to(REPO_ROOT)),
        "results": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }

    structure_error = validate_harness_structure(harness)
    if structure_error is not None:
        report["summary"] = {"total": 1, "passed": 0, "failed": 1}
        report["results"].append(
            {
                "id": "harness_structure",
                "ok": False,
                "expected": {"result": "pass"},
                "actual": {"result": "fail", "error_code": structure_error},
            }
        )
        report_path = (REPO_ROOT / args.report).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[FAIL] harness_structure -> {{'result': 'fail', 'error_code': '{structure_error}'}}")
        print(f"\nSummary: 0/1 checks passed. Report: {report_path.relative_to(REPO_ROOT)}")
        return 1

    all_ok = True
    for case in cases_doc["cases"]:
        case_id = case["case_id"]
        expected_outcome = case["expected_outcome"]
        expected_error = case.get("expected_error_code")

        result, error_code, details = evaluate_case(harness, case)

        ok = expected_matches(expected_outcome, expected_error, result, error_code)
        all_ok = all_ok and ok

        report["summary"]["total"] += 1
        if ok:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

        actual: Dict[str, Any] = {"result": result}
        if error_code is not None:
            actual["error_code"] = error_code
        if details:
            actual["details"] = details

        report["results"].append(
            {
                "id": case_id,
                "ok": ok,
                "expected": {"result": expected_outcome, "error_code": expected_error},
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
