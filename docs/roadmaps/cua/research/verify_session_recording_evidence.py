#!/usr/bin/env python3
"""Pass #12 validator for session recording evidence pipeline fixtures."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run pass #12 session recording evidence validator"
    )
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/session-recording/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass12-session-recording-evidence-report.json",
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


def validate_artifact(
    suite: Dict[str, Any], artifact: Dict[str, Any]
) -> Tuple[str, Optional[str]]:
    """Validate a single artifact against the suite rules.

    Returns (outcome, error_code).  outcome is "pass" or "fail".
    error_code is None on pass, otherwise one of the REC_* codes.
    """

    # --- 1. Artifact type must be known ---
    artifact_type = artifact.get("type")
    allowed_types: List[str] = suite.get("artifact_types", [])
    if artifact_type not in allowed_types:
        return "fail", fail_code(suite, "artifact_type_unknown", "REC_ARTIFACT_TYPE_UNKNOWN")

    # --- 2. Hash must be present ---
    artifact_hash = artifact.get("hash")
    if not isinstance(artifact_hash, str) or not artifact_hash:
        return "fail", fail_code(suite, "hash_missing", "REC_HASH_MISSING")

    # --- 3. Lossy-before-hash invariant ---
    if artifact.get("lossy_before_hash") is True:
        return "fail", fail_code(suite, "lossy_before_hash", "REC_LOSSY_BEFORE_HASH")

    # --- 4. Capture config completeness ---
    required_config_fields: List[str] = suite.get("capture_config_fields", [])
    capture_config = artifact.get("capture_config")
    if not isinstance(capture_config, dict):
        return "fail", fail_code(
            suite, "capture_config_incomplete", "REC_CAPTURE_CONFIG_INCOMPLETE"
        )
    for field in required_config_fields:
        if field not in capture_config:
            return "fail", fail_code(
                suite, "capture_config_incomplete", "REC_CAPTURE_CONFIG_INCOMPLETE"
            )

    # --- 5. Redaction provenance (required for redacted_frame) ---
    if artifact_type == "redacted_frame":
        required_prov_fields: List[str] = suite.get("redaction_provenance_fields", [])
        provenance = artifact.get("redaction_provenance")
        if not isinstance(provenance, dict):
            return "fail", fail_code(
                suite,
                "redaction_provenance_missing",
                "REC_REDACTION_PROVENANCE_MISSING",
            )
        for field in required_prov_fields:
            if field not in provenance or not provenance[field]:
                return "fail", fail_code(
                    suite,
                    "redaction_provenance_missing",
                    "REC_REDACTION_PROVENANCE_MISSING",
                )

    # --- 6. Manifest digest replay (when manifest_ref present) ---
    manifest_ref = artifact.get("manifest_ref")
    if isinstance(manifest_ref, dict):
        declared = manifest_ref.get("manifest_hash")
        recomputed = manifest_ref.get("recomputed_hash")
        if declared != recomputed:
            return "fail", fail_code(
                suite, "manifest_digest_mismatch", "REC_MANIFEST_DIGEST_MISMATCH"
            )

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
        "cases": str(cases_path.relative_to(REPO_ROOT)),
        "results": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }

    all_ok = True
    for case in cases_doc["cases"]:
        case_id = case["case_id"]
        artifact = case["artifact"]
        exp_outcome = case["expected_outcome"]
        exp_error = case.get("expected_error_code")

        actual_outcome, actual_error = validate_artifact(suite, artifact)

        ok = expected_matches(exp_outcome, exp_error, actual_outcome, actual_error)
        all_ok = all_ok and ok

        report["summary"]["total"] += 1
        if ok:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

        actual: Dict[str, Any] = {"outcome": actual_outcome}
        if actual_error is not None:
            actual["error_code"] = actual_error

        expected: Dict[str, Any] = {"outcome": exp_outcome}
        if exp_error is not None:
            expected["error_code"] = exp_error

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
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(
        f"\nSummary: {report['summary']['passed']}/{report['summary']['total']} checks passed. "
        f"Report: {report_path.relative_to(REPO_ROOT)}"
    )

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
