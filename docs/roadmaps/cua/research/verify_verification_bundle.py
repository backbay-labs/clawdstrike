#!/usr/bin/env python3
"""Pass #12 D2 validator for end-to-end verification bundle format fixtures.

Runs deterministic checks over fixtures/receipts/verification-bundle/v1/cases.json
using the verification bundle format suite definition. Validates that bundles
containing receipt, attestation evidence, and verification transcript can be
verified by a third party without hidden context.

Fail-closed error codes:
  BDL_RECEIPT_MISSING          - bundle has no receipt
  BDL_TRANSCRIPT_INCOMPLETE    - transcript missing required checkpoint types
  BDL_ATTESTATION_TYPE_UNKNOWN - attestation type not in supported list
  BDL_CHECKPOINT_FAILED        - one or more checkpoints have status "fail"
  BDL_POLICY_REF_MISSING       - transcript has no policy_ref
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]

REQUIRED_RECEIPT_FIELDS = [
    "receipt_id",
    "version",
    "timestamp",
    "content_hash",
    "verdict",
    "signatures",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #12 D2 verification bundle validator")
    parser.add_argument(
        "--cases",
        default="fixtures/receipts/verification-bundle/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass12-verification-bundle-report.json",
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
        "bundle_structure",
        "checkpoint_schema",
        "fail_closed_codes",
    }
    if not required_top.issubset(suite.keys()):
        return "SUITE_STRUCTURE_INVALID"

    bundle_structure = suite.get("bundle_structure")
    if not isinstance(bundle_structure, dict):
        return "SUITE_STRUCTURE_INVALID"

    for section in ("receipt", "attestation_evidence", "verification_transcript"):
        section_def = bundle_structure.get(section)
        if not isinstance(section_def, dict):
            return "SUITE_STRUCTURE_INVALID"
        if not isinstance(section_def.get("required_fields"), list):
            return "SUITE_STRUCTURE_INVALID"

    attestation_def = bundle_structure.get("attestation_evidence", {})
    supported_types = attestation_def.get("supported_types")
    if not isinstance(supported_types, list) or not supported_types:
        return "SUITE_STRUCTURE_INVALID"

    transcript_def = bundle_structure.get("verification_transcript", {})
    checkpoint_types = transcript_def.get("checkpoint_types")
    if not isinstance(checkpoint_types, list) or not checkpoint_types:
        return "SUITE_STRUCTURE_INVALID"

    checkpoint_schema = suite.get("checkpoint_schema")
    if not isinstance(checkpoint_schema, dict):
        return "SUITE_STRUCTURE_INVALID"

    fail_closed = suite.get("fail_closed_codes")
    if not isinstance(fail_closed, dict):
        return "SUITE_STRUCTURE_INVALID"

    for key in (
        "receipt_missing",
        "transcript_incomplete",
        "attestation_type_unknown",
        "checkpoint_failed",
        "policy_ref_missing",
    ):
        if not isinstance(fail_closed.get(key), str) or not fail_closed.get(key):
            return "SUITE_STRUCTURE_INVALID"

    return None


def get_supported_attestation_types(suite: Dict[str, Any]) -> Set[str]:
    """Extract the set of supported attestation types from the suite."""
    attestation_def = suite.get("bundle_structure", {}).get("attestation_evidence", {})
    supported = attestation_def.get("supported_types", [])
    return set(supported) if isinstance(supported, list) else set()


def get_required_checkpoint_types(suite: Dict[str, Any]) -> Set[str]:
    """Extract the set of required checkpoint types from the suite."""
    transcript_def = suite.get("bundle_structure", {}).get("verification_transcript", {})
    types = transcript_def.get("checkpoint_types", [])
    return set(types) if isinstance(types, list) else set()


def get_receipt_required_fields(suite: Dict[str, Any]) -> List[str]:
    """Extract the list of required receipt fields from the suite."""
    receipt_def = suite.get("bundle_structure", {}).get("receipt", {})
    fields = receipt_def.get("required_fields", REQUIRED_RECEIPT_FIELDS)
    return fields if isinstance(fields, list) else REQUIRED_RECEIPT_FIELDS


def evaluate_bundle(
    suite: Dict[str, Any],
    case: Dict[str, Any],
) -> Tuple[str, Optional[str], Dict[str, Any]]:
    """Evaluate a single test case bundle against the suite rules.

    Returns (result, error_code, details).
    """
    receipt_missing = fail_code(suite, "receipt_missing", "BDL_RECEIPT_MISSING")
    transcript_incomplete = fail_code(suite, "transcript_incomplete", "BDL_TRANSCRIPT_INCOMPLETE")
    attestation_type_unknown = fail_code(suite, "attestation_type_unknown", "BDL_ATTESTATION_TYPE_UNKNOWN")
    checkpoint_failed = fail_code(suite, "checkpoint_failed", "BDL_CHECKPOINT_FAILED")
    policy_ref_missing = fail_code(suite, "policy_ref_missing", "BDL_POLICY_REF_MISSING")

    supported_attestation_types = get_supported_attestation_types(suite)
    required_checkpoint_types = get_required_checkpoint_types(suite)
    receipt_required_fields = get_receipt_required_fields(suite)

    bundle = case.get("bundle")
    if not isinstance(bundle, dict):
        return "fail", receipt_missing, {"reason": "bundle_not_dict"}

    # 1. Receipt presence and structure
    receipt = bundle.get("receipt")
    if receipt is None or not isinstance(receipt, dict):
        return "fail", receipt_missing, {"reason": "receipt_null_or_missing"}

    for field in receipt_required_fields:
        if field not in receipt:
            return "fail", receipt_missing, {"reason": f"receipt_missing_field_{field}"}

    # 2. Attestation evidence check
    attestation = bundle.get("attestation_evidence")
    if isinstance(attestation, dict):
        att_type = attestation.get("attestation_type")
        if att_type not in supported_attestation_types:
            return "fail", attestation_type_unknown, {"attestation_type": att_type}

    # 3. Verification transcript checks
    transcript = bundle.get("verification_transcript")
    if not isinstance(transcript, dict):
        return "fail", transcript_incomplete, {"reason": "transcript_not_dict"}

    # 3a. Policy reference
    policy_ref = transcript.get("policy_ref")
    if not isinstance(policy_ref, str) or not policy_ref:
        return "fail", policy_ref_missing, {"reason": "policy_ref_absent"}

    # 3b. Checkpoints presence and completeness
    checkpoints = transcript.get("checkpoints")
    if not isinstance(checkpoints, list):
        return "fail", transcript_incomplete, {"reason": "checkpoints_not_list"}

    present_types: Set[str] = set()
    for cp in checkpoints:
        if not isinstance(cp, dict):
            continue
        cp_type = cp.get("checkpoint_type")
        if isinstance(cp_type, str):
            present_types.add(cp_type)

    missing_types = required_checkpoint_types - present_types
    if missing_types:
        return "fail", transcript_incomplete, {
            "reason": "missing_checkpoint_types",
            "missing": sorted(missing_types),
        }

    # 3c. Checkpoint failure propagation
    for cp in checkpoints:
        if not isinstance(cp, dict):
            continue
        status = cp.get("status")
        if status == "fail":
            return "fail", checkpoint_failed, {
                "reason": "checkpoint_status_fail",
                "checkpoint_type": cp.get("checkpoint_type"),
            }

    return "pass", None, {"attestation_type": bundle.get("attestation_evidence", {}).get("attestation_type")}


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
        case_id = case["case_id"]
        expected_outcome = case["expected_outcome"]
        expected_error = case.get("expected_error_code")

        result, error_code, details = evaluate_bundle(suite, case)

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
                "expected": {
                    "result": expected_outcome,
                    "error_code": expected_error,
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
