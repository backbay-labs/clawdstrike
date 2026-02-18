#!/usr/bin/env python3
"""Pass #11 C3 validator for envelope semantic equivalence fixtures.

Runs deterministic checks over fixtures/receipts/envelope-equivalence/v1/cases.json
using the envelope semantic equivalence suite definition. Validates that canonical
receipt payload fields are preserved identically across supported envelope wrapper
types (bare, cose_sign1, jws_compact, jws_json).

Fail-closed error codes:
  ENV_WRAPPER_UNKNOWN      - unrecognized wrapper type
  ENV_VERSION_MISMATCH     - receipt version not supported
  ENV_PAYLOAD_DIVERGENCE   - canonical fields differ between payload and envelope
  ENV_SIGNATURE_INVALID    - envelope signature verification failed
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]

CANONICAL_FIELDS = [
    "receipt_id",
    "timestamp",
    "content_hash",
    "verdict",
    "provenance",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #11 C3 envelope semantic equivalence validator")
    parser.add_argument(
        "--cases",
        default="fixtures/receipts/envelope-equivalence/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass11-envelope-equivalence-report.json",
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
        "supported_wrappers",
        "canonical_payload_fields",
        "receipt_version",
        "fail_closed_codes",
    }
    if not required_top.issubset(suite.keys()):
        return "SUITE_STRUCTURE_INVALID"

    wrappers = suite.get("supported_wrappers")
    if not isinstance(wrappers, list) or not wrappers:
        return "SUITE_STRUCTURE_INVALID"

    fields = suite.get("canonical_payload_fields")
    if not isinstance(fields, list) or not fields:
        return "SUITE_STRUCTURE_INVALID"

    fail_closed = suite.get("fail_closed_codes")
    if not isinstance(fail_closed, dict):
        return "SUITE_STRUCTURE_INVALID"

    for key in ("wrapper_unknown", "version_mismatch", "payload_divergence", "signature_invalid"):
        if not isinstance(fail_closed.get(key), str) or not fail_closed.get(key):
            return "SUITE_STRUCTURE_INVALID"

    return None


def decode_base64url(data: str) -> Optional[bytes]:
    """Decode base64url-encoded data, tolerating missing padding."""
    try:
        padded = data + "=" * (4 - len(data) % 4) if len(data) % 4 else data
        return base64.urlsafe_b64decode(padded)
    except Exception:
        return None


def extract_envelope_payload(
    wrapper_type: str,
    envelope: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Extract the payload dict from an envelope wrapper.

    Returns None if envelope is absent (bare) or extraction fails.
    """
    if envelope is None:
        return None

    if wrapper_type == "cose_sign1":
        raw = envelope.get("wrapper_payload")
        if not isinstance(raw, str):
            return None
        decoded = decode_base64url(raw)
        if decoded is None:
            return None
        try:
            return json.loads(decoded)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    elif wrapper_type == "jws_compact":
        token = envelope.get("compact_token")
        if not isinstance(token, str):
            return None
        parts = token.split(".")
        if len(parts) != 3:
            return None
        decoded = decode_base64url(parts[1])
        if decoded is None:
            return None
        try:
            return json.loads(decoded)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    elif wrapper_type == "jws_json":
        raw = envelope.get("payload")
        if not isinstance(raw, str):
            return None
        decoded = decode_base64url(raw)
        if decoded is None:
            return None
        try:
            return json.loads(decoded)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    return None


def validate_signature_present(
    wrapper_type: str,
    envelope: Optional[Dict[str, Any]],
    signature_corrupted: bool,
) -> bool:
    """Check whether the envelope has a syntactically valid signature.

    For the purposes of this deterministic harness, a signature is considered
    valid if it is present and not marked as corrupted. Real cryptographic
    verification would happen in a production verifier.
    """
    if signature_corrupted:
        return False

    if envelope is None:
        return True  # bare has no signature to check

    if wrapper_type == "cose_sign1":
        sig = envelope.get("signature")
        return isinstance(sig, str) and len(sig) > 0

    elif wrapper_type == "jws_compact":
        token = envelope.get("compact_token")
        if not isinstance(token, str):
            return False
        parts = token.split(".")
        return len(parts) == 3 and len(parts[2]) > 0

    elif wrapper_type == "jws_json":
        sigs = envelope.get("signatures")
        if not isinstance(sigs, list) or len(sigs) == 0:
            return False
        return all(isinstance(s.get("signature"), str) and len(s["signature"]) > 0 for s in sigs)

    return True


def compare_canonical_fields(
    declared: Dict[str, Any],
    extracted: Dict[str, Any],
    fields: List[str],
) -> bool:
    """Compare canonical payload fields between declared payload and extracted envelope payload."""
    for field in fields:
        declared_val = declared.get(field)
        extracted_val = extracted.get(field)
        if declared_val != extracted_val:
            return False
    return True


def evaluate_case(
    suite: Dict[str, Any],
    case: Dict[str, Any],
) -> Tuple[str, Optional[str], Dict[str, Any]]:
    """Evaluate a single test case against the suite rules.

    Returns (result, error_code, details).
    """
    wrapper_unknown = fail_code(suite, "wrapper_unknown", "ENV_WRAPPER_UNKNOWN")
    version_mismatch = fail_code(suite, "version_mismatch", "ENV_VERSION_MISMATCH")
    payload_divergence = fail_code(suite, "payload_divergence", "ENV_PAYLOAD_DIVERGENCE")
    signature_invalid = fail_code(suite, "signature_invalid", "ENV_SIGNATURE_INVALID")

    supported_wrappers = suite.get("supported_wrappers", [])
    canonical_fields = suite.get("canonical_payload_fields", CANONICAL_FIELDS)
    suite_receipt_version = suite.get("receipt_version", "1.0.0")

    wrapper_type = case.get("wrapper_type")
    payload = case.get("payload")
    envelope = case.get("envelope")
    version_override = case.get("receipt_version_override")
    signature_corrupted = case.get("signature_corrupted", False)

    # 1. Wrapper type check
    if wrapper_type not in supported_wrappers:
        return "fail", wrapper_unknown, {"wrapper_type": wrapper_type}

    # 2. Version check
    effective_version = version_override if version_override else suite_receipt_version
    if effective_version != suite_receipt_version:
        return "fail", version_mismatch, {"receipt_version": effective_version}

    # 3. Payload must be a dict with canonical fields
    if not isinstance(payload, dict):
        return "fail", payload_divergence, {"reason": "payload_not_dict"}

    for field in canonical_fields:
        if field not in payload:
            return "fail", payload_divergence, {"reason": f"missing_field_{field}"}

    # 4. For non-bare wrappers, extract and compare envelope payload
    if wrapper_type != "bare" and envelope is not None:
        # 4a. Signature check first
        if not validate_signature_present(wrapper_type, envelope, signature_corrupted):
            return "fail", signature_invalid, {"wrapper_type": wrapper_type}

        # 4b. Extract payload from envelope
        extracted = extract_envelope_payload(wrapper_type, envelope)
        if extracted is None:
            return "fail", payload_divergence, {"reason": "envelope_payload_extraction_failed"}

        # 4c. Compare canonical fields
        if not compare_canonical_fields(payload, extracted, canonical_fields):
            return "fail", payload_divergence, {"reason": "canonical_field_mismatch"}

    # 5. Cross-wrapper parity check
    cross_ref = case.get("cross_reference_bare")
    if isinstance(cross_ref, dict):
        if not compare_canonical_fields(payload, cross_ref, canonical_fields):
            return "fail", payload_divergence, {"reason": "cross_wrapper_parity_mismatch"}

    return "pass", None, {"wrapper_type": wrapper_type}


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

        result, error_code, details = evaluate_case(suite, case)

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
