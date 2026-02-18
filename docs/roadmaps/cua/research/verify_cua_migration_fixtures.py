#!/usr/bin/env python3
"""Pass #8 verifier harness for CUA migration fixtures.

Runs deterministic checks over fixtures/receipts/cua-migration/cases.json using:
- verifier flow spec (ordering and stable VFY_* error codes)
- attestation verifier policy (AVP_* subcodes)
- versioned CUA metadata schema package
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import jsonschema
import yaml

import sys

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "packages/sdk/hush-py/src"))

from clawdstrike.receipt import PublicKeySet, SignedReceipt, validate_receipt_version  # noqa: E402


ALLOWED_RECEIPT_KEYS = {
    "version",
    "receipt_id",
    "timestamp",
    "content_hash",
    "verdict",
    "provenance",
    "metadata",
}

ALLOWED_SIGNATURE_KEYS = {"signer", "cosigner"}
ALLOWED_VERDICT_KEYS = {"passed", "gate_id", "scores", "threshold"}


@dataclass
class VerifyOutcome:
    result: str
    error_code: Optional[str] = None
    policy_subcode: Optional[str] = None
    verdict_passed: Optional[bool] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"result": self.result}
        if self.error_code is not None:
            out["error_code"] = self.error_code
        if self.policy_subcode is not None:
            out["policy_subcode"] = self.policy_subcode
        if self.verdict_passed is not None:
            out["verdict_passed"] = self.verdict_passed
        return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #8 verifier harness")
    parser.add_argument(
        "--cases",
        default="fixtures/receipts/cua-migration/cases.json",
        help="Path to cases.json",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass8-verifier-harness-report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def parse_iso8601(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


def get_path(obj: Dict[str, Any], dotted_path: str) -> Any:
    cur: Any = obj
    for part in dotted_path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def check_allowed_keys(obj: Dict[str, Any], allowed: set[str]) -> bool:
    return set(obj.keys()).issubset(allowed)


def shape_validate_signed_receipt(doc: Dict[str, Any]) -> bool:
    if not isinstance(doc, dict):
        return False
    if set(doc.keys()) != {"receipt", "signatures"}:
        return False

    receipt = doc.get("receipt")
    signatures = doc.get("signatures")
    if not isinstance(receipt, dict) or not isinstance(signatures, dict):
        return False

    if not check_allowed_keys(receipt, ALLOWED_RECEIPT_KEYS):
        return False
    if not check_allowed_keys(signatures, ALLOWED_SIGNATURE_KEYS):
        return False

    for req in ("version", "timestamp", "content_hash", "verdict"):
        if req not in receipt:
            return False

    if not isinstance(receipt.get("version"), str):
        return False
    if not isinstance(receipt.get("timestamp"), str):
        return False
    if not isinstance(receipt.get("content_hash"), str):
        return False

    verdict = receipt.get("verdict")
    if not isinstance(verdict, dict):
        return False
    if not check_allowed_keys(verdict, ALLOWED_VERDICT_KEYS):
        return False
    if not isinstance(verdict.get("passed"), bool):
        return False

    if not isinstance(signatures.get("signer"), str):
        return False
    if "cosigner" in signatures and signatures["cosigner"] is not None and not isinstance(
        signatures["cosigner"], str
    ):
        return False

    return True


def resolve_cua_schema_path(
    schema_package: Dict[str, Any], receipt_profile: str, schema_version: str
) -> Optional[Path]:
    supported = schema_package.get("supported", [])
    for entry in supported:
        if (
            isinstance(entry, dict)
            and entry.get("receipt_profile") == receipt_profile
            and entry.get("version") == schema_version
            and isinstance(entry.get("schema"), str)
        ):
            return (REPO_ROOT / "docs/roadmaps/cua/research/schemas/cua-metadata" / entry["schema"]).resolve()
    return None


def evaluate_attestation_policy(
    metadata: Dict[str, Any],
    policy: Dict[str, Any],
    verified_at: datetime,
) -> Tuple[str, Optional[str]]:
    def deny(subcode_key: str) -> Tuple[str, Optional[str]]:
        return (
            "deny",
            policy.get("error_codes", {}).get(subcode_key, "AVP_UNSPECIFIED"),
        )

    def policy_lookup(path: str) -> Any:
        # Policy paths are rooted at "metadata.*"; this evaluator already receives metadata.
        if path.startswith("metadata."):
            path = path[len("metadata.") :]
        return get_path(metadata, path)

    attestation = get_path(metadata, "cua.gateway.attestation")
    if not isinstance(attestation, dict):
        return deny("missing_required_claim")

    issuer = attestation.get("issuer")
    attestation_type = attestation.get("type")
    nonce = attestation.get("nonce")
    issued_at_raw = attestation.get("issued_at")
    not_before_raw = attestation.get("not_before")
    expires_at_raw = attestation.get("expires_at")

    if not all(isinstance(v, str) for v in [issuer, attestation_type, nonce, issued_at_raw, not_before_raw, expires_at_raw]):
        return deny("missing_required_claim")

    allowlist = policy.get("issuers", {}).get("allowlist", [])
    issuer_rule = None
    for entry in allowlist:
        if isinstance(entry, dict) and entry.get("issuer") == issuer:
            issuer_rule = entry
            break
    if issuer_rule is None:
        return deny("unknown_issuer")

    allowed_types = issuer_rule.get("attestation_types", [])
    if attestation_type not in allowed_types:
        return deny("attestation_type_not_allowed")

    key_id = get_path(metadata, "cua.gateway.key_id")
    allowed_key_ids = issuer_rule.get("allowed_key_ids", [])
    if key_id not in allowed_key_ids:
        return deny("key_id_not_allowed")

    # Required claim paths
    for claim_path in policy.get("claims", {}).get("required_paths", []):
        if not isinstance(claim_path, str) or policy_lookup(claim_path) is None:
            return deny("missing_required_claim")

    claim_nonce_path = get_path(policy, "claims.enforce_claim_equals_nonce.claim_path")
    att_nonce_path = get_path(policy, "claims.enforce_claim_equals_nonce.nonce_path")
    if isinstance(claim_nonce_path, str) and isinstance(att_nonce_path, str):
        claim_nonce = policy_lookup(claim_nonce_path)
        att_nonce = policy_lookup(att_nonce_path)
        if claim_nonce != att_nonce:
            return deny("claim_nonce_mismatch")

    schema_version_path = policy.get("claims", {}).get("schema_version_path")
    if not isinstance(schema_version_path, str):
        return deny("missing_required_claim")
    schema_version = policy_lookup(schema_version_path)
    if schema_version not in policy.get("claims", {}).get("allowed_schema_versions", []):
        return deny("missing_required_claim")

    claims_ext = get_path(metadata, "cua.gateway.attestation.claims.extensions")
    required_claims = issuer_rule.get("required_claims", {})
    for k, v in required_claims.items():
        if not isinstance(claims_ext, dict) or claims_ext.get(k) != v:
            return deny("missing_required_claim")

    try:
        issued_at = parse_iso8601(issued_at_raw)
        not_before = parse_iso8601(not_before_raw)
        expires_at = parse_iso8601(expires_at_raw)
    except ValueError:
        return deny("clock_skew_exceeded")

    max_skew = int(policy.get("clock", {}).get("max_skew_seconds", 0))
    max_age = int(policy.get("nonce", {}).get("max_age_seconds", 0))
    max_future = int(policy.get("nonce", {}).get("max_future_skew_seconds", 0))

    # not_before / expires_at window with skew
    if (verified_at.timestamp() + max_skew) < not_before.timestamp():
        return deny("attestation_not_yet_valid")
    if (verified_at.timestamp() - max_skew) > expires_at.timestamp():
        return deny("attestation_expired")

    age_seconds = (verified_at - issued_at).total_seconds()
    if age_seconds > max_age:
        return deny("nonce_stale")
    if age_seconds < -max_future:
        return deny("nonce_from_future")

    return "allow", None


def verify_fixture(
    fixture_text: str,
    *,
    signer_public_key: str,
    cosigner_public_key: Optional[str],
    enforce_cosigner: bool,
    schema_package: Dict[str, Any],
    policy: Dict[str, Any],
    verified_at: datetime,
) -> VerifyOutcome:
    # 1. JSON parse
    try:
        doc = json.loads(fixture_text)
    except json.JSONDecodeError:
        return VerifyOutcome(result="fail", error_code="VFY_PARSE_INVALID_JSON")

    if not isinstance(doc, dict):
        return VerifyOutcome(result="fail", error_code="VFY_PARSE_INVALID_JSON")

    # 2. SignedReceipt shape parse
    if not shape_validate_signed_receipt(doc):
        return VerifyOutcome(result="fail", error_code="VFY_SIGNED_RECEIPT_SHAPE_INVALID")

    receipt = doc["receipt"]
    metadata = receipt.get("metadata")

    # 3. Version gate
    version = receipt.get("version")
    try:
        validate_receipt_version(version)
    except ValueError as exc:
        msg = str(exc)
        if "Invalid receipt version" in msg:
            return VerifyOutcome(result="fail", error_code="VFY_RECEIPT_VERSION_INVALID")
        if "Unsupported receipt version" in msg:
            return VerifyOutcome(result="fail", error_code="VFY_RECEIPT_VERSION_UNSUPPORTED")
        return VerifyOutcome(result="fail", error_code="VFY_INTERNAL_UNEXPECTED")

    # 4. Determine profile
    profile: Optional[str] = None
    if isinstance(metadata, dict) and "receipt_profile" in metadata:
        profile = metadata.get("receipt_profile")

    mode = "baseline"
    if profile is None:
        mode = "baseline"
    elif profile == "cua.v1":
        mode = "cua"
    else:
        return VerifyOutcome(result="fail", error_code="VFY_PROFILE_UNKNOWN")

    schema = None
    if mode == "cua":
        if not isinstance(metadata, dict):
            return VerifyOutcome(result="fail", error_code="VFY_CUA_SCHEMA_INVALID")

        # 5. Resolve schema package
        schema_version = metadata.get("cua_schema_version")
        if not isinstance(schema_version, str):
            return VerifyOutcome(result="fail", error_code="VFY_CUA_SCHEMA_VERSION_UNSUPPORTED")

        schema_path = resolve_cua_schema_path(schema_package, "cua.v1", schema_version)
        if schema_path is None:
            return VerifyOutcome(result="fail", error_code="VFY_CUA_SCHEMA_VERSION_UNSUPPORTED")

        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        # 6. Metadata schema validation
        try:
            jsonschema.validate(metadata, schema)
        except jsonschema.ValidationError:
            return VerifyOutcome(result="fail", error_code="VFY_CUA_SCHEMA_INVALID")

    # 7-8. Signature checks
    try:
        signed = SignedReceipt.from_dict(doc)
    except ValueError:
        return VerifyOutcome(result="fail", error_code="VFY_SIGNED_RECEIPT_SHAPE_INVALID")

    verify_keys = PublicKeySet(
        signer=signer_public_key,
        cosigner=cosigner_public_key if enforce_cosigner else None,
    )
    verify_result = signed.verify(verify_keys)

    if not verify_result.signer_valid:
        return VerifyOutcome(result="fail", error_code="VFY_SIGNATURE_INVALID")

    if enforce_cosigner and doc["signatures"].get("cosigner") is not None:
        if verify_result.cosigner_valid is False:
            return VerifyOutcome(result="fail", error_code="VFY_COSIGNATURE_INVALID")

    if mode == "cua":
        # 9. Attestation policy
        decision, subcode = evaluate_attestation_policy(metadata, policy, verified_at)
        if decision != "allow":
            return VerifyOutcome(
                result="fail",
                error_code="VFY_ATTESTATION_POLICY_DENY",
                policy_subcode=subcode,
            )

        # 10. Chain summary consistency
        event_count = get_path(metadata, "cua.session.event_count")
        total_events = get_path(metadata, "cua.chain.total_events")
        if event_count != total_events:
            return VerifyOutcome(result="fail", error_code="VFY_CHAIN_SUMMARY_MISMATCH")

        supported_kinds = set(
            schema["$defs"]["action_kind"]["enum"] if isinstance(schema, dict) else []
        )
        action_summary = get_path(metadata, "cua.chain.action_summary")
        if isinstance(action_summary, list):
            for item in action_summary:
                kind = item.get("kind") if isinstance(item, dict) else None
                if kind not in supported_kinds:
                    return VerifyOutcome(result="fail", error_code="VFY_CHAIN_SUMMARY_MISMATCH")

    return VerifyOutcome(
        result="pass",
        verdict_passed=bool(get_path(receipt, "verdict.passed")),
    )


def evaluate_expected(expected: Dict[str, Any], outcome: VerifyOutcome) -> bool:
    if expected.get("result") != outcome.result:
        return False

    expected_error = expected.get("error_code")
    if expected_error != outcome.error_code:
        return False

    expected_subcode = expected.get("policy_subcode")
    if expected_subcode != outcome.policy_subcode:
        return False

    return True


def main() -> int:
    args = parse_args()

    cases_path = (REPO_ROOT / args.cases).resolve()
    cases_doc = json.loads(cases_path.read_text(encoding="utf-8"))

    schema_package_path = (REPO_ROOT / cases_doc["schema_package"]).resolve()
    policy_path = (REPO_ROOT / cases_doc["attestation_policy"]).resolve()

    schema_package = json.loads(schema_package_path.read_text(encoding="utf-8"))
    policy = yaml.safe_load(policy_path.read_text(encoding="utf-8"))

    verified_at = parse_iso8601(cases_doc["evaluation_context"]["verified_at"])

    signer_pk = cases_doc["public_keys"]["signer"]
    cosigner_pk = cases_doc["public_keys"].get("cosigner")

    report: Dict[str, Any] = {
        "verified_at": cases_doc["evaluation_context"]["verified_at"],
        "results": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }

    all_ok = True
    for case in cases_doc["cases"]:
        case_id = case["id"]
        fixture_path = cases_path.parent / case["fixture"]
        fixture_text = fixture_path.read_text(encoding="utf-8")

        expected = case["expected"]
        case_results: Dict[str, Any] = {"id": case_id, "fixture": case["fixture"], "checks": []}

        checks: list[tuple[str, Dict[str, Any], VerifyOutcome]] = []
        if "result" in expected:
            checks.append(
                (
                    "updated",
                    expected,
                    verify_fixture(
                        fixture_text,
                        signer_public_key=signer_pk,
                        cosigner_public_key=cosigner_pk,
                        enforce_cosigner=True,
                        schema_package=schema_package,
                        policy=policy,
                        verified_at=verified_at,
                    ),
                )
            )
        else:
            checks.append(
                (
                    "legacy",
                    expected["legacy_verifier"],
                    verify_fixture(
                        fixture_text,
                        signer_public_key=signer_pk,
                        cosigner_public_key=cosigner_pk,
                        enforce_cosigner=False,
                        schema_package=schema_package,
                        policy=policy,
                        verified_at=verified_at,
                    ),
                )
            )
            checks.append(
                (
                    "updated",
                    expected["updated_verifier"],
                    verify_fixture(
                        fixture_text,
                        signer_public_key=signer_pk,
                        cosigner_public_key=cosigner_pk,
                        enforce_cosigner=True,
                        schema_package=schema_package,
                        policy=policy,
                        verified_at=verified_at,
                    ),
                )
            )

        for mode, expected_mode, outcome in checks:
            ok = evaluate_expected(expected_mode, outcome)
            all_ok = all_ok and ok
            report["summary"]["total"] += 1
            if ok:
                report["summary"]["passed"] += 1
            else:
                report["summary"]["failed"] += 1

            case_results["checks"].append(
                {
                    "mode": mode,
                    "ok": ok,
                    "expected": expected_mode,
                    "actual": outcome.to_dict(),
                }
            )

            status = "PASS" if ok else "FAIL"
            print(f"[{status}] {case_id} ({mode}) -> {outcome.to_dict()}")

        report["results"].append(case_results)

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
