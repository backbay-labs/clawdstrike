#!/usr/bin/env python3
"""Generate a strict privacy-preserving telemetry supplemental proof."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
READINESS_AUDIT = SCRIPT_DIR / "endpoint-decision-engine-readiness-audit.py"
NON_RAW_PRIVACY_MODES = {"local_only", "hashes_features", "summary_with_receipts"}
REQUIRED_PROJECTION_CLASSES = {
    "hash_only",
    "metadata_only",
    "local_only",
    "raw_artifact_permitted",
}


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sha256_json(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def write_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def object_value(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict) or not value:
        raise ValueError(f"coverage artifact must include non-empty object {key}")
    return value


def first_object(payload: dict[str, Any], *keys: str) -> dict[str, Any]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, dict) and value:
            return value
    raise ValueError("coverage artifact missing one of: " + ", ".join(keys))


def report_from_response(value: dict[str, Any], label: str) -> dict[str, Any]:
    report = value.get("report")
    if isinstance(report, dict) and report:
        return report
    if isinstance(value.get("privacyMode"), str) and isinstance(value.get("observations"), list):
        return value
    raise ValueError(f"{label} must be a privacy report or response object with report")


def policy_from_response(value: dict[str, Any], label: str) -> dict[str, Any]:
    for key in ("privacy_policy", "privacyPolicy", "policyDecision"):
        policy = value.get(key)
        if isinstance(policy, dict) and policy:
            return policy
    raise ValueError(f"{label} must include privacy_policy/privacyPolicy/policyDecision")


def receipt_from_response(value: dict[str, Any], label: str) -> dict[str, Any]:
    receipt = value.get("receipt")
    if isinstance(receipt, dict) and receipt:
        return receipt
    raise ValueError(f"{label} must include signed receipt object")


def non_empty_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def positive_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return 0
    return value


def nonnegative_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def projection_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    observations = report.get("observations")
    if not isinstance(observations, list) or not observations:
        raise ValueError("privacy report must include non-empty observations")
    rows: list[dict[str, Any]] = []
    for observation in observations:
        if not isinstance(observation, dict):
            raise ValueError("privacy report observations must be objects")
        projections = observation.get("projections")
        if not isinstance(projections, list) or not projections:
            raise ValueError("privacy report observations must include projections")
        for projection in projections:
            if not isinstance(projection, dict):
                raise ValueError("privacy report projections must be objects")
            rows.append(projection)
    return rows


def projection_classes(*reports: dict[str, Any]) -> set[str]:
    classes: set[str] = set()
    for report in reports:
        for projection in projection_rows(report):
            redaction_class = non_empty_string(projection.get("redactionClass"))
            if redaction_class:
                classes.add(redaction_class)
    return classes


def all_raw_values_omitted(report: dict[str, Any]) -> bool:
    for projection in projection_rows(report):
        if projection.get("rawValue") not in (None, ""):
            return False
    return True


def raw_values_only_in_approved_report(
    default_report: dict[str, Any],
    downgraded_report: dict[str, Any],
    approved_report: dict[str, Any],
) -> bool:
    if not all_raw_values_omitted(default_report):
        return False
    if not all_raw_values_omitted(downgraded_report):
        return False
    return any(
        projection.get("redactionClass") == "raw_artifact_permitted"
        and isinstance(projection.get("rawValue"), str)
        and projection["rawValue"].strip()
        for projection in projection_rows(approved_report)
    )


def require_report_counts(report: dict[str, Any], label: str) -> None:
    for field in ("observationCount", "fieldCount"):
        if positive_int(report.get(field)) < 1:
            raise ValueError(f"{label}.{field} must be a positive integer")
    if nonnegative_int(report.get("rawSuppressedCount")) != report.get("rawSuppressedCount"):
        raise ValueError(f"{label}.rawSuppressedCount must be a non-negative integer")
    if nonnegative_int(report.get("localOnlyCount")) != report.get("localOnlyCount"):
        raise ValueError(f"{label}.localOnlyCount must be a non-negative integer")


def receipt_family(receipt: dict[str, Any]) -> str | None:
    metadata = receipt_payload(receipt).get("metadata")
    if not isinstance(metadata, dict):
        return None
    endpoint_decision = metadata.get("endpointDecision")
    if not isinstance(endpoint_decision, dict):
        return None
    return non_empty_string(endpoint_decision.get("receiptFamily"))


def receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    payload = receipt.get("receipt")
    if isinstance(payload, dict) and payload:
        return payload
    return receipt


def receipt_id(receipt: dict[str, Any]) -> str | None:
    return (
        non_empty_string(receipt.get("receiptId"))
        or non_empty_string(receipt.get("id"))
        or non_empty_string(receipt_payload(receipt).get("receiptId"))
        or non_empty_string(receipt_payload(receipt).get("id"))
    )


def require_receipt_binding(
    receipt: dict[str, Any],
    report_id: str,
    approval_id: str,
    approval_reason_hash: str,
) -> str:
    identifier = receipt_id(receipt)
    if not identifier:
        raise ValueError("approved response receipt must include a receipt id")
    metadata = receipt_payload(receipt).get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("approved response receipt must include metadata")
    endpoint_decision = metadata.get("endpointDecision")
    if not isinstance(endpoint_decision, dict):
        raise ValueError("approved response receipt must include endpointDecision metadata")
    decision = endpoint_decision.get("decision")
    if not isinstance(decision, dict):
        raise ValueError("approved response receipt must include decision metadata")
    bound_report_id = (
        non_empty_string(decision.get("findingId"))
        or non_empty_string(decision.get("reportId"))
        or non_empty_string(endpoint_decision.get("reportId"))
    )
    if bound_report_id != report_id:
        raise ValueError("approved response receipt must bind the privacy report id")
    if endpoint_decision.get("rawArtifactApprovalId") != approval_id:
        raise ValueError("approved response receipt must bind raw artifact approval id")
    if endpoint_decision.get("rawArtifactApprovalReasonHash") != approval_reason_hash:
        raise ValueError("approved response receipt must bind approval reason hash")
    if endpoint_decision.get("rawArtifactUploadPermitted") is not True:
        raise ValueError("approved response receipt must bind raw artifact upload permission")
    return identifier


def derive_privacy_evidence(coverage: dict[str, Any]) -> dict[str, Any]:
    default_response = first_object(coverage, "defaultResponse", "defaultReport")
    downgraded_response = first_object(coverage, "downgradedRawResponse", "downgradedRawRequest")
    approved_response = first_object(coverage, "approvedRawResponse", "approvedRawReport")
    default_report = report_from_response(default_response, "defaultResponse")
    downgraded_report = report_from_response(downgraded_response, "downgradedRawResponse")
    approved_report = report_from_response(approved_response, "approvedRawResponse")
    downgraded_policy = policy_from_response(downgraded_response, "downgradedRawResponse")
    approved_policy = policy_from_response(approved_response, "approvedRawResponse")
    receipt = receipt_from_response(approved_response, "approvedRawResponse")

    require_report_counts(default_report, "defaultReport")
    require_report_counts(downgraded_report, "downgradedRawReport")
    require_report_counts(approved_report, "approvedRawReport")

    default_mode = non_empty_string(default_report.get("privacyMode"))
    if default_mode not in NON_RAW_PRIVACY_MODES:
        raise ValueError("default privacy report must use a non-raw privacy mode")
    if default_report.get("rawArtifactUploadPermitted") is not False:
        raise ValueError("default privacy report must suppress raw artifact upload")
    if positive_int(default_report.get("rawSuppressedCount")) < 1:
        raise ValueError("default privacy report must suppress at least one raw artifact")
    if positive_int(default_report.get("localOnlyCount")) < 1:
        raise ValueError("default privacy report must include local-only projection evidence")

    if downgraded_policy.get("requestedPrivacyMode") != "raw_artifact_permitted":
        raise ValueError("downgraded response must request raw_artifact_permitted")
    if downgraded_policy.get("effectivePrivacyMode") not in NON_RAW_PRIVACY_MODES:
        raise ValueError("downgraded raw request must fall back to a non-raw mode")
    if downgraded_policy.get("rawArtifactUploadRequested") is not True:
        raise ValueError("downgraded policy must record raw artifact upload request")
    if downgraded_report.get("rawArtifactUploadPermitted") is not False:
        raise ValueError("downgraded privacy report must not permit raw artifacts")

    if approved_policy.get("requestedPrivacyMode") != "raw_artifact_permitted":
        raise ValueError("approved response must request raw_artifact_permitted")
    if approved_policy.get("effectivePrivacyMode") != "raw_artifact_permitted":
        raise ValueError("approved response must effectively permit raw artifacts")
    if approved_policy.get("rawArtifactUploadAllowed") is not True:
        raise ValueError("approved policy must allow raw artifact upload")
    if approved_policy.get("rawArtifactApprovalRequired") is not True:
        raise ValueError("approved policy must require raw artifact approval")
    if approved_policy.get("rawArtifactApprovalProvided") is not True:
        raise ValueError("approved policy must prove approval was provided")
    if approved_report.get("rawArtifactUploadPermitted") is not True:
        raise ValueError("approved privacy report must permit raw artifact upload")

    report_id = non_empty_string(approved_report.get("reportId"))
    approval_id = non_empty_string(approved_report.get("rawArtifactApprovalId"))
    approval_reason_hash = non_empty_string(approved_report.get("rawArtifactApprovalReasonHash"))
    if not report_id:
        raise ValueError("approved privacy report must include reportId")
    if not approval_id:
        raise ValueError("approved privacy report must include rawArtifactApprovalId")
    if not approval_reason_hash:
        raise ValueError("approved privacy report must include rawArtifactApprovalReasonHash")
    if approved_policy.get("rawArtifactApprovalId") != approval_id:
        raise ValueError("approved policy/report approval IDs must match")
    if approved_policy.get("rawArtifactApprovalReasonHash") != approval_reason_hash:
        raise ValueError("approved policy/report approval reason hashes must match")

    classes = projection_classes(default_report, downgraded_report, approved_report)
    missing_classes = sorted(REQUIRED_PROJECTION_CLASSES - classes)
    if missing_classes:
        raise ValueError("privacy projections missing classes: " + ", ".join(missing_classes))
    if not raw_values_only_in_approved_report(default_report, downgraded_report, approved_report):
        raise ValueError("raw values must be omitted by default and present only in approved report")
    if receipt_family(receipt) != "privacy_report":
        raise ValueError("approved response receipt must be privacy_report family")
    approved_receipt_id = require_receipt_binding(
        receipt,
        report_id,
        approval_id,
        approval_reason_hash,
    )

    approved_raw_artifact_count = sum(
        1
        for projection in projection_rows(approved_report)
        if projection.get("redactionClass") == "raw_artifact_permitted"
        and isinstance(projection.get("rawValue"), str)
        and projection["rawValue"].strip()
    )
    if approved_raw_artifact_count < 1:
        raise ValueError("approved report must contain at least one raw approved artifact")

    return {
        "privacyReceiptFamily": "privacy_report",
        "defaultProjection": default_mode,
        "rawArtifactsSuppressedByDefault": True,
        "rawArtifactsRequireApproval": True,
        "localClassification": True,
        "rawArtifactsDowngradedWithoutApproval": True,
        "rawArtifactsPolicyGateVerified": True,
        "rawArtifactsAllowedOnlyWithApproval": True,
        "rawValuesOmittedFromDefaultReport": True,
        "rawValuesPresentOnlyInApprovedReport": True,
        "privacyReportId": report_id,
        "privacyReceiptId": approved_receipt_id,
        "rawArtifactApprovalId": approval_id,
        "rawArtifactApprovalReasonHash": approval_reason_hash,
        "privacyReceiptBindsReport": True,
        "privacyReceiptBindsApproval": True,
        "defaultReportSha256": sha256_json(default_report),
        "privacyPolicyDecisionSha256": sha256_json(approved_policy),
        "downgradedRawRequestSha256": sha256_json(downgraded_response),
        "approvedRawReportSha256": sha256_json(approved_report),
        "privacyReceiptSha256": sha256_json(receipt),
        "projectionClasses": sorted(classes),
        "observationCount": positive_int(default_report.get("observationCount")),
        "fieldCount": positive_int(default_report.get("fieldCount")),
        "hashOnlyCount": positive_int(default_report.get("hashOnlyCount")),
        "metadataOnlyCount": positive_int(default_report.get("metadataOnlyCount")),
        "localOnlyCount": positive_int(default_report.get("localOnlyCount")),
        "rawSuppressedCount": positive_int(default_report.get("rawSuppressedCount")),
        "approvedRawArtifactCount": approved_raw_artifact_count,
    }


def write_proof(
    out_dir: pathlib.Path,
    evidence_path: pathlib.Path,
    coverage_path: pathlib.Path,
    command_result_path: pathlib.Path,
) -> dict[str, Any]:
    proof_path = out_dir / "privacy-preserving-telemetry-proof.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(READINESS_AUDIT),
            "--write-proof",
            "privacy_preserving_telemetry",
            "--proof-output",
            str(proof_path),
            "--proof-evidence",
            str(evidence_path),
            "--proof-artifact",
            str(coverage_path),
            "--proof-command-result",
            str(command_result_path),
        ],
        check=False,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        raise ValueError(
            "readiness audit proof writer failed: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )
    result = json.loads(completed.stdout)
    if result.get("status") != "verified":
        raise ValueError("readiness audit proof writer returned non-verified status")
    return {"proofPath": str(proof_path), "proofValidation": result}


def build_privacy_proof(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = args.out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    coverage_path = args.coverage_json.expanduser().resolve()
    if not coverage_path.is_file():
        raise ValueError(f"--coverage-json must reference an existing JSON file: {coverage_path}")
    coverage = load_json_object(coverage_path)
    evidence = derive_privacy_evidence(coverage)
    evidence_path = out_dir / "privacy-preserving-telemetry-evidence.json"
    command_result_path = out_dir / "privacy-preserving-telemetry-command-result.json"
    write_json(evidence_path, evidence)
    write_json(
        command_result_path,
        {
            "argv": [
                str(pathlib.Path(__file__).name),
                "--coverage-json",
                str(coverage_path),
            ],
            "exitCode": 0,
            "coveragePath": str(coverage_path),
            "evidencePath": str(evidence_path),
            "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        },
    )
    proof = write_proof(out_dir, evidence_path, coverage_path, command_result_path)
    result = {
        "schemaVersion": 1,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "coveragePath": str(coverage_path),
        "evidencePath": str(evidence_path),
        "commandResultPath": str(command_result_path),
        "evidence": evidence,
        **proof,
    }
    summary_path = out_dir / "privacy-preserving-telemetry-proof-summary.json"
    write_json(summary_path, result)
    result["summaryPath"] = str(summary_path)
    return result


def fixture_report(
    privacy_mode: str,
    raw_permitted: bool,
    include_raw: bool,
    approval_id: str | None = None,
    approval_reason_hash: str | None = None,
) -> dict[str, Any]:
    projections = [
        {
            "fieldPath": "process.image",
            "redactionClass": "hash_only",
            "valueHash": "0x" + "1" * 64,
            "featureValue": None,
            "rawValue": None,
            "reason": "path hash only",
        },
        {
            "fieldPath": "event.network.protocol",
            "redactionClass": "metadata_only",
            "valueHash": None,
            "featureValue": "tcp",
            "rawValue": None,
            "reason": "low-content protocol feature",
        },
        {
            "fieldPath": "event.fileAccess.contentPreview",
            "redactionClass": "raw_artifact_permitted" if include_raw else "local_only",
            "valueHash": "0x" + "2" * 64,
            "featureValue": None,
            "rawValue": "raw customer token material" if include_raw else None,
            "reason": "raw artifact requires approval",
        },
    ]
    report = {
        "reportId": "telemetry_privacy_report:fixture-approved"
        if raw_permitted
        else "telemetry_privacy_report:fixture-default",
        "privacyMode": privacy_mode,
        "rawArtifactUploadPermitted": raw_permitted,
        "observationCount": 1,
        "fieldCount": len(projections),
        "hashOnlyCount": 1,
        "metadataOnlyCount": 1,
        "redactedCount": 0,
        "rawSuppressedCount": 0 if include_raw else 1,
        "localOnlyCount": 0 if include_raw else 1,
        "observations": [
            {
                "observationId": "obs:privacy",
                "eventKind": "file_access",
                "fieldCount": len(projections),
                "rawSuppressedCount": 0 if include_raw else 1,
                "localOnlyCount": 0 if include_raw else 1,
                "projections": projections,
            }
        ],
    }
    if raw_permitted:
        report["rawArtifactApprovalId"] = approval_id or "approval-privacy-fixture"
        report["rawArtifactApprovalReasonHash"] = approval_reason_hash or ("0x" + "a" * 64)
    return report


def fixture_response(
    report: dict[str, Any],
    requested: str,
    effective: str,
    allowed: bool,
    approval_required: bool,
    approval_provided: bool,
) -> dict[str, Any]:
    policy = {
        "requestedPrivacyMode": requested,
        "effectivePrivacyMode": effective,
        "rawArtifactUploadRequested": requested == "raw_artifact_permitted",
        "rawArtifactUploadAllowed": allowed,
        "rawArtifactApprovalRequired": approval_required,
        "rawArtifactApprovalProvided": approval_provided,
        "policySource": "local-policy-fixture",
        "deniedReason": None if approval_provided or not allowed else "approval required",
    }
    if report.get("rawArtifactApprovalId"):
        policy["rawArtifactApprovalId"] = report["rawArtifactApprovalId"]
        policy["rawArtifactApprovalReasonHash"] = report["rawArtifactApprovalReasonHash"]
    return {
        "report": report,
        "privacy_policy": policy,
        "receipt": {
            "receiptId": "privacy_receipt:" + report["reportId"].split(":")[-1],
            "receipt": {
                "receiptId": "privacy_receipt:" + report["reportId"].split(":")[-1],
                "metadata": {
                    "endpointDecision": {
                        "receiptFamily": "privacy_report",
                        "decision": {"findingId": report["reportId"]},
                        "rawArtifactApprovalId": report.get("rawArtifactApprovalId"),
                        "rawArtifactApprovalReasonHash": report.get(
                            "rawArtifactApprovalReasonHash"
                        ),
                        "rawArtifactUploadPermitted": report.get(
                            "rawArtifactUploadPermitted"
                        ),
                        "evidence": [
                            {"key": "privacyMode", "valueHash": "0x" + "3" * 64},
                            {
                                "key": "rawArtifactUploadPermitted",
                                "valueHash": "0x" + "4" * 64,
                            },
                        ],
                    }
                }
            }
        },
    }


def fixture_coverage() -> dict[str, Any]:
    approval_id = "approval-privacy-fixture"
    approval_reason_hash = "0x" + "a" * 64
    default_report = fixture_report("hashes_features", False, False)
    downgraded_report = fixture_report("hashes_features", False, False)
    approved_report = fixture_report(
        "raw_artifact_permitted",
        True,
        True,
        approval_id,
        approval_reason_hash,
    )
    return {
        "schemaVersion": 1,
        "defaultResponse": fixture_response(
            default_report,
            "hashes_features",
            "hashes_features",
            False,
            False,
            False,
        ),
        "downgradedRawResponse": fixture_response(
            downgraded_report,
            "raw_artifact_permitted",
            "hashes_features",
            False,
            False,
            False,
        ),
        "approvedRawResponse": fixture_response(
            approved_report,
            "raw_artifact_permitted",
            "raw_artifact_permitted",
            True,
            True,
            True,
        ),
    }


def expect_failure(root: pathlib.Path, name: str, coverage: dict[str, Any]) -> bool:
    path = root / f"{name}.json"
    write_json(path, coverage)
    try:
        build_privacy_proof(
            argparse.Namespace(out_dir=root / f"{name}-out", coverage_json=path)
        )
    except ValueError:
        return True
    return False


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-privacy-proof-") as temp_dir:
        root = pathlib.Path(temp_dir)
        coverage_path = root / "coverage.json"
        write_json(coverage_path, fixture_coverage())
        result = build_privacy_proof(
            argparse.Namespace(out_dir=root / "out", coverage_json=coverage_path)
        )
        if result["proofValidation"]["status"] != "verified":
            print("self-test expected generated proof to validate", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        missing_approval = fixture_coverage()
        missing_approval["approvedRawResponse"]["report"].pop("rawArtifactApprovalId")
        if not expect_failure(root, "missing-approval", missing_approval):
            print("self-test expected missing approval id to fail", file=sys.stderr)
            return 1

        default_raw_leak = fixture_coverage()
        default_raw_leak["defaultResponse"]["report"]["observations"][0]["projections"][2][
            "rawValue"
        ] = "leaked raw value"
        if not expect_failure(root, "default-raw-leak", default_raw_leak):
            print("self-test expected default raw value leak to fail", file=sys.stderr)
            return 1

        no_raw_approved = fixture_coverage()
        no_raw_approved["approvedRawResponse"]["report"]["observations"][0]["projections"][2][
            "rawValue"
        ] = None
        if not expect_failure(root, "no-raw-approved", no_raw_approved):
            print("self-test expected approved report without raw artifact to fail", file=sys.stderr)
            return 1

        wrong_receipt = fixture_coverage()
        wrong_receipt["approvedRawResponse"]["receipt"]["receipt"]["metadata"][
            "endpointDecision"
        ]["receiptFamily"] = "detection"
        if not expect_failure(root, "wrong-receipt", wrong_receipt):
            print("self-test expected wrong receipt family to fail", file=sys.stderr)
            return 1

        unbound_receipt = fixture_coverage()
        unbound_receipt["approvedRawResponse"]["receipt"]["receipt"]["metadata"][
            "endpointDecision"
        ]["decision"]["findingId"] = "telemetry_privacy_report:other"
        if not expect_failure(root, "unbound-receipt", unbound_receipt):
            print("self-test expected unbound privacy receipt to fail", file=sys.stderr)
            return 1

        unbound_approval = fixture_coverage()
        unbound_approval["approvedRawResponse"]["receipt"]["receipt"]["metadata"][
            "endpointDecision"
        ]["rawArtifactApprovalId"] = "approval-other"
        if not expect_failure(root, "unbound-approval", unbound_approval):
            print("self-test expected unbound privacy approval to fail", file=sys.stderr)
            return 1

    print("privacy preserving telemetry proof self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=pathlib.Path)
    parser.add_argument("--coverage-json", type=pathlib.Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if args.out_dir is None:
        parser.error("--out-dir is required")
    if args.coverage_json is None:
        parser.error("--coverage-json is required")
    try:
        result = build_privacy_proof(args)
    except ValueError as exc:
        print(f"privacy preserving telemetry proof failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
