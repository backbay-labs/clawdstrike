#!/usr/bin/env python3
"""Generate a strict operator-workflows supplemental proof."""

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
REQUIRED_WORKFLOWS = {
    "process_cause",
    "policy_replay",
    "rule_impact",
    "local_containment",
    "agent_secret_touches",
    "causal_groups",
    "proof_at_execution",
    "privacy_report",
    "detection_staging",
}
REQUIRED_ROUTES = {
    "/api/v1/agent/edr/causal-context",
    "/api/v1/agent/edr/policy-replay",
    "/api/v1/agent/edr/policy-events/impact",
    "/api/v1/agent/edr/response-action",
    "/api/v1/agent/edr/agent-secret-touches",
    "/api/v1/agent/edr/finding-groups",
    "/api/v1/agent/edr/protection-state",
    "/api/v1/agent/edr/privacy-report",
    "/api/v1/agent/edr/detection-candidate",
    "/api/v1/agent/edr/staged-detections",
}
REQUIRED_RECEIPT_FAMILIES = {
    "simulation",
    "response_request",
    "response_execution",
    "sensor_state",
    "privacy_report",
}
REQUIRED_RESPONSE_ACTION_KINDS = {
    "isolate_network",
    "suspend_process_tree",
    "revoke_token",
    "quarantine_file",
    "block_persistence",
    "rollback_config",
    "collect_evidence",
}
RESPONSE_RECEIPT_FAMILIES = {"response_request", "response_execution"}


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


def string_values(value: Any) -> list[str]:
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    if isinstance(value, list):
        return [item.strip() for item in value if isinstance(item, str) and item.strip()]
    return []


def object_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key)
    if not isinstance(value, list) or not value:
        raise ValueError(f"coverage artifact must include non-empty list {key}")
    rows = [item for item in value if isinstance(item, dict)]
    if len(rows) != len(value):
        raise ValueError(f"coverage artifact {key} entries must be objects")
    return rows


def object_value(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict) or not value:
        raise ValueError(f"coverage artifact must include non-empty object {key}")
    return value


def values_from_row(row: dict[str, Any], *keys: str) -> set[str]:
    values: set[str] = set()
    for key in keys:
        values.update(string_values(row.get(key)))
    return values


def normalized_response_action_kind(row: dict[str, Any]) -> str | None:
    raw = string_values(row.get("actionKind")) or string_values(row.get("kind"))
    raw = raw or string_values(row.get("actionType"))
    if not raw:
        return None
    normalized = raw[0].strip().lower().replace("-", "_")
    aliases = {
        "network_isolation": "isolate_network",
        "isolate_egress": "isolate_network",
        "restrict_egress": "isolate_network",
        "suspend_process": "suspend_process_tree",
        "terminate_process_tree": "suspend_process_tree",
        "revoke_grant": "revoke_token",
        "revoke_credential": "revoke_token",
        "principal_quarantine": "quarantine_file",
        "file_quarantine": "quarantine_file",
        "disable_persistence": "block_persistence",
        "block_launch_persistence": "block_persistence",
        "roll_back_config": "rollback_config",
        "config_rollback": "rollback_config",
        "evidence_collection": "collect_evidence",
    }
    return aliases.get(normalized, normalized)


def non_empty_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def has_sha256(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        return False
    try:
        int(value.removeprefix("sha256:"), 16)
    except ValueError:
        return False
    return True


def has_confidence(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return 0 <= value <= 1


def require_complete_coverage(
    workflows: set[str],
    routes: set[str],
    receipt_families: set[str],
) -> None:
    missing = {
        "workflows": sorted(REQUIRED_WORKFLOWS - workflows),
        "workflowRoutes": sorted(REQUIRED_ROUTES - routes),
        "receiptFamilies": sorted(REQUIRED_RECEIPT_FAMILIES - receipt_families),
    }
    missing = {key: values for key, values in missing.items() if values}
    if missing:
        raise ValueError("operator workflow coverage missing required evidence: " + json.dumps(missing))


def workflow_run_for(rows: list[dict[str, Any]], workflow: str) -> dict[str, Any]:
    matches = [row for row in rows if row.get("workflow") == workflow]
    if not matches:
        raise ValueError(f"missing workflow run: {workflow}")
    if len(matches) > 1:
        raise ValueError(f"duplicate workflow run: {workflow}")
    return matches[0]


def require_verified_runs(rows: list[dict[str, Any]]) -> None:
    unverified = [
        str(row.get("workflow") or row.get("route") or index)
        for index, row in enumerate(rows)
        if row.get("verified") is not True
    ]
    if unverified:
        raise ValueError("operator workflow runs must be verified: " + ", ".join(unverified))


def require_workflow_latency(rows: list[dict[str, Any]]) -> int:
    latencies: list[int] = []
    for index, row in enumerate(rows):
        latency = row.get("latencyMs")
        if isinstance(latency, bool) or not isinstance(latency, int) or latency < 1 or latency > 10000:
            label = row.get("workflow") or row.get("route") or index
            raise ValueError(f"workflow run {label} must include latencyMs in 1..10000")
        latencies.append(latency)
    return max(latencies)


def require_containment_safety(row: dict[str, Any]) -> int:
    ttl = row.get("ttlSeconds")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 1 or ttl > 3600:
        raise ValueError("local_containment workflow must include ttlSeconds in 1..3600")
    if row.get("rollbackAvailable") is not True:
        raise ValueError("local_containment workflow must prove rollbackAvailable")
    return ttl


def require_detection_staging(row: dict[str, Any]) -> None:
    if row.get("stagedDetectionGenerated") is True:
        return
    if isinstance(row.get("stagedDetectionId"), str) and row["stagedDetectionId"].strip():
        return
    raise ValueError("detection_staging workflow must prove a staged detection was generated")


def require_response_action_coverage(rows: list[dict[str, Any]]) -> set[str]:
    kinds: set[str] = set()
    for index, row in enumerate(rows):
        kind = normalized_response_action_kind(row)
        if kind is None:
            raise ValueError(f"responseActions[{index}] must include actionKind/kind/actionType")
        kinds.add(kind)

        ttl = row.get("ttlSeconds")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 1 or ttl > 3600:
            raise ValueError(f"responseActions[{index}] must include ttlSeconds in 1..3600")
        if row.get("rollbackAvailable") is not True:
            raise ValueError(f"responseActions[{index}] must prove rollbackAvailable")
        if not string_values(row.get("receiptId")) and not string_values(row.get("receiptIds")):
            raise ValueError(f"responseActions[{index}] must include a receipt id")
        families = values_from_row(row, "receiptFamily", "receiptFamilies")
        if not families & RESPONSE_RECEIPT_FAMILIES:
            raise ValueError(
                f"responseActions[{index}] must include response_request or response_execution receipt family"
            )
        if not (has_sha256(row.get("policyHash")) or non_empty_string(row.get("policyVersion"))):
            raise ValueError(f"responseActions[{index}] must bind policyHash or policyVersion")
        if not (
            non_empty_string(row.get("sensorStateReceiptId"))
            or has_sha256(row.get("sensorStateSha256"))
        ):
            raise ValueError(f"responseActions[{index}] must bind sensor state")
        if not non_empty_string(row.get("actorId")) and not non_empty_string(row.get("actor")):
            raise ValueError(f"responseActions[{index}] must bind actor")
        if not has_sha256(row.get("processTreeSha256")):
            raise ValueError(f"responseActions[{index}] must bind processTreeSha256")
        if not has_sha256(row.get("evidenceSha256")):
            raise ValueError(f"responseActions[{index}] must bind evidenceSha256")
        if not has_confidence(row.get("confidence")):
            raise ValueError(f"responseActions[{index}] must include confidence in 0..1")
        if not non_empty_string(row.get("action")):
            raise ValueError(f"responseActions[{index}] must bind action")

    missing = sorted(REQUIRED_RESPONSE_ACTION_KINDS - kinds)
    if missing:
        raise ValueError("responseActions missing required action kinds: " + ", ".join(missing))
    return kinds


def require_local_first_evidence(local_first: dict[str, Any]) -> None:
    for field in (
        "cloudUnavailableDecisionVerified",
        "natsUnavailableDecisionVerified",
        "localContainmentOfflineVerified",
    ):
        if local_first.get(field) is not True:
            raise ValueError(f"localFirst.{field} must be true")
    if local_first.get("cloudProjectionQueuedOrSuppressed") is True:
        return
    if local_first.get("cloudProjectionQueued") is True:
        return
    if local_first.get("cloudProjectionSuppressedByPolicy") is True:
        return
    raise ValueError("localFirst must prove cloud projection was queued or suppressed by policy")


def derive_operator_evidence(coverage: dict[str, Any]) -> dict[str, Any]:
    runs = object_list(coverage, "workflowRuns")
    response_actions = object_list(coverage, "responseActions")
    local_first = object_value(coverage, "localFirst")
    operator_export = object_value(coverage, "operatorExport")
    proof_package = object_value(coverage, "proofPackage")
    require_verified_runs(runs)
    max_latency_ms = require_workflow_latency(runs)
    response_action_kinds = require_response_action_coverage(response_actions)
    require_local_first_evidence(local_first)

    workflows: set[str] = set()
    routes: set[str] = set()
    receipt_families: set[str] = set()
    for row in runs:
        workflows.update(values_from_row(row, "workflow"))
        routes.update(values_from_row(row, "route", "routes"))
        receipt_families.update(values_from_row(row, "receiptFamily", "receiptFamilies"))
    require_complete_coverage(workflows, routes, receipt_families)

    containment_ttl = require_containment_safety(workflow_run_for(runs, "local_containment"))
    require_detection_staging(workflow_run_for(runs, "detection_staging"))
    if operator_export.get("verified") is not True:
        raise ValueError("operatorExport must be verified")
    if proof_package.get("verified") is not True:
        raise ValueError("proofPackage must be verified")

    return {
        "workflows": sorted(workflows),
        "workflowRoutes": sorted(routes),
        "receiptFamilies": sorted(receipt_families),
        "responseActionKinds": sorted(response_action_kinds),
        "allWorkflowsVerified": True,
        "operatorExported": True,
        "containmentRollbackAvailable": True,
        "responseActionsAllTtlBounded": True,
        "responseActionsAllRollbackable": True,
        "responseActionsAllReceipted": True,
        "responseReceiptsBindPolicy": True,
        "responseReceiptsBindSensorState": True,
        "responseReceiptsBindActor": True,
        "responseReceiptsBindProcessTree": True,
        "responseReceiptsBindEvidence": True,
        "responseReceiptsBindConfidence": True,
        "responseReceiptsBindAction": True,
        "localFirstCloudOptional": True,
        "cloudUnavailableDecisionVerified": True,
        "natsUnavailableDecisionVerified": True,
        "localContainmentOfflineVerified": True,
        "cloudProjectionQueuedOrSuppressed": True,
        "stagedDetectionGenerated": True,
        "workflowRunSetSha256": sha256_json(runs),
        "operatorExportSha256": sha256_json(operator_export),
        "proofPackageSha256": sha256_json(proof_package),
        "responseActionCoverageSha256": sha256_json(response_actions),
        "localFirstProofSha256": sha256_json(local_first),
        "workflowRunCount": len(runs),
        "routeCount": len(routes),
        "receiptFamilyCount": len(receipt_families),
        "safeContainmentTtlSeconds": containment_ttl,
        "responseActionCount": len(response_actions),
        "maxWorkflowLatencyMs": max_latency_ms,
        "workflowLatencyBoundMs": 10000,
    }


def write_proof(
    out_dir: pathlib.Path,
    evidence_path: pathlib.Path,
    coverage_path: pathlib.Path,
    command_result_path: pathlib.Path,
) -> dict[str, Any]:
    proof_path = out_dir / "operator-workflows-proof.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(READINESS_AUDIT),
            "--write-proof",
            "operator_workflows",
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


def build_operator_proof(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = args.out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    coverage_path = args.coverage_json.expanduser().resolve()
    if not coverage_path.is_file():
        raise ValueError(f"--coverage-json must reference an existing JSON file: {coverage_path}")
    coverage = load_json_object(coverage_path)
    evidence = derive_operator_evidence(coverage)
    evidence_path = out_dir / "operator-workflows-evidence.json"
    command_result_path = out_dir / "operator-workflows-command-result.json"
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
    summary_path = out_dir / "operator-workflows-proof-summary.json"
    write_json(summary_path, result)
    result["summaryPath"] = str(summary_path)
    return result


def fixture_response_action(kind: str, action: str, confidence: float) -> dict[str, Any]:
    receipt_slug = kind.replace("_", "-")
    return {
        "actionKind": kind,
        "action": action,
        "ttlSeconds": 600,
        "rollbackAvailable": True,
        "receiptId": f"response:request:{receipt_slug}",
        "receiptFamilies": ["response_request", "response_execution"],
        "policyHash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "sensorStateReceiptId": "sensor_state:fixture",
        "actorId": "actor:operator",
        "processTreeSha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "evidenceSha256": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "confidence": confidence,
    }


def fixture_coverage() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "workflowRuns": [
            {
                "workflow": "process_cause",
                "route": "/api/v1/agent/edr/causal-context",
                "verified": True,
                "latencyMs": 120,
            },
            {
                "workflow": "policy_replay",
                "route": "/api/v1/agent/edr/policy-replay",
                "verified": True,
                "receiptFamilies": ["simulation"],
                "latencyMs": 450,
            },
            {
                "workflow": "rule_impact",
                "route": "/api/v1/agent/edr/policy-events/impact",
                "verified": True,
                "receiptFamilies": ["simulation"],
                "latencyMs": 500,
            },
            {
                "workflow": "local_containment",
                "route": "/api/v1/agent/edr/response-action",
                "verified": True,
                "ttlSeconds": 600,
                "rollbackAvailable": True,
                "receiptFamilies": ["response_request", "response_execution"],
                "latencyMs": 250,
            },
            {
                "workflow": "agent_secret_touches",
                "route": "/api/v1/agent/edr/agent-secret-touches",
                "verified": True,
                "latencyMs": 180,
            },
            {
                "workflow": "causal_groups",
                "route": "/api/v1/agent/edr/finding-groups",
                "verified": True,
                "latencyMs": 200,
            },
            {
                "workflow": "proof_at_execution",
                "route": "/api/v1/agent/edr/protection-state",
                "verified": True,
                "receiptFamilies": ["sensor_state"],
                "latencyMs": 160,
            },
            {
                "workflow": "privacy_report",
                "route": "/api/v1/agent/edr/privacy-report",
                "verified": True,
                "receiptFamilies": ["privacy_report"],
                "latencyMs": 190,
            },
            {
                "workflow": "detection_staging",
                "routes": [
                    "/api/v1/agent/edr/detection-candidate",
                    "/api/v1/agent/edr/staged-detections",
                ],
                "verified": True,
                "stagedDetectionGenerated": True,
                "stagedDetectionId": "staged-detection:fixture",
                "latencyMs": 400,
            },
        ],
        "operatorExport": {
            "verified": True,
            "exportId": "operator-workflows:fixture",
            "format": "json",
        },
        "responseActions": [
            fixture_response_action("isolate_network", "restrict endpoint egress to target", 0.99),
            fixture_response_action("suspend_process_tree", "suspend causal process tree", 0.99),
            fixture_response_action("revoke_token", "revoke exposed token", 0.95),
            fixture_response_action("quarantine_file", "quarantine suspicious file", 0.97),
            fixture_response_action("block_persistence", "block launch persistence", 0.98),
            fixture_response_action("rollback_config", "roll back configuration change", 0.94),
            fixture_response_action("collect_evidence", "collect endpoint evidence bundle", 0.9),
        ],
        "localFirst": {
            "cloudUnavailableDecisionVerified": True,
            "natsUnavailableDecisionVerified": True,
            "localContainmentOfflineVerified": True,
            "cloudProjectionQueuedOrSuppressed": True,
            "offlineProofId": "local-first:fixture",
        },
        "proofPackage": {
            "verified": True,
            "artifactCount": 9,
            "summary": "operator workflow proof package fixture",
        },
    }


def expect_failure(root: pathlib.Path, name: str, coverage: dict[str, Any]) -> bool:
    path = root / f"{name}.json"
    write_json(path, coverage)
    try:
        build_operator_proof(
            argparse.Namespace(out_dir=root / f"{name}-out", coverage_json=path)
        )
    except ValueError:
        return True
    return False


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-operator-workflows-proof-") as temp_dir:
        root = pathlib.Path(temp_dir)
        coverage_path = root / "coverage.json"
        write_json(coverage_path, fixture_coverage())
        result = build_operator_proof(
            argparse.Namespace(out_dir=root / "out", coverage_json=coverage_path)
        )
        if result["proofValidation"]["status"] != "verified":
            print("self-test expected generated proof to validate", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        missing_workflow = fixture_coverage()
        missing_workflow["workflowRuns"] = [
            row for row in missing_workflow["workflowRuns"] if row["workflow"] != "privacy_report"
        ]
        if not expect_failure(root, "missing-workflow", missing_workflow):
            print("self-test expected missing privacy workflow to fail", file=sys.stderr)
            return 1

        unverified = fixture_coverage()
        unverified["workflowRuns"][0]["verified"] = False
        if not expect_failure(root, "unverified", unverified):
            print("self-test expected unverified workflow to fail", file=sys.stderr)
            return 1

        too_slow = fixture_coverage()
        too_slow["workflowRuns"][0]["latencyMs"] = 10001
        if not expect_failure(root, "too-slow", too_slow):
            print("self-test expected over-bound workflow latency to fail", file=sys.stderr)
            return 1

        no_rollback = fixture_coverage()
        no_rollback["workflowRuns"][3]["rollbackAvailable"] = False
        if not expect_failure(root, "no-rollback", no_rollback):
            print("self-test expected missing rollback to fail", file=sys.stderr)
            return 1

        missing_response_action = fixture_coverage()
        missing_response_action["responseActions"] = [
            row
            for row in missing_response_action["responseActions"]
            if row["actionKind"] != "collect_evidence"
        ]
        if not expect_failure(root, "missing-response-action", missing_response_action):
            print("self-test expected missing response action kind to fail", file=sys.stderr)
            return 1

        unreceipted_response_action = fixture_coverage()
        unreceipted_response_action["responseActions"][0].pop("receiptId")
        if not expect_failure(root, "unreceipted-response-action", unreceipted_response_action):
            print("self-test expected unreceipted response action to fail", file=sys.stderr)
            return 1

        weak_response_receipt = fixture_coverage()
        weak_response_receipt["responseActions"][0].pop("processTreeSha256")
        if not expect_failure(root, "weak-response-receipt", weak_response_receipt):
            print("self-test expected weak response receipt binding to fail", file=sys.stderr)
            return 1

        cloud_dependent = fixture_coverage()
        cloud_dependent["localFirst"]["cloudUnavailableDecisionVerified"] = False
        if not expect_failure(root, "cloud-dependent", cloud_dependent):
            print("self-test expected cloud-dependent local-first evidence to fail", file=sys.stderr)
            return 1

        no_staging = fixture_coverage()
        no_staging["workflowRuns"][8].pop("stagedDetectionGenerated")
        no_staging["workflowRuns"][8].pop("stagedDetectionId")
        if not expect_failure(root, "no-staging", no_staging):
            print("self-test expected missing staged detection to fail", file=sys.stderr)
            return 1

        no_export = fixture_coverage()
        no_export["operatorExport"]["verified"] = False
        if not expect_failure(root, "no-export", no_export):
            print("self-test expected unverified operator export to fail", file=sys.stderr)
            return 1

    print("operator workflows proof self-test passed")
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
        result = build_operator_proof(args)
    except ValueError as exc:
        print(f"operator workflows proof failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
