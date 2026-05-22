#!/usr/bin/env python3
"""Audit Endpoint Decision Engine readiness evidence.

This is a completion-audit helper, not a live dogfood runner. It maps the
north-star EDR requirements to concrete artifacts and returns ready=false unless
the evidence bundle covers every required objective.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import pathlib
import sys
import tempfile
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
SUPPLEMENTAL_PROOF_KEYS = {
    "policy_simulation_impact",
    "ai_agent_developer_workstation",
    "endpoint_deception",
    "supply_chain_runtime_guard",
    "privacy_preserving_telemetry",
    "operator_workflows",
    "cross_platform_sensor_breadth",
}
EXPECTED_BRIDGE_SCRIPTS = {
    "policy_simulation_impact": "policy-simulation-impact-proof.py",
    "ai_agent_developer_workstation": "ai-agent-developer-workstation-proof.py",
    "endpoint_deception": "endpoint-deception-proof.py",
    "supply_chain_runtime_guard": "supply-chain-runtime-guard-proof.py",
    "privacy_preserving_telemetry": "privacy-preserving-telemetry-proof.py",
    "operator_workflows": "operator-workflows-proof.py",
    "cross_platform_sensor_breadth": "cross-platform-sensor-breadth-proof.py",
}
AUDIT_FIELDS = {
    "schemaVersion",
    "generatedAt",
    "objective",
    "provenance",
    "ready",
    "counts",
    "macosProviderManifestVerification",
    "checklist",
    "unresolved",
    "auditSha256",
}
AUDIT_PROVENANCE_FIELDS = {
    "macosProviderManifest",
    "supplementalProofs",
    "supplementalSourceManifest",
    "qualificationBundleDir",
    "qualificationMetadata",
    "externalEvidenceAllowed",
    "externalOutputAllowed",
}
AUDIT_SOURCE_MANIFEST_PROVENANCE_FIELDS = {
    "path",
    "sha256",
    "verified",
    "evidenceMode",
    "proofRoot",
    "sourceRoot",
    "sourceArtifactCount",
    "generatedProofCount",
    "bridgeScriptCount",
    "externalSourceArtifacts",
}
AUDIT_CHECKLIST_ITEM_FIELDS = {"key", "promptRequirement", "status", "evidence", "gaps"}
AUDIT_MANIFEST_VERIFICATION_FIELDS = {
    "verified",
    "failureCount",
    "failures",
    "warnings",
    "runId",
    "runRoot",
    "fileCount",
    "totalBytes",
    "inventorySha256",
    "freshGateVerified",
}
SUPPLEMENTAL_SOURCE_MANIFEST_KIND = (
    "clawdstrike.endpoint_decision_engine.supplemental_proof_source_manifest.v1"
)
ALLOWED_POLICY_HISTORY_SOURCES = {
    "policy_event_stream",
    "flight_recorder_history",
    "causal_graph_slice",
    "endpoint_history_replay",
}
MAX_POLICY_HISTORY_WINDOW_SECONDS = 604800
REQUIRED_OPERATOR_WORKFLOWS = {
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
REQUIRED_OPERATOR_ROUTES = {
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
REQUIRED_OPERATOR_RECEIPT_FAMILIES = {
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
REQUIRED_SENSOR_MODULES = {
    "process",
    "file",
    "network",
    "dns",
    "persistence",
    "identity",
    "browser",
    "package_manager",
    "secrets",
}
REQUIRED_SENSOR_PLATFORMS = {
    "macos",
    "linux",
    "windows",
}
REQUIRED_SENSOR_INGESTION_ROUTES = {
    "/api/v1/agent/edr/developer-activity",
    "/api/v1/agent/edr/package-manager/events",
    "/api/v1/agent/edr/endpoint-security/events",
    "/api/v1/agent/edr/network-extension/events",
    "/api/v1/agent/edr/policy-events",
}
REQUIRED_SENSOR_EVENT_KINDS = {
    "process_exec",
    "file_access",
    "file_write",
    "network_flow",
    "dns_lookup",
    "launch_persistence",
    "identity_context",
    "browser_download",
    "package_script",
    "shell_command",
    "tool_call",
    "credential_access",
    "policy_decision",
}
REQUIRED_SENSOR_IDENTITY_FIELDS = {
    "host_id",
    "user_id",
    "session_id",
    "agent_id",
    "workload_id",
    "approval_id",
}
REQUIRED_GRAPH_NODE_KINDS = {
    "process",
    "file",
    "network",
    "dns_name",
    "package_script",
    "credential",
    "browser_download",
    "policy_decision",
    "tool",
}
REQUIRED_GRAPH_EDGE_KINDS = {
    "observed_on",
    "ran_as",
    "in_session",
    "used_agent",
    "spawned",
    "executed",
    "read",
    "wrote",
    "connected",
    "resolved_dns",
    "ran_script",
    "downloaded",
    "accessed_credential",
    "made_decision",
}
REQUIRED_AI_AGENT_RUNTIMES = {
    "mcp",
    "browser_automation",
    "shell_agent",
    "package_manager",
    "cloud_cli",
}
REQUIRED_AI_AGENT_PROTECTED_SURFACES = {
    "mcp_server",
    "browser_automation",
    "shell_agent",
    "local_api_key",
    "repo_secret",
    "package_manager",
    "ci_token",
    "cloud_cli",
    "prompt_injected_tool_execution",
}
REQUIRED_AI_AGENT_SECRET_KINDS = {
    "local_api_key",
    "repo_secret",
    "ci_token",
    "browser_cookie",
    "package_registry_token",
    "cloud_credential",
}
REQUIRED_AI_AGENT_IDENTITY_FIELDS = {
    "host_id",
    "user_id",
    "session_id",
    "agent_id",
    "workload_id",
    "approval_id",
    "tool_call_id",
}
REQUIRED_AI_AGENT_COLLECTOR_KINDS = {
    "adapter_core_tool_interceptor",
    "browser_runtime",
    "package_manager_lifecycle_hook",
    "repo_scanner",
    "ci_agent",
    "mcp_policy_check",
}
REQUIRED_DECEPTION_HONEY_KINDS = {
    "file",
    "ssh_key",
    "browser_cookie",
    "api_token",
    "hostname",
}
REQUIRED_SUPPLY_CHAIN_PACKAGE_MANAGERS = {
    "npm",
    "pip",
    "cargo",
}
REQUIRED_SUPPLY_CHAIN_SURFACES = {
    "package_install_script",
    "unsigned_binary",
    "signature_drift",
    "dynamic_library_injection",
    "launch_persistence",
    "browser_extension",
    "developer_tool",
}
REQUIRED_SUPPLY_CHAIN_RULE_IDS = {
    "supply_chain.install_script.risky",
    "supply_chain.unsigned_binary.dev_path",
    "supply_chain.signature_drift",
    "supply_chain.package_manager_dylib_injection",
    "supply_chain.dylib_injection",
    "supply_chain.launch_persistence",
    "supply_chain.unmanaged_browser_extension",
    "supply_chain.developer_secret_access",
    "supply_chain.package_registry_token_operation",
    "supply_chain.cloud_cli_sensitive_operation",
}
REQUIRED_PRIVACY_PROJECTION_CLASSES = {
    "hash_only",
    "metadata_only",
    "local_only",
    "raw_artifact_permitted",
}
SUPPLEMENTAL_PROMPTS = {
    "policy_simulation_impact": "Before enforcement, replay recent history and show what would break.",
    "ai_agent_developer_workstation": "Protect MCP, browser automation, local API keys, repo secrets, package managers, CI tokens, cloud CLIs, and prompt-injected tools.",
    "endpoint_deception": "Honey files, fake keys/cookies/tokens/hostnames must produce high-confidence causal findings.",
    "supply_chain_runtime_guard": "Watch package managers, unsigned binaries, signature drift, install scripts, dylib injection, persistence, extensions, and developer tools.",
    "privacy_preserving_telemetry": "Classify locally, send hashes/features/summaries by default, and upload raw artifacts only by policy.",
    "operator_workflows": "Support process-cause, replay, safe containment, agent secret touch, causal grouping, proof-at-execution, and staged detection workflows.",
    "cross_platform_sensor_breadth": "Sensor modules include process, file, network, DNS, persistence, identity, browser, package manager, and secrets.",
}
SUPPLEMENTAL_EVIDENCE_TEMPLATES = {
    "policy_simulation_impact": {
        "policyHash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "policyEpoch": 1,
        "graphSliceId": "graph-slice-id",
        "eventStreamSha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "resultSha256": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "currentPolicyRef": "current-policy.yaml",
        "proposedPolicyRef": "proposed-policy.yaml",
        "impactEngine": "cli_policy_impact",
        "impactLevel": "medium",
        "recommendedStage": "audit",
        "developerBreakageScore": 0,
        "changedVerdictCount": 2,
        "blockingChangeCount": 1,
        "replayedEventCount": 4,
        "historySource": "policy_event_stream",
        "historyWindowSeconds": 86400,
        "auditModeSupported": True,
        "stagedEnforcementSupported": True,
        "simulationReceiptId": "simulation:receipt-id",
        "simulationReceiptSha256": "sha256:abababababababababababababababababababababababababababababababab",
        "breakageDriversSha256": "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "breakageDriverCount": 1,
        "simulationReceiptFamily": "simulation",
    },
    "ai_agent_developer_workstation": {
        "rawSecretsOmitted": True,
        "rawValueOmissionSha256": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "secretTouchCount": 1,
        "agentIdentityCount": 1,
        "coveredRuntimes": sorted(REQUIRED_AI_AGENT_RUNTIMES),
        "protectedSurfaces": sorted(REQUIRED_AI_AGENT_PROTECTED_SURFACES),
        "secretKinds": sorted(REQUIRED_AI_AGENT_SECRET_KINDS),
        "identityFields": sorted(REQUIRED_AI_AGENT_IDENTITY_FIELDS),
        "collectorKinds": sorted(REQUIRED_AI_AGENT_COLLECTOR_KINDS),
        "activityReceiptsBound": True,
        "causalGraphActivityCoverage": True,
        "activityReceiptCount": 9,
        "activityGraphNodeCount": 9,
        "activityGraphEdgeCount": 9,
        "activityCausalGraphSha256": "sha256:4545454545454545454545454545454545454545454545454545454545454545",
    },
    "endpoint_deception": {
        "materializationReceipt": True,
        "detectionReceipt": True,
        "causalProcessTree": True,
        "materializationReceiptId": "deception_materialization:receipt-id",
        "detectionReceiptId": "detection:receipt-id",
        "findingId": "finding-id",
        "detectionRuleId": "deception.honey_artifact_touched",
        "causalGraphSliceId": "graph-slice-id",
        "materializationReceiptSha256": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
        "detectionReceiptSha256": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
        "causalGraphSha256": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
        "materializedArtifactCount": 5,
        "touchedArtifactCount": 1,
        "materializationReceiptBindsHoneyArtifacts": True,
        "detectionReceiptBindsMaterialization": True,
        "detectionReceiptBindsCausalGraph": True,
        "detectionReceiptBindsTouchedArtifact": True,
        "graphProcessNodeCount": 1,
        "touchedHoneyGraphBindingCount": 1,
        "honeyKinds": sorted(REQUIRED_DECEPTION_HONEY_KINDS),
    },
    "supply_chain_runtime_guard": {
        "packageScriptObservation": True,
        "unsignedOrSignatureDriftCoverage": True,
        "persistenceCoverage": True,
        "packageScriptObservationSha256": "sha256:7777777777777777777777777777777777777777777777777777777777777777",
        "signatureOrDriftEvidenceSha256": "sha256:8888888888888888888888888888888888888888888888888888888888888888",
        "persistenceEvidenceSha256": "sha256:9999999999999999999999999999999999999999999999999999999999999999",
        "browserExtensionEvidenceSha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "developerToolEvidenceSha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "supplyChainGraphSha256": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        "receiptBindingVerified": True,
        "graphObservationCoverage": True,
        "receiptBindingCount": 10,
        "graphObservationNodeCount": 10,
        "graphEdgeCount": 10,
        "packageManagers": sorted(REQUIRED_SUPPLY_CHAIN_PACKAGE_MANAGERS),
        "coveredSurfaces": sorted(REQUIRED_SUPPLY_CHAIN_SURFACES),
        "findingRuleIds": sorted(REQUIRED_SUPPLY_CHAIN_RULE_IDS),
        "observedPackageScriptCount": 1,
        "observedBinaryDriftCount": 2,
        "observedDylibInjectionCount": 2,
        "observedPersistenceCount": 1,
        "observedBrowserExtensionCount": 1,
        "observedDeveloperToolCount": 3,
        "evidenceReceiptCount": 1,
    },
    "privacy_preserving_telemetry": {
        "privacyReceiptFamily": "privacy_report",
        "defaultProjection": "hashes_features",
        "rawArtifactsSuppressedByDefault": True,
        "rawArtifactsRequireApproval": True,
        "localClassification": True,
        "rawArtifactsDowngradedWithoutApproval": True,
        "rawArtifactsPolicyGateVerified": True,
        "rawArtifactsAllowedOnlyWithApproval": True,
        "rawValuesOmittedFromDefaultReport": True,
        "rawValuesPresentOnlyInApprovedReport": True,
        "privacyReportId": "telemetry_privacy_report:report-id",
        "privacyReceiptId": "privacy_receipt:report-id",
        "rawArtifactApprovalId": "approval-id",
        "rawArtifactApprovalReasonHash": "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "privacyReceiptBindsReport": True,
        "privacyReceiptBindsApproval": True,
        "defaultReportSha256": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "privacyPolicyDecisionSha256": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "downgradedRawRequestSha256": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "approvedRawReportSha256": "sha256:abababababababababababababababababababababababababababababababab",
        "privacyReceiptSha256": "sha256:bcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbcbc",
        "projectionClasses": sorted(REQUIRED_PRIVACY_PROJECTION_CLASSES),
        "observationCount": 1,
        "fieldCount": 3,
        "hashOnlyCount": 1,
        "metadataOnlyCount": 1,
        "localOnlyCount": 1,
        "rawSuppressedCount": 1,
        "approvedRawArtifactCount": 1,
    },
    "operator_workflows": {
        "workflows": sorted(REQUIRED_OPERATOR_WORKFLOWS),
        "workflowRoutes": sorted(REQUIRED_OPERATOR_ROUTES),
        "receiptFamilies": sorted(REQUIRED_OPERATOR_RECEIPT_FAMILIES),
        "responseActionKinds": sorted(REQUIRED_RESPONSE_ACTION_KINDS),
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
        "workflowRunSetSha256": "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "operatorExportSha256": "sha256:dededededededededededededededededededededededededededededededede",
        "proofPackageSha256": "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "responseActionCoverageSha256": "sha256:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
        "localFirstProofSha256": "sha256:abababababababababababababababababababababababababababababababab",
        "workflowRunCount": 9,
        "routeCount": 10,
        "receiptFamilyCount": 5,
        "safeContainmentTtlSeconds": 600,
        "responseActionCount": 7,
        "maxWorkflowLatencyMs": 1000,
        "workflowLatencyBoundMs": 10000,
    },
    "cross_platform_sensor_breadth": {
        "sensors": sorted(REQUIRED_SENSOR_MODULES),
        "sensorPlatforms": sorted(REQUIRED_SENSOR_PLATFORMS),
        "ingestionRoutes": sorted(REQUIRED_SENSOR_INGESTION_ROUTES),
        "eventKinds": sorted(REQUIRED_SENSOR_EVENT_KINDS),
        "identityFields": sorted(REQUIRED_SENSOR_IDENTITY_FIELDS),
        "graphNodeKinds": sorted(REQUIRED_GRAPH_NODE_KINDS),
        "graphEdgeKinds": sorted(REQUIRED_GRAPH_EDGE_KINDS),
        "localIngestionVerified": True,
        "identityContextCoverage": True,
        "redactionCoverage": True,
        "graphPersistenceCoverage": True,
        "causalQueriesVerified": True,
        "processTreeCoverage": True,
        "upstreamDownstreamCoverage": True,
        "sensorInventorySha256": "sha256:1212121212121212121212121212121212121212121212121212121212121212",
        "eventCoverageSha256": "sha256:3434343434343434343434343434343434343434343434343434343434343434",
        "ingestionRouteCoverageSha256": "sha256:5656565656565656565656565656565656565656565656565656565656565656",
        "graphSliceSha256": "sha256:7878787878787878787878787878787878787878787878787878787878787878",
        "sensorModuleCount": 9,
        "platformCount": 3,
        "eventKindCount": 13,
        "ingestionRouteCount": 5,
    },
}


def build_supplemental_proof_template(key: str) -> dict[str, Any]:
    if key not in SUPPLEMENTAL_PROOF_KEYS:
        raise ValueError(f"unsupported proof key: {key}")
    return {
        "schemaVersion": 1,
        "key": key,
        "promptRequirement": SUPPLEMENTAL_PROMPTS[key],
        "evidenceTemplate": SUPPLEMENTAL_EVIDENCE_TEMPLATES[key],
        "artifactRequirements": [
            "Provide at least one --proof-artifact file containing durable evidence for this key.",
            "Provide at least one --proof-command-result JSON file for the command that produced or verified the evidence.",
            "The proof writer computes SHA-256 hashes and byte counts; do not hand-edit them.",
        ],
        "commandResultTemplate": {
            "argv": ["replace-with", "exact", "command", "argv"],
            "exitCode": 0,
            "summary": "short human-readable command result",
        },
        "writeProofExample": (
            "scripts/endpoint-decision-engine-readiness-audit.py "
            f"--write-proof {key} "
            "--proof-output proof.json "
            "--proof-evidence evidence.json "
            "--proof-artifact evidence-artifact.json "
            "--proof-command-result command-result.json"
        ),
    }


def load_module(path: pathlib.Path) -> Any:
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def audit_payload_sha256(audit: dict[str, Any]) -> str:
    payload = dict(audit)
    payload.pop("auditSha256", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def attach_audit_digest(audit: dict[str, Any]) -> dict[str, Any]:
    payload = dict(audit)
    payload["auditSha256"] = audit_payload_sha256(payload)
    return payload


def reject_unsupported_fields(
    value: dict[str, Any],
    allowed: set[str],
    label: str,
    failures: list[str],
) -> None:
    unsupported_fields = sorted(set(value) - allowed)
    if unsupported_fields:
        failures.append(f"{label} contains unsupported fields: {', '.join(unsupported_fields)}")


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def require_bool_field(value: dict[str, Any], field: str, label: str, failures: list[str]) -> None:
    if not isinstance(value.get(field), bool):
        failures.append(f"{label}.{field} must be a boolean")


def require_optional_bool_field(
    value: dict[str, Any],
    field: str,
    label: str,
    failures: list[str],
) -> None:
    if value.get(field) is not None and not isinstance(value.get(field), bool):
        failures.append(f"{label}.{field} must be a boolean or null")


def require_nonnegative_int_field(
    value: dict[str, Any],
    field: str,
    label: str,
    failures: list[str],
) -> None:
    if not is_nonnegative_int(value.get(field)):
        failures.append(f"{label}.{field} must be a non-negative integer")


def require_string_list_field(
    value: dict[str, Any],
    field: str,
    label: str,
    failures: list[str],
) -> None:
    items = value.get(field)
    if not isinstance(items, list):
        failures.append(f"{label}.{field} must be a list")
        return
    for index, item in enumerate(items):
        if not isinstance(item, str):
            failures.append(f"{label}.{field}[{index}] must be a string")


def require_count_map_field(
    value: dict[str, Any],
    field: str,
    label: str,
    failures: list[str],
) -> None:
    counts = value.get(field)
    if not isinstance(counts, dict):
        failures.append(f"{label}.{field} must be an object of non-negative integer counts")
        return
    for key, count in counts.items():
        if not isinstance(key, str) or not is_nonnegative_int(count):
            failures.append(f"{label}.{field} must be an object of non-negative integer counts")
            return


def require_string_map_field(
    value: dict[str, Any],
    field: str,
    label: str,
    failures: list[str],
) -> None:
    items = value.get(field)
    if not isinstance(items, dict):
        failures.append(f"{label}.{field} must be an object")
        return
    for key, item in items.items():
        if not isinstance(key, str) or not isinstance(item, str):
            failures.append(f"{label}.{field} must be a string map")
            return


def source_manifest_provenance_record(path: pathlib.Path) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    digest = file_digest(resolved)
    record: dict[str, Any] = {
        "path": str(resolved),
        "sha256": digest["sha256"],
    }
    try:
        source_manifest = load_json_object(resolved)
    except Exception:  # noqa: BLE001 - verifier will report precise manifest parse failure later.
        return record
    for field in ("proofRoot", "sourceRoot"):
        raw_dir = source_manifest.get(field)
        if isinstance(raw_dir, str) and raw_dir.strip():
            candidate = pathlib.Path(raw_dir).expanduser()
            candidate = candidate if candidate.is_absolute() else resolved.parent / candidate
            if candidate.is_dir():
                record[field] = str(candidate.resolve())
    evidence_mode = source_manifest.get("evidenceMode")
    if isinstance(evidence_mode, str) and evidence_mode.strip():
        record["evidenceMode"] = evidence_mode
    source_artifacts = source_manifest.get("sourceArtifacts")
    if isinstance(source_artifacts, dict):
        coverage_inputs = source_artifacts.get("coverageInputs")
        if isinstance(coverage_inputs, dict):
            record["sourceArtifactCount"] = 2 + len(coverage_inputs)
    generated_proofs = source_manifest.get("generatedProofs")
    if isinstance(generated_proofs, dict):
        record["generatedProofCount"] = len(generated_proofs)
    bridge_scripts = source_manifest.get("bridgeScripts")
    if isinstance(bridge_scripts, dict):
        record["bridgeScriptCount"] = len(bridge_scripts)
    return record


def write_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_digest(path: pathlib.Path) -> dict[str, Any]:
    payload = path.read_bytes()
    return {
        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "byteSize": len(payload),
    }


def resolve_manifest_record_path(record: dict[str, Any], base_dir: pathlib.Path) -> pathlib.Path | None:
    raw_path = record.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    candidate = pathlib.Path(raw_path)
    return candidate if candidate.is_absolute() else base_dir / candidate


def resolve_manifest_dir_path(raw_path: Any, base_dir: pathlib.Path) -> pathlib.Path | None:
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    candidate = pathlib.Path(raw_path).expanduser()
    return candidate if candidate.is_absolute() else base_dir / candidate


def is_under_directory(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(root.expanduser().resolve())
    except ValueError:
        return False
    return True


def verify_source_manifest_directory(
    raw_path: Any,
    label: str,
    base_dir: pathlib.Path,
    failures: list[str],
) -> pathlib.Path | None:
    resolved = resolve_manifest_dir_path(raw_path, base_dir)
    if resolved is None:
        failures.append(f"{label} must be a non-empty path")
        return None
    if not resolved.is_dir():
        failures.append(f"{label} must reference an existing directory")
        return None
    return resolved.expanduser().resolve()


def verify_source_manifest_record(
    record: Any,
    label: str,
    base_dir: pathlib.Path,
    failures: list[str],
    required_root: pathlib.Path | None = None,
    allowed_external_path: pathlib.Path | None = None,
) -> None:
    if not isinstance(record, dict):
        failures.append(f"{label} must be an object")
        return
    unsupported_fields = sorted(set(record) - {"path", "sha256", "byteSize"})
    if unsupported_fields:
        failures.append(
            f"{label} contains unsupported fields: {', '.join(unsupported_fields)}"
        )
    resolved = resolve_manifest_record_path(record, base_dir)
    if resolved is None:
        failures.append(f"{label}.path must be a non-empty path")
        return
    if not resolved.is_file():
        failures.append(f"{label}.path must reference an existing file")
        return
    if (
        required_root is not None
        and not is_under_directory(resolved, required_root)
        and (
            allowed_external_path is None
            or resolved.expanduser().resolve() != allowed_external_path.expanduser().resolve()
        )
    ):
        failures.append(f"{label}.path must resolve inside supplemental source manifest sourceRoot")
    expected_hash = record.get("sha256")
    expected_size = record.get("byteSize")
    if not isinstance(expected_hash, str) or not expected_hash.startswith("sha256:"):
        failures.append(f"{label}.sha256 must be present")
        return
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
        failures.append(f"{label}.byteSize must be present")
        return
    current = file_digest(resolved)
    if expected_hash != current["sha256"]:
        failures.append(f"{label}.sha256 no longer matches current file")
    if expected_size != current["byteSize"]:
        failures.append(f"{label}.byteSize no longer matches current file")


def verify_source_manifest_proof_record(
    record: Any,
    label: str,
    base_dir: pathlib.Path,
    proof_root: pathlib.Path,
    supplemental_proofs: dict[str, pathlib.Path],
    key: str,
    failures: list[str],
) -> None:
    before_count = len(failures)
    verify_source_manifest_record(record, label, base_dir, failures)
    if len(failures) != before_count or not isinstance(record, dict):
        return
    resolved = resolve_manifest_record_path(record, base_dir)
    if resolved is None:
        return
    expected = supplemental_proofs.get(key)
    if not is_under_directory(resolved, proof_root):
        if expected is None or resolved.expanduser().resolve() != expected.expanduser().resolve():
            failures.append(
                f"{label}.path must resolve inside supplemental source manifest proofRoot "
                f"or match provenance.supplementalProofs.{key}"
            )
    if expected is not None and resolved.expanduser().resolve() != expected.expanduser().resolve():
        failures.append(f"{label}.path does not match provenance.supplementalProofs.{key}")


def resolve_source_policy_ref_path(policy_ref: str, base_dir: pathlib.Path) -> pathlib.Path | None:
    candidate = pathlib.Path(policy_ref).expanduser()
    resolved = candidate if candidate.is_absolute() else base_dir / candidate
    return resolved if resolved.is_file() else None


def verify_source_manifest_policy(
    policy: Any,
    base_dir: pathlib.Path,
    failures: list[str],
) -> None:
    if not isinstance(policy, dict):
        failures.append("supplemental source manifest policy must be an object")
        return
    unsupported_fields = sorted(
        set(policy) - {"currentPolicyRef", "proposedPolicyRef", "proposedPolicyHash", "policyEpoch"}
    )
    if unsupported_fields:
        failures.append(
            "supplemental source manifest policy contains unsupported fields: "
            + ", ".join(unsupported_fields)
        )
    proposed_ref = policy.get("proposedPolicyRef")
    for field in ("currentPolicyRef", "proposedPolicyRef"):
        value = policy.get(field)
        if not isinstance(value, str) or not value.strip():
            failures.append(f"supplemental source manifest policy.{field} must be non-empty")
    proposed_hash = policy.get("proposedPolicyHash")
    valid_proposed_hash = True
    if (
        not isinstance(proposed_hash, str)
        or not proposed_hash.startswith("sha256:")
        or len(proposed_hash) != 71
    ):
        failures.append("supplemental source manifest policy.proposedPolicyHash must be sha256:<64-hex>")
        valid_proposed_hash = False
    else:
        try:
            int(proposed_hash.removeprefix("sha256:"), 16)
        except ValueError:
            failures.append(
                "supplemental source manifest policy.proposedPolicyHash must be sha256:<64-hex>"
            )
            valid_proposed_hash = False
    if isinstance(proposed_ref, str) and proposed_ref.strip() and valid_proposed_hash:
        proposed_path = resolve_source_policy_ref_path(proposed_ref, base_dir)
        if proposed_path is not None and file_digest(proposed_path)["sha256"] != proposed_hash:
            failures.append(
                "supplemental source manifest policy.proposedPolicyHash no longer matches proposedPolicyRef file"
            )
    policy_epoch = policy.get("policyEpoch")
    if not isinstance(policy_epoch, int) or isinstance(policy_epoch, bool) or policy_epoch < 1:
        failures.append("supplemental source manifest policy.policyEpoch must be a positive integer")


def verify_supplemental_source_manifest_provenance(
    provenance_value: Any,
    failures: list[str],
    supplemental_proofs: dict[str, pathlib.Path] | None = None,
) -> None:
    starting_failure_count = len(failures)
    supplemental_proofs = supplemental_proofs or {}
    if not isinstance(provenance_value, dict):
        failures.append("provenance.supplementalSourceManifest must be an object")
        return
    reject_unsupported_fields(
        provenance_value,
        AUDIT_SOURCE_MANIFEST_PROVENANCE_FIELDS,
        "provenance.supplementalSourceManifest",
        failures,
    )
    require_bool_field(
        provenance_value,
        "verified",
        "provenance.supplementalSourceManifest",
        failures,
    )
    for count_field in ("sourceArtifactCount", "generatedProofCount", "bridgeScriptCount"):
        require_nonnegative_int_field(
            provenance_value,
            count_field,
            "provenance.supplementalSourceManifest",
            failures,
        )

    def finalize_verified_status() -> None:
        computed_verified = len(failures) == starting_failure_count
        if provenance_value.get("verified") is not computed_verified:
            failures.append(
                "provenance.supplementalSourceManifest.verified does not match current verification"
            )

    raw_path = provenance_value.get("path")
    expected_hash = provenance_value.get("sha256")
    if not isinstance(raw_path, str) or not raw_path.strip():
        failures.append("provenance.supplementalSourceManifest.path must be a non-empty path")
        finalize_verified_status()
        return
    if not isinstance(expected_hash, str) or not expected_hash.startswith("sha256:"):
        failures.append("provenance.supplementalSourceManifest.sha256 must be present")
        finalize_verified_status()
        return
    manifest_path = pathlib.Path(raw_path)
    if not manifest_path.is_file():
        failures.append("provenance.supplementalSourceManifest.path must reference an existing file")
        finalize_verified_status()
        return
    current_manifest = file_digest(manifest_path)
    if expected_hash != current_manifest["sha256"]:
        failures.append("provenance.supplementalSourceManifest.sha256 no longer matches current file")
        finalize_verified_status()
        return

    try:
        source_manifest = load_json_object(manifest_path)
    except Exception as exc:  # noqa: BLE001 - verification output should preserve parse failure.
        failures.append(f"provenance.supplementalSourceManifest must be valid JSON: {exc}")
        finalize_verified_status()
        return
    if source_manifest.get("schemaVersion") != 1 or isinstance(source_manifest.get("schemaVersion"), bool):
        failures.append("supplemental source manifest schemaVersion must be 1")
    unsupported_manifest_fields = sorted(
        set(source_manifest)
        - {
            "schemaVersion",
            "kind",
            "generatedAt",
            "evidenceMode",
            "proofRoot",
            "sourceRoot",
            "expectedProofKeys",
            "policy",
            "sourceArtifacts",
            "generatedProofs",
            "bridgeScripts",
        }
    )
    if unsupported_manifest_fields:
        failures.append(
            "supplemental source manifest contains unsupported fields: "
            + ", ".join(unsupported_manifest_fields)
        )
    if source_manifest.get("kind") != SUPPLEMENTAL_SOURCE_MANIFEST_KIND:
        failures.append("supplemental source manifest kind is unsupported")
    if not isinstance(source_manifest.get("generatedAt"), str) or not source_manifest["generatedAt"].strip():
        failures.append("supplemental source manifest generatedAt must be a non-empty string")
    evidence_mode = source_manifest.get("evidenceMode")
    if evidence_mode not in {"live", "fixture"}:
        failures.append("supplemental source manifest evidenceMode must be live or fixture")
    elif provenance_value.get("evidenceMode") != evidence_mode:
        failures.append(
            "provenance.supplementalSourceManifest.evidenceMode does not match current manifest"
        )
    expected_keys = source_manifest.get("expectedProofKeys")
    if not isinstance(expected_keys, list) or any(not isinstance(key, str) for key in expected_keys):
        failures.append("supplemental source manifest expectedProofKeys must be a string list")
    elif sorted(expected_keys) != sorted(SUPPLEMENTAL_PROOF_KEYS):
        failures.append("supplemental source manifest expectedProofKeys do not match verifier keys")
    proof_root = verify_source_manifest_directory(
        source_manifest.get("proofRoot"),
        "supplemental source manifest proofRoot",
        manifest_path.parent,
        failures,
    )
    source_root = verify_source_manifest_directory(
        source_manifest.get("sourceRoot"),
        "supplemental source manifest sourceRoot",
        manifest_path.parent,
        failures,
    )
    if proof_root is not None and proof_root != manifest_path.parent.expanduser().resolve():
        failures.append("supplemental source manifest proofRoot must resolve to manifest parent")
    if source_root is not None and proof_root is not None and not is_under_directory(
        source_root,
        proof_root,
    ):
        failures.append("supplemental source manifest sourceRoot must resolve inside proofRoot")
    if proof_root is not None and provenance_value.get("proofRoot") != str(proof_root):
        failures.append("provenance.supplementalSourceManifest.proofRoot does not match current manifest")
    if source_root is not None and provenance_value.get("sourceRoot") != str(source_root):
        failures.append("provenance.supplementalSourceManifest.sourceRoot does not match current manifest")
    allowed_external_sources: dict[str, pathlib.Path] = {}
    external_source_artifacts = provenance_value.get("externalSourceArtifacts")
    if isinstance(external_source_artifacts, dict):
        for key, value in sorted(external_source_artifacts.items()):
            if not isinstance(key, str) or not isinstance(value, str) or not value.strip():
                failures.append(
                    "provenance.supplementalSourceManifest.externalSourceArtifacts "
                    "must be a string map"
                )
                continue
            allowed_external_sources[key] = pathlib.Path(value).expanduser().resolve()
    elif external_source_artifacts is not None:
        failures.append(
            "provenance.supplementalSourceManifest.externalSourceArtifacts must be an object"
        )
    verify_source_manifest_policy(source_manifest.get("policy"), manifest_path.parent, failures)

    source_artifact_count: int | None = None
    actual_external_sources: dict[str, str] = {}
    source_artifacts = source_manifest.get("sourceArtifacts")
    if not isinstance(source_artifacts, dict):
        failures.append("supplemental source manifest sourceArtifacts must be an object")
    else:
        unsupported_source_artifact_fields = sorted(
            set(source_artifacts) - {"policyEvents", "policyImpactJson", "coverageInputs"}
        )
        if unsupported_source_artifact_fields:
            failures.append(
                "supplemental source manifest sourceArtifacts contains unsupported fields: "
                + ", ".join(unsupported_source_artifact_fields)
            )
        policy_events_record = source_artifacts.get("policyEvents")
        verify_source_manifest_record(
            policy_events_record,
            "supplementalSourceManifest.sourceArtifacts.policyEvents",
            manifest_path.parent,
            failures,
            source_root,
            allowed_external_sources.get("source:policyEvents"),
        )
        if isinstance(policy_events_record, dict) and source_root is not None:
            policy_events_path = resolve_manifest_record_path(policy_events_record, manifest_path.parent)
            if (
                policy_events_path is not None
                and policy_events_path.is_file()
                and not is_under_directory(policy_events_path, source_root)
            ):
                actual_external_sources["source:policyEvents"] = str(
                    policy_events_path.expanduser().resolve()
                )
        policy_impact_record = source_artifacts.get("policyImpactJson")
        verify_source_manifest_record(
            policy_impact_record,
            "supplementalSourceManifest.sourceArtifacts.policyImpactJson",
            manifest_path.parent,
            failures,
            source_root,
            allowed_external_sources.get("source:policyImpactJson"),
        )
        if isinstance(policy_impact_record, dict) and source_root is not None:
            policy_impact_path = resolve_manifest_record_path(policy_impact_record, manifest_path.parent)
            if (
                policy_impact_path is not None
                and policy_impact_path.is_file()
                and not is_under_directory(policy_impact_path, source_root)
            ):
                actual_external_sources["source:policyImpactJson"] = str(
                    policy_impact_path.expanduser().resolve()
                )
        coverage_inputs = source_artifacts.get("coverageInputs")
        expected_coverage_keys = sorted(SUPPLEMENTAL_PROOF_KEYS - {"policy_simulation_impact"})
        if not isinstance(coverage_inputs, dict):
            failures.append("supplemental source manifest coverageInputs must be an object")
        elif sorted(coverage_inputs) != expected_coverage_keys:
            failures.append("supplemental source manifest coverageInputs do not match verifier keys")
        else:
            source_artifact_count = 2 + len(coverage_inputs)
            for key in expected_coverage_keys:
                coverage_record = coverage_inputs.get(key)
                verify_source_manifest_record(
                    coverage_record,
                    f"supplementalSourceManifest.sourceArtifacts.coverageInputs.{key}",
                    manifest_path.parent,
                    failures,
                    source_root,
                    allowed_external_sources.get(f"source:coverageInputs.{key}"),
                )
                if isinstance(coverage_record, dict) and source_root is not None:
                    coverage_path = resolve_manifest_record_path(coverage_record, manifest_path.parent)
                    if (
                        coverage_path is not None
                        and coverage_path.is_file()
                        and not is_under_directory(coverage_path, source_root)
                    ):
                        actual_external_sources[f"source:coverageInputs.{key}"] = str(
                            coverage_path.expanduser().resolve()
                        )
    if {
        key: str(path)
        for key, path in sorted(allowed_external_sources.items())
    } != actual_external_sources:
        failures.append(
            "provenance.supplementalSourceManifest.externalSourceArtifacts "
            "does not match current source manifest external artifacts"
        )

    generated_proof_count: int | None = None
    generated_proofs = source_manifest.get("generatedProofs")
    if not isinstance(generated_proofs, dict):
        failures.append("supplemental source manifest generatedProofs must be an object")
    elif sorted(generated_proofs) != sorted(SUPPLEMENTAL_PROOF_KEYS):
        failures.append("supplemental source manifest generatedProofs do not match verifier keys")
    elif proof_root is not None:
        generated_proof_count = len(generated_proofs)
        for key in sorted(SUPPLEMENTAL_PROOF_KEYS):
            verify_source_manifest_proof_record(
                generated_proofs.get(key),
                f"supplementalSourceManifest.generatedProofs.{key}",
                manifest_path.parent,
                proof_root,
                supplemental_proofs,
                key,
                failures,
            )

    bridge_script_count: int | None = None
    bridge_scripts = source_manifest.get("bridgeScripts")
    if not isinstance(bridge_scripts, dict):
        failures.append("supplemental source manifest bridgeScripts must be an object")
    elif sorted(bridge_scripts) != sorted(SUPPLEMENTAL_PROOF_KEYS):
        failures.append("supplemental source manifest bridgeScripts do not match verifier keys")
    else:
        bridge_script_count = len(bridge_scripts)
        for key in sorted(SUPPLEMENTAL_PROOF_KEYS):
            bridge_record = bridge_scripts.get(key)
            verify_source_manifest_record(
                bridge_record,
                f"supplementalSourceManifest.bridgeScripts.{key}",
                manifest_path.parent,
                failures,
            )
            if isinstance(bridge_record, dict):
                bridge_path = resolve_manifest_record_path(bridge_record, manifest_path.parent)
                expected_path = SCRIPT_DIR / EXPECTED_BRIDGE_SCRIPTS[key]
                if (
                    bridge_path is not None
                    and bridge_path.expanduser().resolve() != expected_path.resolve()
                ):
                    failures.append(
                        f"supplementalSourceManifest.bridgeScripts.{key}.path "
                        f"must reference {expected_path}"
                    )
    if source_artifact_count is not None:
        recorded_source_count = provenance_value.get("sourceArtifactCount")
        if recorded_source_count != source_artifact_count:
            failures.append(
                "provenance.supplementalSourceManifest.sourceArtifactCount "
                "does not match current manifest"
            )
    if bridge_script_count is not None:
        recorded_bridge_count = provenance_value.get("bridgeScriptCount")
        if recorded_bridge_count != bridge_script_count:
            failures.append(
                "provenance.supplementalSourceManifest.bridgeScriptCount "
                "does not match current manifest"
            )
    if generated_proof_count is not None:
        recorded_generated_count = provenance_value.get("generatedProofCount")
        if recorded_generated_count != generated_proof_count:
            failures.append(
                "provenance.supplementalSourceManifest.generatedProofCount "
                "does not match current manifest"
            )
    finalize_verified_status()


def audit_reverification_projection(audit: dict[str, Any]) -> dict[str, Any]:
    manifest_verification = audit.get("macosProviderManifestVerification")
    if not isinstance(manifest_verification, dict):
        manifest_verification = {}
    checklist = audit.get("checklist")
    if not isinstance(checklist, list):
        checklist = []
    return {
        "ready": audit.get("ready"),
        "counts": audit.get("counts") if isinstance(audit.get("counts"), dict) else {},
        "unresolved": audit.get("unresolved") if isinstance(audit.get("unresolved"), list) else [],
        "macosProviderManifestVerification": {
            "verified": manifest_verification.get("verified"),
            "failureCount": manifest_verification.get("failureCount"),
            "failures": manifest_verification.get("failures"),
            "fileCount": manifest_verification.get("fileCount"),
            "totalBytes": manifest_verification.get("totalBytes"),
            "inventorySha256": manifest_verification.get("inventorySha256"),
            "freshGateVerified": manifest_verification.get("freshGateVerified"),
        },
        "checklist": [
            {
                "key": item.get("key"),
                "status": item.get("status"),
                "gaps": item.get("gaps"),
            }
            for item in checklist
            if isinstance(item, dict)
        ],
    }


def verify_audit_file(path: pathlib.Path) -> dict[str, Any]:
    failures: list[str] = []
    source_reverified: bool | None = None
    try:
        audit = load_json_object(path)
    except Exception as exc:  # noqa: BLE001 - verification output should preserve parse failure.
        return {
            "verified": False,
            "failureCount": 1,
            "failures": [f"audit file must be a JSON object: {exc}"],
        }
    if audit.get("schemaVersion") != 1 or isinstance(audit.get("schemaVersion"), bool):
        failures.append("schemaVersion must be 1")
    reject_unsupported_fields(audit, AUDIT_FIELDS, "audit", failures)
    if not isinstance(audit.get("generatedAt"), str) or not audit["generatedAt"].strip():
        failures.append("generatedAt must be a non-empty string")
    require_bool_field(audit, "ready", "audit", failures)
    require_count_map_field(audit, "counts", "audit", failures)
    require_string_list_field(audit, "unresolved", "audit", failures)
    manifest_verification = audit.get("macosProviderManifestVerification")
    if isinstance(manifest_verification, dict):
        reject_unsupported_fields(
            manifest_verification,
            AUDIT_MANIFEST_VERIFICATION_FIELDS,
            "macosProviderManifestVerification",
            failures,
        )
        require_bool_field(
            manifest_verification,
            "verified",
            "macosProviderManifestVerification",
            failures,
        )
        require_nonnegative_int_field(
            manifest_verification,
            "failureCount",
            "macosProviderManifestVerification",
            failures,
        )
        require_string_list_field(
            manifest_verification,
            "failures",
            "macosProviderManifestVerification",
            failures,
        )
        require_string_list_field(
            manifest_verification,
            "warnings",
            "macosProviderManifestVerification",
            failures,
        )
        require_nonnegative_int_field(
            manifest_verification,
            "fileCount",
            "macosProviderManifestVerification",
            failures,
        )
        require_nonnegative_int_field(
            manifest_verification,
            "totalBytes",
            "macosProviderManifestVerification",
            failures,
        )
        require_optional_bool_field(
            manifest_verification,
            "freshGateVerified",
            "macosProviderManifestVerification",
            failures,
        )
    elif manifest_verification is not None:
        failures.append("macosProviderManifestVerification must be an object")
    checklist = audit.get("checklist")
    if not isinstance(checklist, list):
        failures.append("checklist must be a list")
    else:
        for index, item in enumerate(checklist):
            if not isinstance(item, dict):
                failures.append(f"checklist[{index}] must be an object")
                continue
            reject_unsupported_fields(
                item,
                AUDIT_CHECKLIST_ITEM_FIELDS,
                f"checklist[{index}]",
                failures,
            )
            for field in ("key", "promptRequirement", "status"):
                if not isinstance(item.get(field), str) or not item[field].strip():
                    failures.append(f"checklist[{index}].{field} must be a non-empty string")
            require_string_list_field(item, "evidence", f"checklist[{index}]", failures)
            require_string_list_field(item, "gaps", f"checklist[{index}]", failures)
    recorded = audit.get("auditSha256")
    if not isinstance(recorded, str) or not recorded.startswith("sha256:"):
        failures.append("auditSha256 must be present")
        recorded = ""
    current = audit_payload_sha256(audit)
    if recorded and recorded != current:
        failures.append("auditSha256 does not match current audit payload")
    provenance = audit.get("provenance")
    if isinstance(provenance, dict):
        reject_unsupported_fields(provenance, AUDIT_PROVENANCE_FIELDS, "provenance", failures)
        qualification_metadata = provenance.get("qualificationMetadata")
        if isinstance(qualification_metadata, dict):
            for key, value in sorted(qualification_metadata.items()):
                if not isinstance(key, str) or not isinstance(value, str):
                    failures.append("provenance.qualificationMetadata must be a string map")
                    break
        elif qualification_metadata is not None:
            failures.append("provenance.qualificationMetadata must be an object")
        for field in ("externalEvidenceAllowed", "externalOutputAllowed"):
            if field in provenance and not isinstance(provenance.get(field), bool):
                failures.append(f"provenance.{field} must be boolean")
        manifest_value = provenance.get("macosProviderManifest")
        manifest_path = pathlib.Path(manifest_value) if isinstance(manifest_value, str) and manifest_value else None
        supplemental: dict[str, pathlib.Path] = {}
        supplemental_value = provenance.get("supplementalProofs")
        if isinstance(supplemental_value, dict):
            for key, value in supplemental_value.items():
                if key not in SUPPLEMENTAL_PROOF_KEYS:
                    failures.append(f"provenance.supplementalProofs has unsupported key: {key}")
                    continue
                if not isinstance(value, str) or not value.strip():
                    failures.append(f"provenance.supplementalProofs.{key} must be a non-empty path")
                    continue
                supplemental[key] = pathlib.Path(value)
        elif supplemental_value is not None:
            failures.append("provenance.supplementalProofs must be an object")
        source_manifest_value = provenance.get("supplementalSourceManifest")
        source_manifest_path: pathlib.Path | None = None
        source_manifest_external_artifacts: dict[str, str] | None = None
        if set(supplemental) == SUPPLEMENTAL_PROOF_KEYS and source_manifest_value is None:
            failures.append(
                "complete supplemental proof provenance requires "
                "provenance.supplementalSourceManifest"
            )
        if source_manifest_value is not None:
            verify_supplemental_source_manifest_provenance(
                source_manifest_value,
                failures,
                supplemental,
            )
            if isinstance(source_manifest_value, dict):
                source_manifest_path_value = source_manifest_value.get("path")
                if isinstance(source_manifest_path_value, str) and source_manifest_path_value.strip():
                    source_manifest_path = pathlib.Path(source_manifest_path_value)
                external_source_value = source_manifest_value.get("externalSourceArtifacts")
                if isinstance(external_source_value, dict):
                    source_manifest_external_artifacts = {
                        key: value
                        for key, value in external_source_value.items()
                        if isinstance(key, str) and isinstance(value, str)
                    }
        if not failures:
            rechecked = build_audit(
                manifest_path,
                supplemental,
                source_manifest_path,
                source_manifest_external_artifacts,
            )
            source_reverified = audit_reverification_projection(audit) == audit_reverification_projection(
                rechecked
            )
            if not source_reverified:
                failures.append("source evidence no longer matches recorded readiness projection")
    elif provenance is not None:
        failures.append("provenance must be an object")
    return {
        "verified": not failures,
        "failureCount": len(failures),
        "failures": failures,
        "auditPath": str(path.resolve()),
        "recordedAuditSha256": recorded or None,
        "currentAuditSha256": current,
        "sourceReverified": source_reverified,
        "ready": audit.get("ready") if isinstance(audit.get("ready"), bool) else None,
        "unresolved": audit.get("unresolved") if isinstance(audit.get("unresolved"), list) else [],
    }


def selected_artifact_path(
    manifest_path: pathlib.Path,
    manifest: dict[str, Any],
    artifact_name: str,
) -> pathlib.Path | None:
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        return None
    artifact = artifacts.get(artifact_name)
    if not isinstance(artifact, dict):
        return None
    relative_path = artifact.get("relativePath")
    if not isinstance(relative_path, str) or not relative_path.strip():
        return None
    relative = pathlib.PurePath(relative_path)
    if relative.is_absolute():
        return None
    resolved = (manifest_path.parent / relative_path).resolve()
    try:
        resolved.relative_to(manifest_path.parent.resolve())
    except ValueError:
        return None
    return resolved


def criterion(
    key: str,
    prompt_requirement: str,
    status: str,
    evidence: list[str] | None = None,
    gaps: list[str] | None = None,
) -> dict[str, Any]:
    if status not in {"verified", "partial", "missing", "failed"}:
        raise ValueError(f"invalid status for {key}: {status}")
    return {
        "key": key,
        "promptRequirement": prompt_requirement,
        "status": status,
        "evidence": evidence or [],
        "gaps": gaps or [],
    }


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def _resolve_artifact_path(base: pathlib.Path, value: Any) -> pathlib.Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = pathlib.Path(value)
    if not path.is_absolute():
        path = base / path
    return path.expanduser().resolve()


def _artifact_digest(path: pathlib.Path) -> dict[str, Any]:
    payload = path.read_bytes()
    return {
        "path": str(path),
        "sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
    }


def _artifact_reference(path: pathlib.Path, base: pathlib.Path) -> str:
    resolved = path.expanduser().resolve()
    try:
        return str(resolved.relative_to(base.expanduser().resolve()))
    except ValueError:
        return str(resolved)


def artifact_entry_for_path(path: pathlib.Path, base: pathlib.Path) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"artifact path must reference an existing file: {path}")
    digest = _artifact_digest(resolved)
    return {
        "path": _artifact_reference(resolved, base),
        "sha256": digest["sha256"],
        "bytes": digest["bytes"],
    }


def command_result_entry_for_path(path: pathlib.Path, base: pathlib.Path) -> dict[str, Any]:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"command result path must reference an existing file: {path}")
    try:
        command_result = load_json_object(resolved)
    except Exception as exc:  # noqa: BLE001 - operator CLI should return a concise validation error.
        raise ValueError(f"command result {path} must be a JSON object: {exc}") from exc
    argv = command_result.get("argv")
    if not isinstance(argv, list) or not argv or not all(
        isinstance(item, str) and item.strip() for item in argv
    ):
        raise ValueError(f"command result {path} must contain argv as a non-empty string list")
    exit_code = command_result.get("exitCode")
    if exit_code != 0 or isinstance(exit_code, bool):
        raise ValueError(f"command result {path} must contain exitCode: 0")
    digest = _artifact_digest(resolved)
    return {
        "argv": argv,
        "exitCode": 0,
        "artifactPath": _artifact_reference(resolved, base),
        "artifactSha256": digest["sha256"],
        "artifactBytes": digest["bytes"],
    }


def _artifact_entry_matches(
    entry: Any,
    proof_path: pathlib.Path,
    field: str,
    index: int,
    failures: list[str],
) -> str | None:
    if not isinstance(entry, dict):
        failures.append(f"{field}[{index}] must be an object")
        return None
    unsupported_fields = sorted(set(entry) - {"path", "sha256", "bytes"})
    if unsupported_fields:
        failures.append(
            f"{field}[{index}] contains unsupported fields: {', '.join(unsupported_fields)}"
        )
    relative_path = entry.get("path")
    resolved = _resolve_artifact_path(proof_path.parent.resolve(), relative_path)
    if resolved is None or not resolved.is_file():
        failures.append(f"{field}[{index}].path must reference an existing file")
        return None
    current = _artifact_digest(resolved)
    if entry.get("sha256") != current["sha256"]:
        failures.append(f"{field}[{index}].sha256 must match current file")
    entry_bytes = entry.get("bytes")
    if not isinstance(entry_bytes, int) or isinstance(entry_bytes, bool) or entry_bytes < 0:
        failures.append(f"{field}[{index}].bytes must be a non-negative integer")
    elif entry_bytes != current["bytes"]:
        failures.append(f"{field}[{index}].bytes must match current file")
    return f"{field}[{index}]={resolved} {current['sha256']} bytes={current['bytes']}"


def _require_artifact_entries(
    proof_path: pathlib.Path,
    values: Any,
    field: str,
    failures: list[str],
) -> list[str]:
    if not isinstance(values, list) or not values:
        failures.append(f"{field} must be a non-empty list of hashed artifact objects")
        return []
    resolved_paths: list[str] = []
    for index, value in enumerate(values):
        evidence = _artifact_entry_matches(value, proof_path, field, index, failures)
        if evidence is not None:
            resolved_paths.append(evidence)
    return resolved_paths


def _require_command_results(proof_path: pathlib.Path, value: Any, failures: list[str]) -> list[str]:
    if not isinstance(value, list) or not value:
        failures.append("commands must be a non-empty list of command result objects")
        return []
    evidence: list[str] = []
    base = proof_path.parent.resolve()
    for index, command in enumerate(value):
        if not isinstance(command, dict):
            failures.append(f"commands[{index}] must be an object")
            continue
        unsupported_fields = sorted(
            set(command) - {"argv", "exitCode", "artifactPath", "artifactSha256", "artifactBytes"}
        )
        if unsupported_fields:
            failures.append(
                f"commands[{index}] contains unsupported fields: {', '.join(unsupported_fields)}"
            )
        argv = command.get("argv")
        if not isinstance(argv, list) or not argv or not all(
            isinstance(item, str) and item.strip() for item in argv
        ):
            failures.append(f"commands[{index}].argv must be a non-empty string list")
        exit_code = command.get("exitCode")
        if exit_code != 0 or isinstance(exit_code, bool):
            failures.append(f"commands[{index}].exitCode must be 0")
        artifact_path = _resolve_artifact_path(base, command.get("artifactPath"))
        if artifact_path is None or not artifact_path.is_file():
            failures.append(f"commands[{index}].artifactPath must reference an existing file")
        else:
            current = _artifact_digest(artifact_path)
            if command.get("artifactSha256") != current["sha256"]:
                failures.append(f"commands[{index}].artifactSha256 must match current file")
            artifact_bytes = command.get("artifactBytes")
            if (
                not isinstance(artifact_bytes, int)
                or isinstance(artifact_bytes, bool)
                or artifact_bytes < 0
            ):
                failures.append(f"commands[{index}].artifactBytes must be a non-negative integer")
            elif artifact_bytes != current["bytes"]:
                failures.append(f"commands[{index}].artifactBytes must match current file")
            evidence.append(
                f"commandArtifact={artifact_path} {current['sha256']} bytes={current['bytes']}"
            )
        if isinstance(argv, list):
            evidence.append("command=" + " ".join(str(item) for item in argv))
    return evidence


def _require_bool_true(evidence: dict[str, Any], field: str, failures: list[str]) -> None:
    if evidence.get(field) is not True:
        failures.append(f"evidence.{field} must be true")


def _require_positive_int(evidence: dict[str, Any], field: str, failures: list[str]) -> None:
    value = evidence.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        failures.append(f"evidence.{field} must be a positive integer")


def _require_nonnegative_int(evidence: dict[str, Any], field: str, failures: list[str]) -> None:
    value = evidence.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        failures.append(f"evidence.{field} must be a non-negative integer")


def _require_non_empty_string(evidence: dict[str, Any], field: str, failures: list[str]) -> None:
    value = evidence.get(field)
    if not isinstance(value, str) or not value.strip():
        failures.append(f"evidence.{field} must be a non-empty string")


def _require_sha256_string(evidence: dict[str, Any], field: str, failures: list[str]) -> None:
    value = evidence.get(field)
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        failures.append(f"evidence.{field} must be a sha256:<64-hex> string")
        return
    try:
        int(value.removeprefix("sha256:"), 16)
    except ValueError:
        failures.append(f"evidence.{field} must be a sha256:<64-hex> string")


def _require_digest_string(evidence: dict[str, Any], field: str, failures: list[str]) -> None:
    value = evidence.get(field)
    if not isinstance(value, str):
        failures.append(f"evidence.{field} must be a sha256:<64-hex> or 0x<64-hex> string")
        return
    if value.startswith("sha256:") and len(value) == 71:
        hex_part = value.removeprefix("sha256:")
    elif value.startswith("0x") and len(value) == 66:
        hex_part = value.removeprefix("0x")
    else:
        failures.append(f"evidence.{field} must be a sha256:<64-hex> or 0x<64-hex> string")
        return
    try:
        int(hex_part, 16)
    except ValueError:
        failures.append(f"evidence.{field} must be a sha256:<64-hex> or 0x<64-hex> string")


def _require_contains(
    evidence: dict[str, Any],
    field: str,
    required: set[str],
    failures: list[str],
) -> None:
    actual = set(_string_list(evidence.get(field)))
    missing = sorted(required - actual)
    if missing:
        failures.append(f"evidence.{field} missing required values: {', '.join(missing)}")


def _validate_key_specific_evidence(key: str, evidence: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    if key == "policy_simulation_impact":
        _require_sha256_string(evidence, "policyHash", failures)
        _require_sha256_string(evidence, "eventStreamSha256", failures)
        _require_sha256_string(evidence, "resultSha256", failures)
        _require_sha256_string(evidence, "simulationReceiptSha256", failures)
        _require_sha256_string(evidence, "breakageDriversSha256", failures)
        for field in (
            "graphSliceId",
            "currentPolicyRef",
            "proposedPolicyRef",
            "impactLevel",
            "recommendedStage",
            "impactEngine",
            "historySource",
            "simulationReceiptId",
        ):
            _require_non_empty_string(evidence, field, failures)
        _require_positive_int(evidence, "policyEpoch", failures)
        _require_positive_int(evidence, "replayedEventCount", failures)
        _require_positive_int(evidence, "historyWindowSeconds", failures)
        _require_positive_int(evidence, "breakageDriverCount", failures)
        _require_nonnegative_int(evidence, "developerBreakageScore", failures)
        _require_nonnegative_int(evidence, "changedVerdictCount", failures)
        _require_nonnegative_int(evidence, "blockingChangeCount", failures)
        _require_bool_true(evidence, "auditModeSupported", failures)
        _require_bool_true(evidence, "stagedEnforcementSupported", failures)
        if evidence.get("impactEngine") not in {
            "cli_policy_impact",
            "agent_policy_events_impact",
            "agent_policy_events_history_impact",
            "agent_graph_policy_simulation",
            "agent_policy_replay",
        }:
            failures.append("evidence.impactEngine must name a supported policy simulation engine")
        if evidence.get("simulationReceiptFamily") != "simulation":
            failures.append("evidence.simulationReceiptFamily must be simulation")
        if evidence.get("historySource") not in ALLOWED_POLICY_HISTORY_SOURCES:
            failures.append("evidence.historySource must name a supported replay history source")
        history_window_seconds = evidence.get("historyWindowSeconds")
        if (
            isinstance(history_window_seconds, int)
            and not isinstance(history_window_seconds, bool)
            and history_window_seconds > MAX_POLICY_HISTORY_WINDOW_SECONDS
        ):
            failures.append("evidence.historyWindowSeconds must be no more than 604800")
        replayed_count = evidence.get("replayedEventCount")
        changed_count = evidence.get("changedVerdictCount")
        blocking_count = evidence.get("blockingChangeCount")
        if (
            isinstance(replayed_count, int)
            and not isinstance(replayed_count, bool)
            and isinstance(changed_count, int)
            and not isinstance(changed_count, bool)
            and changed_count > replayed_count
        ):
            failures.append("evidence.changedVerdictCount cannot exceed replayedEventCount")
        if (
            isinstance(changed_count, int)
            and not isinstance(changed_count, bool)
            and isinstance(blocking_count, int)
            and not isinstance(blocking_count, bool)
            and blocking_count > changed_count
        ):
            failures.append("evidence.blockingChangeCount cannot exceed changedVerdictCount")
    elif key == "ai_agent_developer_workstation":
        _require_bool_true(evidence, "rawSecretsOmitted", failures)
        _require_bool_true(evidence, "activityReceiptsBound", failures)
        _require_bool_true(evidence, "causalGraphActivityCoverage", failures)
        _require_sha256_string(evidence, "rawValueOmissionSha256", failures)
        _require_sha256_string(evidence, "activityCausalGraphSha256", failures)
        _require_positive_int(evidence, "secretTouchCount", failures)
        _require_positive_int(evidence, "agentIdentityCount", failures)
        _require_positive_int(evidence, "activityReceiptCount", failures)
        _require_positive_int(evidence, "activityGraphNodeCount", failures)
        _require_positive_int(evidence, "activityGraphEdgeCount", failures)
        _require_contains(
            evidence,
            "coveredRuntimes",
            REQUIRED_AI_AGENT_RUNTIMES,
            failures,
        )
        _require_contains(
            evidence,
            "protectedSurfaces",
            REQUIRED_AI_AGENT_PROTECTED_SURFACES,
            failures,
        )
        _require_contains(evidence, "secretKinds", REQUIRED_AI_AGENT_SECRET_KINDS, failures)
        _require_contains(evidence, "identityFields", REQUIRED_AI_AGENT_IDENTITY_FIELDS, failures)
        _require_contains(evidence, "collectorKinds", REQUIRED_AI_AGENT_COLLECTOR_KINDS, failures)
    elif key == "endpoint_deception":
        for field in ("materializationReceipt", "detectionReceipt", "causalProcessTree"):
            _require_bool_true(evidence, field, failures)
        for field in (
            "materializationReceiptBindsHoneyArtifacts",
            "detectionReceiptBindsMaterialization",
            "detectionReceiptBindsCausalGraph",
            "detectionReceiptBindsTouchedArtifact",
        ):
            _require_bool_true(evidence, field, failures)
        for field in (
            "materializationReceiptId",
            "detectionReceiptId",
            "findingId",
            "detectionRuleId",
            "causalGraphSliceId",
        ):
            _require_non_empty_string(evidence, field, failures)
        for field in (
            "materializationReceiptSha256",
            "detectionReceiptSha256",
            "causalGraphSha256",
        ):
            _require_sha256_string(evidence, field, failures)
        _require_positive_int(evidence, "materializedArtifactCount", failures)
        _require_positive_int(evidence, "touchedArtifactCount", failures)
        _require_positive_int(evidence, "graphProcessNodeCount", failures)
        _require_positive_int(evidence, "touchedHoneyGraphBindingCount", failures)
        if evidence.get("detectionRuleId") != "deception.honey_artifact_touched":
            failures.append("evidence.detectionRuleId must be deception.honey_artifact_touched")
        _require_contains(
            evidence,
            "honeyKinds",
            REQUIRED_DECEPTION_HONEY_KINDS,
            failures,
        )
    elif key == "supply_chain_runtime_guard":
        for field in (
            "packageScriptObservation",
            "unsignedOrSignatureDriftCoverage",
            "persistenceCoverage",
            "receiptBindingVerified",
            "graphObservationCoverage",
        ):
            _require_bool_true(evidence, field, failures)
        for field in (
            "packageScriptObservationSha256",
            "signatureOrDriftEvidenceSha256",
            "persistenceEvidenceSha256",
            "browserExtensionEvidenceSha256",
            "developerToolEvidenceSha256",
            "supplyChainGraphSha256",
        ):
            _require_sha256_string(evidence, field, failures)
        _require_contains(
            evidence,
            "packageManagers",
            REQUIRED_SUPPLY_CHAIN_PACKAGE_MANAGERS,
            failures,
        )
        _require_contains(
            evidence,
            "coveredSurfaces",
            REQUIRED_SUPPLY_CHAIN_SURFACES,
            failures,
        )
        _require_contains(
            evidence,
            "findingRuleIds",
            REQUIRED_SUPPLY_CHAIN_RULE_IDS,
            failures,
        )
        for field in (
            "observedPackageScriptCount",
            "observedBinaryDriftCount",
            "observedDylibInjectionCount",
            "observedPersistenceCount",
            "observedBrowserExtensionCount",
            "observedDeveloperToolCount",
            "evidenceReceiptCount",
            "receiptBindingCount",
            "graphObservationNodeCount",
            "graphEdgeCount",
        ):
            _require_positive_int(evidence, field, failures)
    elif key == "privacy_preserving_telemetry":
        if evidence.get("privacyReceiptFamily") != "privacy_report":
            failures.append("evidence.privacyReceiptFamily must be privacy_report")
        if evidence.get("defaultProjection") not in {
            "local_only",
            "hashes_features",
            "summary_with_receipts",
        }:
            failures.append("evidence.defaultProjection must be a non-raw projection")
        for field in (
            "rawArtifactsSuppressedByDefault",
            "rawArtifactsRequireApproval",
            "localClassification",
            "rawArtifactsDowngradedWithoutApproval",
            "rawArtifactsPolicyGateVerified",
            "rawArtifactsAllowedOnlyWithApproval",
            "rawValuesOmittedFromDefaultReport",
            "rawValuesPresentOnlyInApprovedReport",
            "privacyReceiptBindsReport",
            "privacyReceiptBindsApproval",
        ):
            _require_bool_true(evidence, field, failures)
        for field in ("privacyReportId", "privacyReceiptId", "rawArtifactApprovalId"):
            _require_non_empty_string(evidence, field, failures)
        _require_digest_string(evidence, "rawArtifactApprovalReasonHash", failures)
        for field in (
            "defaultReportSha256",
            "privacyPolicyDecisionSha256",
            "downgradedRawRequestSha256",
            "approvedRawReportSha256",
            "privacyReceiptSha256",
        ):
            _require_sha256_string(evidence, field, failures)
        _require_contains(
            evidence,
            "projectionClasses",
            REQUIRED_PRIVACY_PROJECTION_CLASSES,
            failures,
        )
        for field in (
            "observationCount",
            "fieldCount",
            "hashOnlyCount",
            "metadataOnlyCount",
            "localOnlyCount",
            "rawSuppressedCount",
            "approvedRawArtifactCount",
        ):
            _require_positive_int(evidence, field, failures)
    elif key == "operator_workflows":
        _require_contains(evidence, "workflows", REQUIRED_OPERATOR_WORKFLOWS, failures)
        _require_contains(evidence, "workflowRoutes", REQUIRED_OPERATOR_ROUTES, failures)
        _require_contains(
            evidence,
            "receiptFamilies",
            REQUIRED_OPERATOR_RECEIPT_FAMILIES,
            failures,
        )
        _require_contains(
            evidence,
            "responseActionKinds",
            REQUIRED_RESPONSE_ACTION_KINDS,
            failures,
        )
        for field in (
            "allWorkflowsVerified",
            "operatorExported",
            "containmentRollbackAvailable",
            "responseActionsAllTtlBounded",
            "responseActionsAllRollbackable",
            "responseActionsAllReceipted",
            "responseReceiptsBindPolicy",
            "responseReceiptsBindSensorState",
            "responseReceiptsBindActor",
            "responseReceiptsBindProcessTree",
            "responseReceiptsBindEvidence",
            "responseReceiptsBindConfidence",
            "responseReceiptsBindAction",
            "localFirstCloudOptional",
            "cloudUnavailableDecisionVerified",
            "natsUnavailableDecisionVerified",
            "localContainmentOfflineVerified",
            "cloudProjectionQueuedOrSuppressed",
            "stagedDetectionGenerated",
        ):
            _require_bool_true(evidence, field, failures)
        for field in (
            "workflowRunSetSha256",
            "operatorExportSha256",
            "proofPackageSha256",
            "responseActionCoverageSha256",
            "localFirstProofSha256",
        ):
            _require_sha256_string(evidence, field, failures)
        _require_positive_int(evidence, "workflowRunCount", failures)
        _require_positive_int(evidence, "routeCount", failures)
        _require_positive_int(evidence, "receiptFamilyCount", failures)
        _require_positive_int(evidence, "safeContainmentTtlSeconds", failures)
        _require_positive_int(evidence, "responseActionCount", failures)
        _require_positive_int(evidence, "maxWorkflowLatencyMs", failures)
        _require_positive_int(evidence, "workflowLatencyBoundMs", failures)
        ttl_seconds = evidence.get("safeContainmentTtlSeconds")
        if (
            isinstance(ttl_seconds, int)
            and not isinstance(ttl_seconds, bool)
            and ttl_seconds > 3600
        ):
            failures.append("evidence.safeContainmentTtlSeconds must be at most 3600")
        if isinstance(evidence.get("responseActionCount"), int) and not isinstance(
            evidence.get("responseActionCount"), bool
        ) and evidence["responseActionCount"] < len(REQUIRED_RESPONSE_ACTION_KINDS):
            failures.append("evidence.responseActionCount must cover every required action kind")
        latency = evidence.get("maxWorkflowLatencyMs")
        latency_bound = evidence.get("workflowLatencyBoundMs")
        if isinstance(latency_bound, int) and not isinstance(latency_bound, bool) and latency_bound > 10000:
            failures.append("evidence.workflowLatencyBoundMs must be at most 10000")
        if (
            isinstance(latency, int)
            and not isinstance(latency, bool)
            and isinstance(latency_bound, int)
            and not isinstance(latency_bound, bool)
            and latency > latency_bound
        ):
            failures.append("evidence.maxWorkflowLatencyMs must be within workflowLatencyBoundMs")
    elif key == "cross_platform_sensor_breadth":
        _require_contains(evidence, "sensors", REQUIRED_SENSOR_MODULES, failures)
        _require_contains(evidence, "sensorPlatforms", REQUIRED_SENSOR_PLATFORMS, failures)
        _require_contains(
            evidence,
            "ingestionRoutes",
            REQUIRED_SENSOR_INGESTION_ROUTES,
            failures,
        )
        _require_contains(evidence, "eventKinds", REQUIRED_SENSOR_EVENT_KINDS, failures)
        _require_contains(evidence, "identityFields", REQUIRED_SENSOR_IDENTITY_FIELDS, failures)
        _require_contains(evidence, "graphNodeKinds", REQUIRED_GRAPH_NODE_KINDS, failures)
        _require_contains(evidence, "graphEdgeKinds", REQUIRED_GRAPH_EDGE_KINDS, failures)
        for field in (
            "localIngestionVerified",
            "identityContextCoverage",
            "redactionCoverage",
            "graphPersistenceCoverage",
            "causalQueriesVerified",
            "processTreeCoverage",
            "upstreamDownstreamCoverage",
        ):
            _require_bool_true(evidence, field, failures)
        for field in (
            "sensorInventorySha256",
            "eventCoverageSha256",
            "ingestionRouteCoverageSha256",
            "graphSliceSha256",
        ):
            _require_sha256_string(evidence, field, failures)
        for field in (
            "sensorModuleCount",
            "platformCount",
            "eventKindCount",
            "ingestionRouteCount",
        ):
            _require_positive_int(evidence, field, failures)
    else:
        failures.append(f"unsupported supplemental proof key: {key}")
    return failures


def validate_supplemental_proof(key: str, proof_path: pathlib.Path) -> dict[str, Any]:
    failures: list[str] = []
    evidence_lines = [f"proof={proof_path}"]
    try:
        proof = load_json_object(proof_path)
    except Exception as exc:  # noqa: BLE001 - audit output should preserve parse failure.
        return criterion(key, SUPPLEMENTAL_PROMPTS[key], "failed", evidence_lines, [str(exc)])

    if proof.get("schemaVersion") != 1 or isinstance(proof.get("schemaVersion"), bool):
        failures.append("schemaVersion must be 1")
    unsupported_fields = sorted(
        set(proof) - {"schemaVersion", "key", "verified", "generatedAt", "artifacts", "commands", "evidence"}
    )
    if unsupported_fields:
        failures.append(f"proof contains unsupported fields: {', '.join(unsupported_fields)}")
    if proof.get("key") != key:
        failures.append(f"key must be {key}")
    if proof.get("verified") is not True:
        failures.append("verified must be true")
    if not isinstance(proof.get("generatedAt"), str) or not proof["generatedAt"].strip():
        failures.append("generatedAt must be a non-empty string")
    evidence_payload = proof.get("evidence")
    if not isinstance(evidence_payload, dict):
        failures.append("evidence must be an object")
        evidence_payload = {}
    else:
        unsupported_evidence_fields = sorted(
            set(evidence_payload) - set(SUPPLEMENTAL_EVIDENCE_TEMPLATES[key])
        )
        if unsupported_evidence_fields:
            failures.append(
                "evidence contains unsupported fields: "
                + ", ".join(unsupported_evidence_fields)
            )

    evidence_lines.extend(_require_artifact_entries(proof_path, proof.get("artifacts"), "artifacts", failures))
    evidence_lines.extend(_require_command_results(proof_path, proof.get("commands"), failures))
    failures.extend(_validate_key_specific_evidence(key, evidence_payload))
    for field in sorted(evidence_payload):
        value = evidence_payload[field]
        if isinstance(value, (str, int, bool)) or value is None:
            evidence_lines.append(f"{field}={value}")
        elif isinstance(value, list):
            evidence_lines.append(f"{field}={','.join(str(item) for item in value)}")

    return criterion(
        key,
        SUPPLEMENTAL_PROMPTS[key],
        "verified" if not failures else "failed",
        evidence_lines,
        failures,
    )


def is_provider_health_bound(health: Any, provider: str) -> bool:
    if not isinstance(health, dict):
        return False
    return (
        health.get("provider") == provider
        and health.get("installState") == "installed"
        and health.get("approval") == "approved"
        and health.get("runtimeState") == "active"
        and health.get("installed") is True
        and health.get("active") is True
        and health.get("healthy") is True
        and health.get("availability") == "active"
        and health.get("approvalStatus") in {"approved", "not_required"}
        and health.get("degradedReasons") in (None, [])
    )


def load_manifest_evidence(
    manifest_path: pathlib.Path | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None, dict[str, Any], dict[str, Any]]:
    if manifest_path is None:
        return None, None, {}, {
            "verified": False,
            "failureCount": 1,
            "failures": ["--macos-provider-manifest was not supplied"],
        }

    manifest_module = load_module(SCRIPT_DIR / "macos-provider-dogfood-manifest.py")
    manifest_verify = manifest_module.verify_manifest(manifest_path)
    try:
        manifest = load_json_object(manifest_path)
    except Exception as exc:  # noqa: BLE001 - audit output should preserve parse failure.
        return None, None, {}, {
            "verified": False,
            "failureCount": 1,
            "failures": [f"manifest must be readable JSON: {exc}"],
        }

    selected: dict[str, Any] = {}
    for name in (
        "deploymentEvidenceSummary",
        "endpointSecuritySummary",
        "networkExtensionSummary",
        "gateResult",
    ):
        path = selected_artifact_path(manifest_path, manifest, name)
        if path is None or not path.is_file():
            selected[name] = None
            continue
        try:
            selected[name] = load_json_object(path)
        except Exception as exc:  # noqa: BLE001 - preserve precise artifact parse failure.
            selected[name] = {"_loadError": str(exc)}

    gate_payload = selected.get("gateResult")
    return manifest, gate_payload if isinstance(gate_payload, dict) else None, selected, manifest_verify


def macos_provider_criteria(
    manifest_path: pathlib.Path | None,
    manifest: dict[str, Any] | None,
    gate: dict[str, Any] | None,
    selected: dict[str, Any],
    manifest_verify: dict[str, Any],
) -> list[dict[str, Any]]:
    if manifest_path is None or manifest is None or gate is None:
        return [
            criterion(
                "macos_provider_bundle_integrity",
                "Deep OS events must come from a signed/notarized/approved local macOS provider bundle.",
                "missing",
                gaps=["No verified macOS provider manifest was supplied."],
            ),
            criterion(
                "prove_later_manifest",
                "Evidence must be auditable and replayable later.",
                "missing",
                gaps=["No hash manifest, gate result, or fresh-gate verification evidence is available."],
            ),
        ]

    deployment = gate.get("deploymentEvidence") if isinstance(gate.get("deploymentEvidence"), dict) else {}
    endpoint_security = (
        gate.get("endpointSecurity") if isinstance(gate.get("endpointSecurity"), dict) else {}
    )
    network_extension = (
        gate.get("networkExtension") if isinstance(gate.get("networkExtension"), dict) else {}
    )
    bindings = gate.get("providerBindings") if isinstance(gate.get("providerBindings"), dict) else {}
    extension_points = bindings.get("deploymentExtensionPoints")
    if not isinstance(extension_points, list):
        extension_points = []
    es_health = bindings.get("endpointSecurityProviderHealth")
    ne_health = bindings.get("networkExtensionProviderHealth")
    es_summary = selected.get("endpointSecuritySummary")
    ne_summary = selected.get("networkExtensionSummary")
    if not isinstance(es_summary, dict):
        es_summary = {}
    if not isinstance(ne_summary, dict):
        ne_summary = {}

    manifest_ok = manifest_verify.get("verified") is True
    production_evidence_ok = manifest.get("evidenceMode") == "live"
    gate_ok = gate.get("verified") is True
    deployment_ok = deployment.get("verified") is True
    es_ok = endpoint_security.get("verified") is True
    ne_ok = network_extension.get("verified") is True
    es_bound = is_provider_health_bound(es_health, "endpoint_security")
    ne_bound = is_provider_health_bound(ne_health, "network_extension")

    checks: list[dict[str, Any]] = []
    checks.append(
        criterion(
            "macos_provider_bundle_integrity",
            "Deep OS events must come from a signed/notarized/approved local macOS provider bundle.",
            "verified"
            if (
                manifest_ok
                and production_evidence_ok
                and gate_ok
                and deployment_ok
                and "endpoint_security" in extension_points
                and "network_extension_content_filter" in extension_points
                and es_bound
                and ne_bound
            )
            else "failed",
            evidence=[
                f"manifest={manifest_path}",
                f"evidenceMode={manifest.get('evidenceMode')}",
                f"inventorySha256={manifest_verify.get('inventorySha256')}",
                f"teamId={deployment.get('teamId')}",
                f"appBundleId={deployment.get('appBundleId')}",
                f"systemExtensionBundleId={deployment.get('systemExtensionBundleId')}",
                f"extensionPoints={extension_points}",
            ],
            gaps=(
                []
                if manifest_ok and production_evidence_ok and gate_ok and deployment_ok and es_bound and ne_bound
                else manifest_verify.get("failures", [])
                + (
                    []
                    if production_evidence_ok
                    else ["macOS provider manifest evidenceMode must be live for readiness."]
                )
            ),
        )
    )
    checks.append(
        criterion(
            "causal_graph_flight_recorder",
            "Show what happened and what caused it through causal graph evidence.",
            "verified" if manifest_ok and gate_ok and es_ok and endpoint_security.get("targetHash") else "failed",
            evidence=[
                f"endpointSecuritySummary={selected_artifact_path(manifest_path, manifest, 'endpointSecuritySummary')}",
                f"probeFile={endpoint_security.get('probeFile')}",
                f"targetHash={endpoint_security.get('targetHash')}",
            ],
            gaps=[] if es_ok and endpoint_security.get("targetHash") else ["EndpointSecurity graph/receipt proof did not verify."],
        )
    )
    checks.append(
        criterion(
            "evidence_receipts",
            "Every relevant observation, decision, and response must be backed by signed receipts.",
            "verified" if manifest_ok and gate_ok and es_ok and ne_ok else "failed",
            evidence=[
                "EndpointSecurity verifier required observation receipt and sensor-state receipt metadata.",
                "NetworkExtension verifier required sensor-state receipt metadata.",
                f"gateResult={selected_artifact_path(manifest_path, manifest, 'gateResult')}",
            ],
            gaps=[] if es_ok and ne_ok else ["ES/NE receipt verifier did not pass."],
        )
    )
    context_fields = ("hostId", "userId")
    context_ok = all(
        deployment.get(field) == endpoint_security.get(field) == network_extension.get(field)
        for field in context_fields
    ) and all(network_extension.get(field) for field in ("sessionId", "agentId", "workloadId", "approvalId"))
    checks.append(
        criterion(
            "identity_aware_enforcement",
            "Decisions must bind user, device/session, agent, workload, approval, and policy context where available.",
            "verified" if gate_ok and context_ok else "failed",
            evidence=[
                f"hostId={deployment.get('hostId')}",
                f"userId={deployment.get('userId')}",
                f"sessionId={network_extension.get('sessionId')}",
                f"agentId={network_extension.get('agentId')}",
                f"workloadId={network_extension.get('workloadId')}",
                f"approvalId={network_extension.get('approvalId')}",
            ],
            gaps=[] if context_ok else ["Deployment, ES, and NE identity context did not bind cleanly."],
        )
    )
    ne_live_ok = (
        ne_ok
        and ne_summary.get("liveEnforcementProven") is True
        and isinstance(ne_summary.get("blockedFlowCount"), int)
        and not isinstance(ne_summary.get("blockedFlowCount"), bool)
        and ne_summary.get("blockedFlowCount", 0) >= 1
        and isinstance(ne_summary.get("providerReloadDelivery"), dict)
        and ne_summary["providerReloadDelivery"].get("matched") is True
    )
    checks.append(
        criterion(
            "local_controlled_response",
            "Stop activity locally without waiting for cloud verdicts.",
            "verified" if ne_live_ok else "failed",
            evidence=[
                f"target={network_extension.get('target')}",
                f"executionId={network_extension.get('executionId')}",
                f"liveEnforcementProven={ne_summary.get('liveEnforcementProven')}",
                f"blockedFlowCount={ne_summary.get('blockedFlowCount')}",
                f"providerReloadDelivery={ne_summary.get('providerReloadDelivery')}",
            ],
            gaps=[] if ne_live_ok else ["NetworkExtension live enforcement proof did not bind real flow blocking."],
        )
    )
    rollback_ok = (
        ne_ok
        and ne_summary.get("rollbackSkipped") is False
        and ne_summary.get("rollbackSucceeded") is True
        and ne_summary.get("postRollbackConnectSucceeded") is True
    )
    checks.append(
        criterion(
            "safe_autonomous_response",
            "Bounded response actions need rollback and non-bricking proof.",
            "verified" if rollback_ok else "failed",
            evidence=[
                f"rollbackSkipped={ne_summary.get('rollbackSkipped')}",
                f"rollbackSucceeded={ne_summary.get('rollbackSucceeded')}",
                f"postRollbackConnectSucceeded={ne_summary.get('postRollbackConnectSucceeded')}",
            ],
            gaps=[] if rollback_ok else ["Rollback and post-rollback reachability were not proven."],
        )
    )
    checks.append(
        criterion(
            "prove_later_manifest",
            "Evidence must be auditable and replayable later.",
            "verified"
            if manifest_ok and production_evidence_ok and manifest_verify.get("freshGateVerified") is True
            else "failed",
            evidence=[
                f"evidenceMode={manifest.get('evidenceMode')}",
                f"fileCount={manifest_verify.get('fileCount')}",
                f"totalBytes={manifest_verify.get('totalBytes')}",
                f"inventorySha256={manifest_verify.get('inventorySha256')}",
                f"freshGateVerified={manifest_verify.get('freshGateVerified')}",
            ],
            gaps=(
                []
                if manifest_ok and production_evidence_ok
                else manifest_verify.get("failures", [])
                + (
                    []
                    if production_evidence_ok
                    else ["macOS provider manifest evidenceMode must be live for prove-later readiness."]
                )
            ),
        )
    )
    return checks


def uncovered_objective_criteria(supplemental_proofs: dict[str, pathlib.Path]) -> list[dict[str, Any]]:
    missing_gap = {
        "policy_simulation_impact": "No policy replay/impact proof artifact was supplied to this audit.",
        "ai_agent_developer_workstation": "No agent/developer-workstation telemetry or secret-touch proof artifact was supplied.",
        "endpoint_deception": "No deception materialization/touch receipt proof artifact was supplied.",
        "supply_chain_runtime_guard": "No supply-chain runtime guard proof artifact was supplied.",
        "privacy_preserving_telemetry": "No privacy projection/report proof artifact was supplied.",
        "operator_workflows": "No operator-console/workflow dogfood proof artifact was supplied.",
        "cross_platform_sensor_breadth": "The macOS provider manifest covers ES/NE deployment evidence only; broader sensor breadth is not proven here.",
    }
    checks: list[dict[str, Any]] = []
    for key in (
        "policy_simulation_impact",
        "ai_agent_developer_workstation",
        "endpoint_deception",
        "supply_chain_runtime_guard",
        "privacy_preserving_telemetry",
        "operator_workflows",
        "cross_platform_sensor_breadth",
    ):
        proof_path = supplemental_proofs.get(key)
        if proof_path is not None:
            checks.append(validate_supplemental_proof(key, proof_path))
        else:
            checks.append(
                criterion(
                    key,
                    SUPPLEMENTAL_PROMPTS[key],
                    "missing",
                    gaps=[missing_gap[key]],
                )
            )
    return checks


def build_audit(
    macos_provider_manifest: pathlib.Path | None,
    supplemental_proofs: dict[str, pathlib.Path] | None = None,
    supplemental_source_manifest: pathlib.Path | None = None,
    supplemental_source_manifest_external_artifacts: dict[str, str] | None = None,
) -> dict[str, Any]:
    supplemental_proofs = supplemental_proofs or {}
    source_manifest_record: dict[str, Any] | None = None
    source_manifest_failures: list[str] = []
    if supplemental_source_manifest is not None:
        try:
            source_manifest_record = source_manifest_provenance_record(supplemental_source_manifest)
            source_manifest_record["verified"] = True
            if supplemental_source_manifest_external_artifacts:
                source_manifest_record["externalSourceArtifacts"] = dict(
                    sorted(supplemental_source_manifest_external_artifacts.items())
                )
            if source_manifest_record.get("evidenceMode") != "live":
                source_manifest_failures.append(
                    "supplemental source manifest evidenceMode must be live for readiness"
                )
            source_manifest_verification_failures: list[str] = []
            verify_supplemental_source_manifest_provenance(
                source_manifest_record,
                source_manifest_verification_failures,
                supplemental_proofs,
            )
            source_manifest_record["verified"] = not source_manifest_verification_failures
            source_manifest_failures.extend(source_manifest_verification_failures)
        except Exception as exc:  # noqa: BLE001 - audit output should preserve provenance failure.
            source_manifest_failures.append(
                f"supplemental source manifest provenance could not be recorded: {exc}"
            )
    if set(supplemental_proofs) == SUPPLEMENTAL_PROOF_KEYS and source_manifest_record is None:
        source_manifest_failures.append(
            "complete supplemental proof set requires supplemental source manifest provenance"
        )
    manifest, gate, selected, manifest_verify = load_manifest_evidence(macos_provider_manifest)
    checklist = macos_provider_criteria(
        macos_provider_manifest,
        manifest,
        gate,
        selected,
        manifest_verify,
    )
    checklist.extend(uncovered_objective_criteria(supplemental_proofs))
    if source_manifest_failures:
        for item in checklist:
            if item.get("key") == "prove_later_manifest":
                evidence = list(item.get("evidence") if isinstance(item.get("evidence"), list) else [])
                if source_manifest_record is not None:
                    evidence.extend(
                        [
                            f"supplementalSourceManifest={source_manifest_record['path']}",
                            f"supplementalSourceManifestSha256={source_manifest_record['sha256']}",
                        ]
                    )
                gaps = list(item.get("gaps") if isinstance(item.get("gaps"), list) else [])
                item["evidence"] = evidence
                item["gaps"] = gaps + source_manifest_failures
                if item.get("status") == "verified":
                    item["status"] = "failed"
                break
    ready = all(item["status"] == "verified" for item in checklist)
    counts: dict[str, int] = {}
    for item in checklist:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    provenance: dict[str, Any] = {
        "macosProviderManifest": str(macos_provider_manifest) if macos_provider_manifest else None,
        "supplementalProofs": {
            key: str(path)
            for key, path in sorted(supplemental_proofs.items())
        },
    }
    if source_manifest_record is not None:
        provenance["supplementalSourceManifest"] = source_manifest_record
    return attach_audit_digest({
        "schemaVersion": 1,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "objective": "Next-gen EDR local runtime integrity, causal evidence, controlled response",
        "provenance": provenance,
        "ready": ready,
        "counts": counts,
        "macosProviderManifestVerification": manifest_verify,
        "checklist": checklist,
        "unresolved": [
            item["key"]
            for item in checklist
            if item["status"] != "verified"
        ],
    })


def parse_proof_specs(values: list[str] | None) -> dict[str, pathlib.Path]:
    proofs: dict[str, pathlib.Path] = {}
    for value in values or []:
        if "=" not in value:
            raise ValueError("--proof must use KEY=PATH")
        key, path_text = value.split("=", 1)
        key = key.strip()
        path_text = path_text.strip()
        if key not in SUPPLEMENTAL_PROOF_KEYS:
            raise ValueError(f"unsupported proof key: {key}")
        if not path_text:
            raise ValueError(f"proof path for {key} must not be empty")
        if key in proofs:
            raise ValueError(f"duplicate proof key: {key}")
        proofs[key] = pathlib.Path(path_text)
    return proofs


def write_operator_supplemental_proof(
    key: str,
    output_path: pathlib.Path,
    evidence_path: pathlib.Path,
    artifact_paths: list[pathlib.Path],
    command_result_paths: list[pathlib.Path],
) -> dict[str, Any]:
    if key not in SUPPLEMENTAL_PROOF_KEYS:
        raise ValueError(f"unsupported proof key: {key}")
    if not artifact_paths:
        raise ValueError("--proof-artifact must be provided at least once")
    if not command_result_paths:
        raise ValueError("--proof-command-result must be provided at least once")

    try:
        evidence = load_json_object(evidence_path.expanduser().resolve())
    except Exception as exc:  # noqa: BLE001 - operator CLI should return a concise validation error.
        raise ValueError(f"evidence {evidence_path} must be a JSON object: {exc}") from exc
    evidence_failures = _validate_key_specific_evidence(key, evidence)
    if evidence_failures:
        raise ValueError(
            "invalid evidence for "
            + key
            + ": "
            + "; ".join(evidence_failures)
        )

    resolved_output = output_path.expanduser().resolve()
    base = resolved_output.parent
    artifacts = [artifact_entry_for_path(path, base) for path in artifact_paths]
    commands = [command_result_entry_for_path(path, base) for path in command_result_paths]
    proof = {
        "schemaVersion": 1,
        "key": key,
        "verified": True,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "artifacts": artifacts,
        "commands": commands,
        "evidence": evidence,
    }
    write_json(resolved_output, proof)
    result = validate_supplemental_proof(key, resolved_output)
    if result["status"] != "verified":
        raise ValueError(
            "generated proof failed validation: "
            + "; ".join(result.get("gaps") or ["unknown validation failure"])
        )
    return result


def write_supplemental_proof(
    root: pathlib.Path,
    key: str,
    evidence: dict[str, Any],
) -> pathlib.Path:
    proof_dir = root / "supplemental" / key
    proof_dir.mkdir(parents=True, exist_ok=True)
    command_artifact = proof_dir / "command-output.json"
    proof_artifact = proof_dir / "proof-artifact.json"
    command_artifact.write_text(
        json.dumps({"status": "passed", "key": key}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    proof_artifact.write_text(
        json.dumps({"evidence": evidence}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    command_digest = _artifact_digest(command_artifact)
    proof_artifact_digest = _artifact_digest(proof_artifact)
    proof_path = proof_dir / "proof.json"
    proof_path.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "key": key,
                "verified": True,
                "generatedAt": "2026-05-19T01:02:03Z",
                "artifacts": [
                    {
                        "path": str(command_artifact.relative_to(proof_dir)),
                        "sha256": command_digest["sha256"],
                        "bytes": command_digest["bytes"],
                    },
                    {
                        "path": str(proof_artifact.relative_to(proof_dir)),
                        "sha256": proof_artifact_digest["sha256"],
                        "bytes": proof_artifact_digest["bytes"],
                    },
                ],
                "commands": [
                    {
                        "argv": ["clawdstrike-proof", key],
                        "exitCode": 0,
                        "artifactPath": str(command_artifact.relative_to(proof_dir)),
                        "artifactSha256": command_digest["sha256"],
                        "artifactBytes": command_digest["bytes"],
                    }
                ],
                "evidence": evidence,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return proof_path


def source_manifest_file_record(
    path: pathlib.Path,
    display_path: pathlib.Path | str | None = None,
) -> dict[str, Any]:
    digest = file_digest(path)
    return {
        "path": str(display_path if display_path is not None else path),
        "sha256": digest["sha256"],
        "byteSize": digest["byteSize"],
    }


def write_synthetic_supplemental_source_manifest(
    root: pathlib.Path,
    supported_keys: set[str],
) -> pathlib.Path:
    source_root = root / "source-artifacts"
    source_root.mkdir(parents=True, exist_ok=True)
    policy_dir = source_root / "policies"
    policy_dir.mkdir(parents=True, exist_ok=True)
    policy_events = source_root / "policy-events.jsonl"
    policy_impact = source_root / "policy-impact.json"
    current_policy = policy_dir / "current-policy.yaml"
    proposed_policy = policy_dir / "proposed-policy.yaml"
    policy_events.write_text(
        "".join(
            json.dumps(
                {
                    "schemaVersion": 1,
                    "eventId": f"evt-{index}",
                    "eventType": "tool_call",
                }
            )
            + "\n"
            for index in range(1, 5)
        ),
        encoding="utf-8",
    )
    current_policy.write_text("schemaVersion: 1\nname: self-test-current\n", encoding="utf-8")
    proposed_policy.write_text("schemaVersion: 1\nname: self-test-proposed\n", encoding="utf-8")
    write_json(
        policy_impact,
        {
            "version": 1,
            "command": "policy_impact",
            "summary": {
                "total": 4,
                "changed": 2,
                "allow_to_warn": 1,
                "allow_to_block": 1,
                "warn_to_allow": 0,
                "warn_to_block": 0,
                "block_to_allow": 0,
                "block_to_warn": 0,
            },
            "historySource": "policy_event_stream",
            "historyWindowSeconds": 86400,
            "auditModeSupported": True,
            "stagedEnforcementSupported": True,
            "breakageDrivers": [
                {
                    "workflow": "developer_shell",
                    "changedVerdicts": 2,
                    "blockingChanges": 1,
                }
            ],
            "receipt": {
                "receiptId": "simulation:readiness-source-fixture",
                "metadata": {
                    "endpointDecision": {
                        "receiptFamily": "simulation",
                    },
                },
            },
            "exit_code": 0,
        },
    )
    coverage_inputs: dict[str, Any] = {}
    for key in sorted(supported_keys - {"policy_simulation_impact"}):
        path = source_root / f"{key}.json"
        write_json(path, {"schemaVersion": 1, "coverageKey": key})
        coverage_inputs[key] = source_manifest_file_record(path, path.relative_to(root))
    generated_proofs = {
        key: source_manifest_file_record(
            root / "supplemental" / key / "proof.json",
            pathlib.Path("supplemental") / key / "proof.json",
        )
        for key in sorted(supported_keys)
    }
    source_manifest = {
        "schemaVersion": 1,
        "kind": SUPPLEMENTAL_SOURCE_MANIFEST_KIND,
        "generatedAt": "2026-05-19T01:02:03Z",
        "evidenceMode": "fixture",
        "proofRoot": ".",
        "sourceRoot": "source-artifacts",
        "expectedProofKeys": sorted(supported_keys),
        "policy": {
            "currentPolicyRef": str(current_policy.relative_to(root)),
            "proposedPolicyRef": str(proposed_policy.relative_to(root)),
            "proposedPolicyHash": file_digest(proposed_policy)["sha256"],
            "policyEpoch": 77,
        },
        "sourceArtifacts": {
            "policyEvents": source_manifest_file_record(
                policy_events,
                policy_events.relative_to(root),
            ),
            "policyImpactJson": source_manifest_file_record(
                policy_impact,
                policy_impact.relative_to(root),
            ),
            "coverageInputs": coverage_inputs,
        },
        "generatedProofs": generated_proofs,
        "bridgeScripts": {
            key: source_manifest_file_record(SCRIPT_DIR / EXPECTED_BRIDGE_SCRIPTS[key])
            for key in sorted(supported_keys)
        },
    }
    manifest_path = root / "supplemental-proof-source-manifest.json"
    write_json(manifest_path, source_manifest)
    return manifest_path


def run_self_test() -> int:
    gate_module = load_module(SCRIPT_DIR / "macos-provider-dogfood-gate.py")
    manifest_module = load_module(SCRIPT_DIR / "macos-provider-dogfood-manifest.py")
    with tempfile.TemporaryDirectory(prefix="clawdstrike-ede-readiness-") as temp_dir:
        temp_root = pathlib.Path(temp_dir)
        root = temp_root / "dogfood"
        proof_root = temp_root / "supplemental"
        root.mkdir(parents=True, exist_ok=True)
        deployment_dir = root / "deployment-evidence"
        es_dir = root / "endpoint-security"
        ne_dir = root / "network-extension"
        deployment_summary_path = deployment_dir / "summary.json"
        es_summary_path = es_dir / "summary.json"
        ne_summary_path = ne_dir / "summary.json"
        gate_result_path = root / "gate-result.json"
        manifest_path = root / "manifest.json"

        deployment_summary_path.parent.mkdir(parents=True, exist_ok=True)
        es_summary_path.parent.mkdir(parents=True, exist_ok=True)
        ne_summary_path.parent.mkdir(parents=True, exist_ok=True)
        deployment_summary_path.write_text(
            json.dumps(gate_module.fixture_deployment_evidence_summary(deployment_dir)),
            encoding="utf-8",
        )
        es_summary_path.write_text(
            json.dumps(gate_module.fixture_endpoint_security_summary(es_dir)),
            encoding="utf-8",
        )
        ne_summary_path.write_text(
            json.dumps(gate_module.fixture_network_extension_summary(ne_dir)),
            encoding="utf-8",
        )
        gate_result = gate_module.gate_artifacts(
            es_summary_path,
            ne_summary_path,
            deployment_summary_path,
        )
        if gate_result.get("verified") is not True:
            print(json.dumps(gate_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        gate_result_path.write_text(json.dumps(gate_result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        manifest_module.write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary_path,
            endpoint_security_summary=es_summary_path,
            network_extension_summary=ne_summary_path,
            gate_result=gate_result_path,
            max_run_skew_seconds=3600,
            evidence_mode="fixture",
        )

        audit = build_audit(manifest_path)
        if audit["ready"] is True:
            print("self-test expected synthetic macOS manifest not to satisfy full north-star audit", file=sys.stderr)
            print(json.dumps(audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        statuses = {item["key"]: item["status"] for item in audit["checklist"]}
        for key in (
            "causal_graph_flight_recorder",
            "evidence_receipts",
            "identity_aware_enforcement",
            "local_controlled_response",
            "safe_autonomous_response",
        ):
            if statuses.get(key) != "verified":
                print(f"self-test expected {key} to verify", file=sys.stderr)
                print(json.dumps(audit, indent=2, sort_keys=True), file=sys.stderr)
                return 1
        for key in ("macos_provider_bundle_integrity", "prove_later_manifest"):
            if statuses.get(key) != "failed":
                print(f"self-test expected fixture {key} to fail production readiness", file=sys.stderr)
                print(json.dumps(audit, indent=2, sort_keys=True), file=sys.stderr)
                return 1
        for key in (
            "policy_simulation_impact",
            "ai_agent_developer_workstation",
            "privacy_preserving_telemetry",
        ):
            if statuses.get(key) != "missing":
                print(f"self-test expected {key} to remain missing", file=sys.stderr)
                print(json.dumps(audit, indent=2, sort_keys=True), file=sys.stderr)
                return 1

        manifest, gate, selected, manifest_verify = load_manifest_evidence(manifest_path)
        bool_flow_selected = dict(selected)
        bool_flow_ne_summary = dict(bool_flow_selected["networkExtensionSummary"])
        bool_flow_ne_summary["blockedFlowCount"] = True
        bool_flow_selected["networkExtensionSummary"] = bool_flow_ne_summary
        bool_flow_statuses = {
            item["key"]: item["status"]
            for item in macos_provider_criteria(
                manifest_path,
                manifest,
                gate,
                bool_flow_selected,
                manifest_verify,
            )
        }
        if bool_flow_statuses.get("local_controlled_response") != "failed":
            print(
                "self-test expected boolean blockedFlowCount to fail local controlled response",
                file=sys.stderr,
            )
            print(json.dumps(bool_flow_statuses, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        missing_audit = build_audit(None)
        if missing_audit["ready"] is True or "macos_provider_bundle_integrity" not in missing_audit["unresolved"]:
            print("self-test expected missing manifest to fail macOS provider evidence", file=sys.stderr)
            print(json.dumps(missing_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        for key in sorted(SUPPLEMENTAL_PROOF_KEYS):
            template = build_supplemental_proof_template(key)
            if template.get("key") != key:
                print(f"self-test expected proof template key to be {key}", file=sys.stderr)
                print(json.dumps(template, indent=2, sort_keys=True), file=sys.stderr)
                return 1
            evidence_template = template.get("evidenceTemplate")
            if not isinstance(evidence_template, dict):
                print(f"self-test expected proof template evidence object for {key}", file=sys.stderr)
                print(json.dumps(template, indent=2, sort_keys=True), file=sys.stderr)
                return 1
            template_failures = _validate_key_specific_evidence(key, evidence_template)
            if template_failures:
                print(f"self-test expected proof template to satisfy evidence validator for {key}", file=sys.stderr)
                print(json.dumps(template_failures, indent=2, sort_keys=True), file=sys.stderr)
                return 1

        incomplete_operator_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["operator_workflows"])
        incomplete_operator_evidence["responseActionKinds"] = [
            value
            for value in incomplete_operator_evidence["responseActionKinds"]
            if value != "collect_evidence"
        ]
        if not _validate_key_specific_evidence("operator_workflows", incomplete_operator_evidence):
            print(
                "self-test expected missing controlled-response action kind to fail operator evidence",
                file=sys.stderr,
            )
            return 1

        cloud_dependent_operator_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["operator_workflows"])
        cloud_dependent_operator_evidence["cloudUnavailableDecisionVerified"] = False
        if not _validate_key_specific_evidence("operator_workflows", cloud_dependent_operator_evidence):
            print(
                "self-test expected cloud-dependent operator evidence to fail",
                file=sys.stderr,
            )
            return 1

        slow_operator_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["operator_workflows"])
        slow_operator_evidence["maxWorkflowLatencyMs"] = 10001
        if not _validate_key_specific_evidence("operator_workflows", slow_operator_evidence):
            print("self-test expected over-bound operator latency to fail", file=sys.stderr)
            return 1

        weak_response_receipt_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["operator_workflows"])
        weak_response_receipt_evidence["responseReceiptsBindProcessTree"] = False
        if not _validate_key_specific_evidence("operator_workflows", weak_response_receipt_evidence):
            print(
                "self-test expected weak response receipt binding to fail operator evidence",
                file=sys.stderr,
            )
            return 1

        incomplete_graph_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["cross_platform_sensor_breadth"])
        incomplete_graph_evidence["graphEdgeKinds"] = [
            edge for edge in incomplete_graph_evidence["graphEdgeKinds"] if edge != "made_decision"
        ]
        if not _validate_key_specific_evidence("cross_platform_sensor_breadth", incomplete_graph_evidence):
            print("self-test expected missing causal graph edge kind to fail", file=sys.stderr)
            return 1

        unbound_ai_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["ai_agent_developer_workstation"])
        unbound_ai_evidence["activityReceiptsBound"] = False
        if not _validate_key_specific_evidence("ai_agent_developer_workstation", unbound_ai_evidence):
            print("self-test expected unbound AI-agent receipts to fail evidence", file=sys.stderr)
            return 1

        graphless_ai_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["ai_agent_developer_workstation"])
        graphless_ai_evidence["activityGraphEdgeCount"] = 0
        if not _validate_key_specific_evidence("ai_agent_developer_workstation", graphless_ai_evidence):
            print("self-test expected missing AI-agent graph coverage to fail evidence", file=sys.stderr)
            return 1

        unbound_deception_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["endpoint_deception"])
        unbound_deception_evidence["detectionReceiptBindsTouchedArtifact"] = False
        if not _validate_key_specific_evidence("endpoint_deception", unbound_deception_evidence):
            print("self-test expected unbound deception receipt to fail evidence", file=sys.stderr)
            return 1

        proxy_deception_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["endpoint_deception"])
        proxy_deception_evidence["touchedHoneyGraphBindingCount"] = 0
        if not _validate_key_specific_evidence("endpoint_deception", proxy_deception_evidence):
            print("self-test expected missing deception graph binding to fail evidence", file=sys.stderr)
            return 1

        unbound_supply_chain_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["supply_chain_runtime_guard"])
        unbound_supply_chain_evidence["receiptBindingVerified"] = False
        if not _validate_key_specific_evidence("supply_chain_runtime_guard", unbound_supply_chain_evidence):
            print("self-test expected unbound supply-chain receipts to fail evidence", file=sys.stderr)
            return 1

        graphless_supply_chain_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["supply_chain_runtime_guard"])
        graphless_supply_chain_evidence["graphObservationNodeCount"] = 0
        if not _validate_key_specific_evidence("supply_chain_runtime_guard", graphless_supply_chain_evidence):
            print("self-test expected missing supply-chain graph coverage to fail evidence", file=sys.stderr)
            return 1

        unbound_privacy_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["privacy_preserving_telemetry"])
        unbound_privacy_evidence["privacyReceiptBindsReport"] = False
        if not _validate_key_specific_evidence("privacy_preserving_telemetry", unbound_privacy_evidence):
            print("self-test expected unbound privacy receipt to fail evidence", file=sys.stderr)
            return 1

        missing_privacy_receipt_evidence = dict(
            SUPPLEMENTAL_EVIDENCE_TEMPLATES["privacy_preserving_telemetry"]
        )
        missing_privacy_receipt_evidence["privacyReceiptId"] = ""
        if not _validate_key_specific_evidence(
            "privacy_preserving_telemetry",
            missing_privacy_receipt_evidence,
        ):
            print("self-test expected missing privacy receipt id to fail evidence", file=sys.stderr)
            return 1

        zero_replay_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["policy_simulation_impact"])
        zero_replay_evidence["replayedEventCount"] = 0
        if not _validate_key_specific_evidence("policy_simulation_impact", zero_replay_evidence):
            print("self-test expected zero replay count to fail policy simulation evidence", file=sys.stderr)
            return 1

        unauditable_policy_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["policy_simulation_impact"])
        unauditable_policy_evidence["auditModeSupported"] = False
        if not _validate_key_specific_evidence("policy_simulation_impact", unauditable_policy_evidence):
            print("self-test expected missing audit mode to fail policy simulation evidence", file=sys.stderr)
            return 1

        unbound_breakage_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["policy_simulation_impact"])
        unbound_breakage_evidence["breakageDriverCount"] = 0
        if not _validate_key_specific_evidence("policy_simulation_impact", unbound_breakage_evidence):
            print("self-test expected missing breakage drivers to fail policy simulation evidence", file=sys.stderr)
            return 1

        invalid_policy_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["policy_simulation_impact"])
        invalid_policy_evidence.update(
            {
                "policyHash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "policyEpoch": 77,
                "graphSliceId": "graph-slice-1",
                "eventStreamSha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "resultSha256": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "currentPolicyRef": "current-policy.yaml",
                "proposedPolicyRef": "proposed-policy.yaml",
                "impactEngine": "cli_policy_impact",
                "impactLevel": "high",
                "recommendedStage": "audit",
                "developerBreakageScore": 72,
                "changedVerdictCount": 3,
                "blockingChangeCount": 1,
                "replayedEventCount": 4,
                "simulationReceiptFamily": "not_simulation",
            }
        )
        invalid_proof = write_supplemental_proof(
            proof_root,
            "policy_simulation_impact",
            invalid_policy_evidence,
        )
        invalid_audit = build_audit(manifest_path, {"policy_simulation_impact": invalid_proof})
        invalid_statuses = {item["key"]: item["status"] for item in invalid_audit["checklist"]}
        if invalid_statuses.get("policy_simulation_impact") != "failed":
            print("self-test expected invalid supplemental proof to fail", file=sys.stderr)
            print(json.dumps(invalid_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        operator_proof_dir = temp_root / "operator-proof"
        operator_evidence_path = operator_proof_dir / "policy-evidence.json"
        operator_artifact_path = operator_proof_dir / "impact-report.json"
        operator_command_path = operator_proof_dir / "simulate-command.json"
        valid_policy_evidence = dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["policy_simulation_impact"])
        valid_policy_evidence.update(
            {
                "policyHash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "policyEpoch": 77,
                "graphSliceId": "graph-slice-1",
                "eventStreamSha256": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "resultSha256": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "currentPolicyRef": "current-policy.yaml",
                "proposedPolicyRef": "proposed-policy.yaml",
                "impactEngine": "cli_policy_impact",
                "impactLevel": "high",
                "recommendedStage": "audit",
                "developerBreakageScore": 72,
                "changedVerdictCount": 3,
                "blockingChangeCount": 1,
                "replayedEventCount": 4,
            }
        )
        write_json(operator_evidence_path, valid_policy_evidence)
        write_json(
            operator_artifact_path,
            {
                "graphSliceId": "graph-slice-1",
                "changedVerdicts": 3,
                "developerBreakageScore": 72,
            },
        )
        write_json(
            operator_command_path,
            {
                "argv": ["clawdstrike", "policy", "simulate", "--policy", "policy.yaml"],
                "exitCode": 0,
                "summary": "simulation passed",
            },
        )
        operator_result = write_operator_supplemental_proof(
            "policy_simulation_impact",
            operator_proof_dir / "generated-proof.json",
            operator_evidence_path,
            [operator_artifact_path],
            [operator_command_path],
        )
        if operator_result["status"] != "verified":
            print("self-test expected operator-written proof to validate", file=sys.stderr)
            print(json.dumps(operator_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        generated_proof = load_json_object(operator_proof_dir / "generated-proof.json")
        if generated_proof.get("key") != "policy_simulation_impact":
            print("self-test expected operator proof to preserve proof key", file=sys.stderr)
            print(json.dumps(generated_proof, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        hidden_proof_path = operator_proof_dir / "hidden-field-proof.json"
        hidden_proof = dict(generated_proof)
        hidden_proof["operatorNote"] = "unverified"
        write_json(hidden_proof_path, hidden_proof)
        hidden_proof_result = validate_supplemental_proof(
            "policy_simulation_impact",
            hidden_proof_path,
        )
        if hidden_proof_result["status"] != "failed":
            print("self-test expected hidden proof field to fail", file=sys.stderr)
            print(json.dumps(hidden_proof_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bool_schema_proof_path = operator_proof_dir / "bool-schema-proof.json"
        bool_schema_proof = dict(generated_proof)
        bool_schema_proof["schemaVersion"] = True
        write_json(bool_schema_proof_path, bool_schema_proof)
        bool_schema_proof_result = validate_supplemental_proof(
            "policy_simulation_impact",
            bool_schema_proof_path,
        )
        if bool_schema_proof_result["status"] != "failed":
            print("self-test expected boolean proof schemaVersion to fail", file=sys.stderr)
            print(json.dumps(bool_schema_proof_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        hidden_evidence_proof_path = operator_proof_dir / "hidden-evidence-field-proof.json"
        hidden_evidence_proof = json.loads(json.dumps(generated_proof))
        hidden_evidence_proof["evidence"]["operatorNote"] = "unverified"
        write_json(hidden_evidence_proof_path, hidden_evidence_proof)
        hidden_evidence_result = validate_supplemental_proof(
            "policy_simulation_impact",
            hidden_evidence_proof_path,
        )
        if hidden_evidence_result["status"] != "failed":
            print("self-test expected hidden proof evidence field to fail", file=sys.stderr)
            print(json.dumps(hidden_evidence_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        hidden_artifact_proof_path = operator_proof_dir / "hidden-artifact-field-proof.json"
        hidden_artifact_proof = json.loads(json.dumps(generated_proof))
        hidden_artifact_proof["artifacts"][0]["sourcePath"] = str(operator_artifact_path)
        write_json(hidden_artifact_proof_path, hidden_artifact_proof)
        hidden_artifact_result = validate_supplemental_proof(
            "policy_simulation_impact",
            hidden_artifact_proof_path,
        )
        if hidden_artifact_result["status"] != "failed":
            print("self-test expected hidden proof artifact field to fail", file=sys.stderr)
            print(json.dumps(hidden_artifact_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        hidden_command_proof_path = operator_proof_dir / "hidden-command-field-proof.json"
        hidden_command_proof = json.loads(json.dumps(generated_proof))
        hidden_command_proof["commands"][0]["stdout"] = "unverified"
        write_json(hidden_command_proof_path, hidden_command_proof)
        hidden_command_result = validate_supplemental_proof(
            "policy_simulation_impact",
            hidden_command_proof_path,
        )
        if hidden_command_result["status"] != "failed":
            print("self-test expected hidden proof command field to fail", file=sys.stderr)
            print(json.dumps(hidden_command_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bool_exit_code_proof_path = operator_proof_dir / "bool-exit-code-proof.json"
        bool_exit_code_proof = json.loads(json.dumps(generated_proof))
        bool_exit_code_proof["commands"][0]["exitCode"] = False
        write_json(bool_exit_code_proof_path, bool_exit_code_proof)
        bool_exit_code_result = validate_supplemental_proof(
            "policy_simulation_impact",
            bool_exit_code_proof_path,
        )
        if bool_exit_code_result["status"] != "failed":
            print("self-test expected boolean proof command exitCode to fail", file=sys.stderr)
            print(json.dumps(bool_exit_code_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bad_operator_evidence_path = operator_proof_dir / "bad-policy-evidence.json"
        bad_policy_evidence = dict(valid_policy_evidence)
        bad_policy_evidence["simulationReceiptFamily"] = "not_simulation"
        write_json(bad_operator_evidence_path, bad_policy_evidence)
        try:
            write_operator_supplemental_proof(
                "policy_simulation_impact",
                operator_proof_dir / "bad-evidence-proof.json",
                bad_operator_evidence_path,
                [operator_artifact_path],
                [operator_command_path],
            )
        except ValueError:
            pass
        else:
            print("self-test expected invalid operator evidence to be rejected", file=sys.stderr)
            return 1

        bad_operator_command_path = operator_proof_dir / "bad-simulate-command.json"
        write_json(
            bad_operator_command_path,
            {
                "argv": ["clawdstrike", "policy", "simulate", "--policy", "policy.yaml"],
                "exitCode": 1,
                "summary": "simulation failed",
            },
        )
        try:
            write_operator_supplemental_proof(
                "policy_simulation_impact",
                operator_proof_dir / "bad-command-proof.json",
                operator_evidence_path,
                [operator_artifact_path],
                [bad_operator_command_path],
            )
        except ValueError:
            pass
        else:
            print("self-test expected failing operator command result to be rejected", file=sys.stderr)
            return 1

        try:
            write_operator_supplemental_proof(
                "policy_simulation_impact",
                operator_proof_dir / "missing-command-proof.json",
                operator_evidence_path,
                [operator_artifact_path],
                [operator_proof_dir / "missing-command-result.json"],
            )
        except ValueError:
            pass
        else:
            print("self-test expected missing operator command result to be rejected", file=sys.stderr)
            return 1

        bad_operator_command_json_path = operator_proof_dir / "malformed-command.json"
        bad_operator_command_json_path.write_text("{", encoding="utf-8")
        try:
            write_operator_supplemental_proof(
                "policy_simulation_impact",
                operator_proof_dir / "malformed-command-proof.json",
                operator_evidence_path,
                [operator_artifact_path],
                [bad_operator_command_json_path],
            )
        except ValueError:
            pass
        else:
            print("self-test expected malformed operator command result to be rejected", file=sys.stderr)
            return 1

        supplemental = {
            "policy_simulation_impact": write_supplemental_proof(
                proof_root,
                "policy_simulation_impact",
                valid_policy_evidence,
            ),
            "ai_agent_developer_workstation": write_supplemental_proof(
                proof_root,
                "ai_agent_developer_workstation",
                dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["ai_agent_developer_workstation"]),
            ),
            "endpoint_deception": write_supplemental_proof(
                proof_root,
                "endpoint_deception",
                dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["endpoint_deception"]),
            ),
            "supply_chain_runtime_guard": write_supplemental_proof(
                proof_root,
                "supply_chain_runtime_guard",
                dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["supply_chain_runtime_guard"]),
            ),
            "privacy_preserving_telemetry": write_supplemental_proof(
                proof_root,
                "privacy_preserving_telemetry",
                dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["privacy_preserving_telemetry"]),
            ),
            "operator_workflows": write_supplemental_proof(
                proof_root,
                "operator_workflows",
                dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["operator_workflows"]),
            ),
            "cross_platform_sensor_breadth": write_supplemental_proof(
                proof_root,
                "cross_platform_sensor_breadth",
                dict(SUPPLEMENTAL_EVIDENCE_TEMPLATES["cross_platform_sensor_breadth"]),
            ),
        }
        complete_without_source_manifest = build_audit(manifest_path, supplemental)
        if complete_without_source_manifest["ready"] is True:
            print(
                "self-test expected complete supplemental proof set without source manifest to fail",
                file=sys.stderr,
            )
            print(json.dumps(complete_without_source_manifest, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        without_source_statuses = {
            item["key"]: item["status"]
            for item in complete_without_source_manifest["checklist"]
        }
        if without_source_statuses.get("prove_later_manifest") != "failed":
            print(
                "self-test expected missing supplemental source manifest to fail prove-later",
                file=sys.stderr,
            )
            print(json.dumps(complete_without_source_manifest, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        missing_source_audit_path = temp_root / "readiness-audit-missing-source.json"
        write_json(missing_source_audit_path, complete_without_source_manifest)
        missing_source_verification = verify_audit_file(missing_source_audit_path)
        if missing_source_verification["verified"] is True:
            print(
                "self-test expected persisted complete audit without source manifest to fail verification",
                file=sys.stderr,
            )
            print(json.dumps(missing_source_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        source_manifest_path = write_synthetic_supplemental_source_manifest(
            proof_root,
            set(SUPPLEMENTAL_PROOF_KEYS),
        )
        invalid_policy_manifest_path = proof_root / "invalid-policy-source-manifest.json"
        invalid_policy_manifest = load_json_object(source_manifest_path)
        invalid_policy_manifest["policy"]["proposedPolicyHash"] = "not-a-sha256"
        write_json(invalid_policy_manifest_path, invalid_policy_manifest)
        invalid_policy_audit = build_audit(manifest_path, supplemental, invalid_policy_manifest_path)
        invalid_policy_statuses = {
            item["key"]: item["status"]
            for item in invalid_policy_audit["checklist"]
        }
        if invalid_policy_statuses.get("prove_later_manifest") != "failed":
            print(
                "self-test expected invalid supplemental source policy to fail prove-later",
                file=sys.stderr,
            )
            print(json.dumps(invalid_policy_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        mismatched_policy_manifest_path = proof_root / "mismatched-policy-source-manifest.json"
        mismatched_policy_manifest = load_json_object(source_manifest_path)
        mismatched_policy_manifest["policy"]["proposedPolicyHash"] = "sha256:" + ("ab" * 32)
        write_json(mismatched_policy_manifest_path, mismatched_policy_manifest)
        mismatched_policy_audit = build_audit(
            manifest_path,
            supplemental,
            mismatched_policy_manifest_path,
        )
        mismatched_policy_statuses = {
            item["key"]: item["status"]
            for item in mismatched_policy_audit["checklist"]
        }
        if mismatched_policy_statuses.get("prove_later_manifest") != "failed":
            print(
                "self-test expected mismatched supplemental source policy hash to fail prove-later",
                file=sys.stderr,
            )
            print(json.dumps(mismatched_policy_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        external_source_root_manifest_path = proof_root / "external-source-root-manifest.json"
        external_source_root_manifest = load_json_object(source_manifest_path)
        external_source_root_manifest["sourceRoot"] = str(temp_root)
        write_json(external_source_root_manifest_path, external_source_root_manifest)
        external_source_root_audit = build_audit(
            manifest_path,
            supplemental,
            external_source_root_manifest_path,
        )
        external_source_root_statuses = {
            item["key"]: item["status"]
            for item in external_source_root_audit["checklist"]
        }
        if external_source_root_statuses.get("prove_later_manifest") != "failed":
            print(
                "self-test expected external supplemental sourceRoot to fail prove-later",
                file=sys.stderr,
            )
            print(json.dumps(external_source_root_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        wrong_source_root_manifest_path = proof_root / "wrong-source-root-manifest.json"
        wrong_source_root_manifest = load_json_object(source_manifest_path)
        wrong_source_root_manifest["sourceRoot"] = "source-artifacts/policies"
        write_json(wrong_source_root_manifest_path, wrong_source_root_manifest)
        wrong_source_root_audit = build_audit(
            manifest_path,
            supplemental,
            wrong_source_root_manifest_path,
        )
        wrong_source_root_statuses = {
            item["key"]: item["status"]
            for item in wrong_source_root_audit["checklist"]
        }
        if wrong_source_root_statuses.get("prove_later_manifest") != "failed":
            print(
                "self-test expected supplemental source artifacts outside sourceRoot to fail prove-later",
                file=sys.stderr,
            )
            print(json.dumps(wrong_source_root_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        wrong_bridge_manifest_path = proof_root / "wrong-bridge-source-manifest.json"
        wrong_bridge_manifest = load_json_object(source_manifest_path)
        wrong_bridge_manifest["bridgeScripts"]["policy_simulation_impact"] = (
            source_manifest_file_record(SCRIPT_DIR / "endpoint-decision-engine-readiness-audit.py")
        )
        write_json(wrong_bridge_manifest_path, wrong_bridge_manifest)
        wrong_bridge_audit = build_audit(manifest_path, supplemental, wrong_bridge_manifest_path)
        wrong_bridge_statuses = {
            item["key"]: item["status"]
            for item in wrong_bridge_audit["checklist"]
        }
        if wrong_bridge_statuses.get("prove_later_manifest") != "failed":
            print(
                "self-test expected wrong supplemental bridge script path to fail prove-later",
                file=sys.stderr,
            )
            print(json.dumps(wrong_bridge_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        complete_audit = build_audit(manifest_path, supplemental, source_manifest_path)
        if complete_audit["ready"] is True:
            print(
                "self-test expected complete fixture proof set to fail production readiness",
                file=sys.stderr,
            )
            print(json.dumps(complete_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        complete_statuses = {item["key"]: item["status"] for item in complete_audit["checklist"]}
        for key in ("macos_provider_bundle_integrity", "prove_later_manifest"):
            if complete_statuses.get(key) != "failed":
                print(f"self-test expected fixture {key} to remain failed", file=sys.stderr)
                print(json.dumps(complete_audit, indent=2, sort_keys=True), file=sys.stderr)
                return 1
        complete_provenance = complete_audit.get("provenance")
        if not isinstance(complete_provenance, dict) or not isinstance(
            complete_provenance.get("supplementalSourceManifest"),
            dict,
        ):
            print("self-test expected complete audit to record source manifest provenance", file=sys.stderr)
            print(json.dumps(complete_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if complete_provenance["supplementalSourceManifest"].get("verified") is not True:
            print("self-test expected complete audit to record verified source manifest provenance", file=sys.stderr)
            print(json.dumps(complete_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        bool_size_source_manifest_path = proof_root / "bool-byte-size-source-manifest.json"
        bool_size_source_manifest = load_json_object(source_manifest_path)
        bool_size_source_manifest["sourceArtifacts"]["policyEvents"]["byteSize"] = True
        write_json(bool_size_source_manifest_path, bool_size_source_manifest)
        bool_size_audit = build_audit(
            manifest_path,
            supplemental,
            bool_size_source_manifest_path,
        )
        bool_size_statuses = {item["key"]: item["status"] for item in bool_size_audit["checklist"]}
        if (
            bool_size_statuses.get("prove_later_manifest") != "failed"
            or bool_size_audit["provenance"]["supplementalSourceManifest"].get("verified") is not False
        ):
            print(
                "self-test expected boolean source-manifest byteSize to fail provenance verification",
                file=sys.stderr,
            )
            print(json.dumps(bool_size_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        source_path_manifest_path = proof_root / "source-path-source-manifest.json"
        source_path_manifest = load_json_object(source_manifest_path)
        source_path_manifest["sourceArtifacts"]["policyEvents"]["sourcePath"] = str(
            proof_root / "operator-origin-policy-events.jsonl"
        )
        write_json(source_path_manifest_path, source_path_manifest)
        source_path_audit = build_audit(
            manifest_path,
            supplemental,
            source_path_manifest_path,
        )
        source_path_statuses = {
            item["key"]: item["status"] for item in source_path_audit["checklist"]
        }
        if (
            source_path_statuses.get("prove_later_manifest") != "failed"
            or source_path_audit["provenance"]["supplementalSourceManifest"].get("verified")
            is not False
        ):
            print(
                "self-test expected source-manifest sourcePath to fail provenance verification",
                file=sys.stderr,
            )
            print(json.dumps(source_path_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        hidden_source_manifest_path = proof_root / "hidden-field-source-manifest.json"
        hidden_source_manifest = load_json_object(source_manifest_path)
        hidden_source_manifest["operatorNote"] = "unverified"
        write_json(hidden_source_manifest_path, hidden_source_manifest)
        hidden_source_audit = build_audit(
            manifest_path,
            supplemental,
            hidden_source_manifest_path,
        )
        hidden_source_statuses = {
            item["key"]: item["status"] for item in hidden_source_audit["checklist"]
        }
        if (
            hidden_source_statuses.get("prove_later_manifest") != "failed"
            or hidden_source_audit["provenance"]["supplementalSourceManifest"].get("verified")
            is not False
        ):
            print(
                "self-test expected hidden source-manifest field to fail provenance verification",
                file=sys.stderr,
            )
            print(json.dumps(hidden_source_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        hidden_policy_manifest_path = proof_root / "hidden-policy-source-manifest.json"
        hidden_policy_manifest = load_json_object(source_manifest_path)
        hidden_policy_manifest["policy"]["reviewTicket"] = "unverified"
        write_json(hidden_policy_manifest_path, hidden_policy_manifest)
        hidden_policy_audit = build_audit(
            manifest_path,
            supplemental,
            hidden_policy_manifest_path,
        )
        hidden_policy_statuses = {
            item["key"]: item["status"] for item in hidden_policy_audit["checklist"]
        }
        if (
            hidden_policy_statuses.get("prove_later_manifest") != "failed"
            or hidden_policy_audit["provenance"]["supplementalSourceManifest"].get("verified")
            is not False
        ):
            print(
                "self-test expected hidden source-manifest policy field to fail provenance verification",
                file=sys.stderr,
            )
            print(json.dumps(hidden_policy_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if not isinstance(complete_audit.get("auditSha256"), str):
            print("self-test expected auditSha256 on complete audit", file=sys.stderr)
            print(json.dumps(complete_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        audit_path = temp_root / "readiness-audit.json"
        write_json(audit_path, complete_audit)
        verified_audit = verify_audit_file(audit_path)
        if verified_audit["verified"] is not True:
            print("self-test expected persisted audit digest verification to pass", file=sys.stderr)
            print(json.dumps(verified_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if verified_audit.get("sourceReverified") is not True:
            print("self-test expected persisted audit source re-verification to pass", file=sys.stderr)
            print(json.dumps(verified_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        hidden_audit = load_json_object(audit_path)
        hidden_audit["operatorNote"] = "unverified"
        hidden_audit = attach_audit_digest(hidden_audit)
        write_json(audit_path, hidden_audit)
        hidden_audit_verification = verify_audit_file(audit_path)
        if hidden_audit_verification["verified"] is True:
            print("self-test expected rehashed hidden audit field to fail verification", file=sys.stderr)
            print(json.dumps(hidden_audit_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        hidden_provenance_audit = load_json_object(audit_path)
        hidden_provenance = hidden_provenance_audit["provenance"]
        hidden_provenance["operatorNote"] = "unverified"
        hidden_provenance_audit = attach_audit_digest(hidden_provenance_audit)
        write_json(audit_path, hidden_provenance_audit)
        hidden_provenance_verification = verify_audit_file(audit_path)
        if hidden_provenance_verification["verified"] is True:
            print("self-test expected rehashed hidden provenance field to fail verification", file=sys.stderr)
            print(json.dumps(hidden_provenance_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        hidden_checklist_audit = load_json_object(audit_path)
        hidden_checklist_audit["checklist"][0]["operatorNote"] = "unverified"
        hidden_checklist_audit = attach_audit_digest(hidden_checklist_audit)
        write_json(audit_path, hidden_checklist_audit)
        hidden_checklist_verification = verify_audit_file(audit_path)
        if hidden_checklist_verification["verified"] is True:
            print("self-test expected rehashed hidden checklist field to fail verification", file=sys.stderr)
            print(json.dumps(hidden_checklist_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        hidden_source_provenance_audit = load_json_object(audit_path)
        hidden_source_provenance = hidden_source_provenance_audit["provenance"][
            "supplementalSourceManifest"
        ]
        hidden_source_provenance["operatorNote"] = "unverified"
        hidden_source_provenance_audit = attach_audit_digest(hidden_source_provenance_audit)
        write_json(audit_path, hidden_source_provenance_audit)
        hidden_source_provenance_verification = verify_audit_file(audit_path)
        if hidden_source_provenance_verification["verified"] is True:
            print(
                "self-test expected rehashed hidden source-manifest provenance field to fail verification",
                file=sys.stderr,
            )
            print(json.dumps(hidden_source_provenance_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        bool_schema_audit = load_json_object(audit_path)
        bool_schema_audit["schemaVersion"] = True
        bool_schema_audit = attach_audit_digest(bool_schema_audit)
        write_json(audit_path, bool_schema_audit)
        bool_schema_verification = verify_audit_file(audit_path)
        if bool_schema_verification["verified"] is True or "schemaVersion must be 1" not in bool_schema_verification["failures"]:
            print("self-test expected rehashed boolean audit schemaVersion to fail verification", file=sys.stderr)
            print(json.dumps(bool_schema_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        bool_count_audit = load_json_object(audit_path)
        bool_count_audit["counts"] = {"verified": True}
        bool_count_audit = attach_audit_digest(bool_count_audit)
        write_json(audit_path, bool_count_audit)
        bool_count_verification = verify_audit_file(audit_path)
        bool_count_failure = "audit.counts must be an object of non-negative integer counts"
        if bool_count_verification["verified"] is True or bool_count_failure not in bool_count_verification["failures"]:
            print("self-test expected rehashed boolean audit count to fail verification", file=sys.stderr)
            print(json.dumps(bool_count_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        bool_manifest_verification_audit = load_json_object(audit_path)
        bool_manifest_verification_audit["macosProviderManifestVerification"]["failureCount"] = False
        bool_manifest_verification_audit = attach_audit_digest(bool_manifest_verification_audit)
        write_json(audit_path, bool_manifest_verification_audit)
        bool_manifest_verification = verify_audit_file(audit_path)
        bool_manifest_failure = (
            "macosProviderManifestVerification.failureCount must be a non-negative integer"
        )
        if (
            bool_manifest_verification["verified"] is True
            or bool_manifest_failure not in bool_manifest_verification["failures"]
        ):
            print(
                "self-test expected rehashed boolean manifest-verification count to fail verification",
                file=sys.stderr,
            )
            print(json.dumps(bool_manifest_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        bad_checklist_audit = load_json_object(audit_path)
        bad_checklist_audit["checklist"][0]["evidence"] = [{"path": "unverified"}]
        bad_checklist_audit = attach_audit_digest(bad_checklist_audit)
        write_json(audit_path, bad_checklist_audit)
        bad_checklist_verification = verify_audit_file(audit_path)
        bad_checklist_failure = "checklist[0].evidence[0] must be a string"
        if (
            bad_checklist_verification["verified"] is True
            or bad_checklist_failure not in bad_checklist_verification["failures"]
        ):
            print("self-test expected rehashed non-string checklist evidence to fail verification", file=sys.stderr)
            print(json.dumps(bad_checklist_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        bool_source_count_audit = load_json_object(audit_path)
        bool_source_count = bool_source_count_audit["provenance"]["supplementalSourceManifest"]
        bool_source_count["sourceArtifactCount"] = True
        bool_source_count_audit = attach_audit_digest(bool_source_count_audit)
        write_json(audit_path, bool_source_count_audit)
        bool_source_count_verification = verify_audit_file(audit_path)
        bool_source_count_failure = (
            "provenance.supplementalSourceManifest.sourceArtifactCount must be a non-negative integer"
        )
        if (
            bool_source_count_verification["verified"] is True
            or bool_source_count_failure not in bool_source_count_verification["failures"]
        ):
            print(
                "self-test expected rehashed boolean source-manifest provenance count to fail verification",
                file=sys.stderr,
            )
            print(json.dumps(bool_source_count_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        write_json(audit_path, complete_audit)
        count_tampered_audit = load_json_object(audit_path)
        count_tampered_source = count_tampered_audit["provenance"]["supplementalSourceManifest"]
        count_tampered_source["sourceArtifactCount"] = 999
        count_tampered_audit = attach_audit_digest(count_tampered_audit)
        write_json(audit_path, count_tampered_audit)
        count_tampered_verification = verify_audit_file(audit_path)
        if count_tampered_verification["verified"] is True:
            print(
                "self-test expected rehashed source-manifest count drift to fail audit verification",
                file=sys.stderr,
            )
            print(json.dumps(count_tampered_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        generated_count_tampered_audit = load_json_object(audit_path)
        generated_count_tampered_source = (
            generated_count_tampered_audit["provenance"]["supplementalSourceManifest"]
        )
        generated_count_tampered_source["generatedProofCount"] = 999
        generated_count_tampered_audit = attach_audit_digest(generated_count_tampered_audit)
        write_json(audit_path, generated_count_tampered_audit)
        generated_count_tampered_verification = verify_audit_file(audit_path)
        if generated_count_tampered_verification["verified"] is True:
            print(
                "self-test expected rehashed generated-proof count drift to fail audit verification",
                file=sys.stderr,
            )
            print(
                json.dumps(generated_count_tampered_verification, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        external_source_tampered_audit = load_json_object(audit_path)
        external_source_tampered = (
            external_source_tampered_audit["provenance"]["supplementalSourceManifest"]
        )
        external_source_tampered["externalSourceArtifacts"] = {
            "source:policyEvents": str(temp_root / "not-recorded-policy-events.jsonl")
        }
        external_source_tampered_audit = attach_audit_digest(external_source_tampered_audit)
        write_json(audit_path, external_source_tampered_audit)
        external_source_tampered_verification = verify_audit_file(audit_path)
        if external_source_tampered_verification["verified"] is True:
            print(
                "self-test expected stale external source disclosure to fail audit verification",
                file=sys.stderr,
            )
            print(
                json.dumps(external_source_tampered_verification, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        write_json(audit_path, complete_audit)
        verified_tampered_audit = load_json_object(audit_path)
        verified_tampered_source = verified_tampered_audit["provenance"]["supplementalSourceManifest"]
        verified_tampered_source["verified"] = False
        verified_tampered_audit = attach_audit_digest(verified_tampered_audit)
        write_json(audit_path, verified_tampered_audit)
        verified_tampered_verification = verify_audit_file(audit_path)
        if verified_tampered_verification["verified"] is True:
            print(
                "self-test expected rehashed source-manifest verified drift to fail audit verification",
                file=sys.stderr,
            )
            print(json.dumps(verified_tampered_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        write_json(audit_path, complete_audit)
        early_failure_tampered_audit = load_json_object(audit_path)
        early_failure_source = early_failure_tampered_audit["provenance"]["supplementalSourceManifest"]
        early_failure_source["path"] = str(temp_root / "missing-source-manifest.json")
        early_failure_source["verified"] = True
        early_failure_tampered_audit = attach_audit_digest(early_failure_tampered_audit)
        write_json(audit_path, early_failure_tampered_audit)
        early_failure_tampered_verification = verify_audit_file(audit_path)
        if early_failure_tampered_verification["verified"] is True or not any(
            "supplementalSourceManifest.verified" in failure
            for failure in early_failure_tampered_verification["failures"]
        ):
            print(
                "self-test expected early source-manifest provenance failures to verify recorded status",
                file=sys.stderr,
            )
            print(json.dumps(early_failure_tampered_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        write_json(audit_path, complete_audit)
        persisted = load_json_object(audit_path)
        persisted["ready"] = True
        write_json(audit_path, persisted)
        invalid_audit_file = verify_audit_file(audit_path)
        if invalid_audit_file["verified"] is True:
            print("self-test expected mutated persisted audit to fail digest verification", file=sys.stderr)
            print(json.dumps(invalid_audit_file, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        write_json(audit_path, complete_audit)

        drift_artifact = proof_root / "supplemental" / "policy_simulation_impact" / "proof-artifact.json"
        drift_artifact.write_text(
            json.dumps({"evidence": {"tampered": True}}, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        drift_audit_file = verify_audit_file(audit_path)
        if drift_audit_file["verified"] is True:
            print("self-test expected source artifact mutation to fail persisted audit verification", file=sys.stderr)
            print(json.dumps(drift_audit_file, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        drift_audit = build_audit(manifest_path, supplemental, source_manifest_path)
        drift_statuses = {item["key"]: item["status"] for item in drift_audit["checklist"]}
        if drift_statuses.get("policy_simulation_impact") != "failed":
            print("self-test expected supplemental artifact mutation to fail", file=sys.stderr)
            print(json.dumps(drift_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1

    print("endpoint decision engine readiness audit self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--macos-provider-manifest", type=pathlib.Path)
    parser.add_argument("--output", type=pathlib.Path, help="Write the readiness audit JSON to this path")
    parser.add_argument(
        "--verify-audit",
        type=pathlib.Path,
        help="Verify a previously written audit JSON self-hash and re-check recorded source provenance",
    )
    parser.add_argument(
        "--proof",
        action="append",
        default=[],
        metavar="KEY=PATH",
        help=(
            "Supplemental strict proof artifact for a non-macOS checklist key. "
            "May be repeated."
        ),
    )
    parser.add_argument(
        "--supplemental-source-manifest",
        type=pathlib.Path,
        help=(
            "Supplemental proof source manifest to record in persisted audit provenance. "
            "Required for a complete supplemental proof set to verify as prove-later evidence."
        ),
    )
    parser.add_argument(
        "--write-proof",
        choices=sorted(SUPPLEMENTAL_PROOF_KEYS),
        metavar="KEY",
        help="Write one strict supplemental proof JSON for KEY and validate it",
    )
    parser.add_argument(
        "--proof-template",
        choices=["all", *sorted(SUPPLEMENTAL_PROOF_KEYS)],
        metavar="KEY",
        help="Print the key-specific evidence and command-result template for one proof key or all",
    )
    parser.add_argument("--proof-output", type=pathlib.Path, help="Output path for --write-proof")
    parser.add_argument(
        "--proof-evidence",
        type=pathlib.Path,
        help="KEY-specific evidence JSON object used by --write-proof",
    )
    parser.add_argument(
        "--proof-artifact",
        action="append",
        default=[],
        type=pathlib.Path,
        help="Evidence artifact to hash into a generated proof. May be repeated.",
    )
    parser.add_argument(
        "--proof-command-result",
        action="append",
        default=[],
        type=pathlib.Path,
        help=(
            "Command-result JSON artifact to hash into a generated proof command entry. "
            "The JSON must include argv and exitCode: 0. May be repeated."
        ),
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    if args.proof_template is not None:
        if args.proof_template == "all":
            payload: dict[str, Any] = {
                "schemaVersion": 1,
                "supplementalProofTemplates": {
                    key: build_supplemental_proof_template(key)
                    for key in sorted(SUPPLEMENTAL_PROOF_KEYS)
                },
            }
        else:
            payload = build_supplemental_proof_template(args.proof_template)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    if args.write_proof is not None:
        if args.proof_output is None:
            parser.error("--write-proof requires --proof-output")
        if args.proof_evidence is None:
            parser.error("--write-proof requires --proof-evidence")
        try:
            result = write_operator_supplemental_proof(
                args.write_proof,
                args.proof_output,
                args.proof_evidence,
                args.proof_artifact,
                args.proof_command_result,
            )
        except ValueError as exc:
            print(f"proof generation failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["status"] == "verified" else 1

    if args.verify_audit is not None:
        result = verify_audit_file(args.verify_audit)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["verified"] else 1

    try:
        supplemental_proofs = parse_proof_specs(args.proof)
    except ValueError as exc:
        parser.error(str(exc))

    audit = build_audit(
        args.macos_provider_manifest,
        supplemental_proofs,
        args.supplemental_source_manifest,
    )
    if args.output is not None:
        write_json(args.output, audit)
    print(json.dumps(audit, indent=2, sort_keys=True))
    return 0 if audit["ready"] else 1


if __name__ == "__main__":
    sys.exit(main())
