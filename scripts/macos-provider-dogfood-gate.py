#!/usr/bin/env python3
"""Gate macOS ES/NE deployed-provider dogfood artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import pathlib
import sys
from typing import Any, Callable


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
Verifier = Callable[[dict[str, Any]], dict[str, Any]]
DEFAULT_MAX_RUN_SKEW_SECONDS = 3600


def load_module(path: pathlib.Path) -> Any:
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_verifier(path: pathlib.Path, function_name: str = "verify_summary") -> Verifier:
    module = load_module(path)
    verifier = getattr(module, function_name, None)
    if not callable(verifier):
        raise RuntimeError(f"{path} does not expose {function_name}()")
    return verifier


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def _rebase_artifact_path(value: Any, output_dir: pathlib.Path) -> Any:
    if not isinstance(value, str) or not value.strip():
        return value
    path = pathlib.Path(value)
    candidates = []
    if path.is_absolute():
        candidates.append(output_dir / path.name)
    else:
        candidates.append(output_dir / path)
        candidates.append(output_dir / path.name)
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return value


def _summary_for_bundle(path: pathlib.Path, artifact_fields: tuple[str, ...]) -> dict[str, Any]:
    summary = load_json_object(path)
    output_dir = path.resolve().parent
    recorded_output_dir = summary.get("outputDir")
    recorded_output_path = (
        pathlib.Path(recorded_output_dir).expanduser().resolve()
        if isinstance(recorded_output_dir, str) and recorded_output_dir.strip()
        else None
    )
    if recorded_output_path == output_dir:
        return summary

    rebased_fields: dict[str, Any] = {}
    rebased = False
    for field in artifact_fields:
        if field in summary:
            value = _rebase_artifact_path(summary[field], output_dir)
            rebased_fields[field] = value
            rebased = rebased or value != summary[field]
    observer = summary.get("authOpenObserver")
    rebased_observer: dict[str, Any] = {}
    if isinstance(observer, dict):
        for field in ("stdout", "stderr"):
            if field in observer:
                value = _rebase_artifact_path(observer[field], output_dir)
                rebased_observer[field] = value
                rebased = rebased or value != observer[field]
    if not rebased:
        return summary

    summary["outputDir"] = str(output_dir)
    for field, value in rebased_fields.items():
        summary[field] = value
    if isinstance(observer, dict):
        for field, value in rebased_observer.items():
            observer[field] = value
    return summary


def _result_string(result: dict[str, Any], field: str, label: str, failures: list[str]) -> str:
    value = result.get(field)
    if isinstance(value, str) and value.strip():
        return value
    failures.append(f"{label}.{field} is required")
    return ""


def _parse_run_id(value: Any, label: str, failures: list[str]) -> dt.datetime | None:
    if not isinstance(value, str) or not value.strip():
        failures.append(f"{label}.runId is required")
        return None
    try:
        return dt.datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc)
    except ValueError:
        failures.append(f"{label}.runId must use YYYYMMDDTHHMMSSZ")
        return None


def _max_run_skew_seconds(
    runs: list[tuple[str, dt.datetime | None]],
    failures: list[str],
) -> int | None:
    present = [(label, timestamp) for label, timestamp in runs if timestamp is not None]
    if len(present) < 2:
        return None
    skew = 0
    for index, (_left_label, left_time) in enumerate(present):
        for _right_label, right_time in present[index + 1 :]:
            delta = int(abs((left_time - right_time).total_seconds()))
            skew = max(skew, delta)
    return skew


def _result_provider_health(
    result: dict[str, Any],
    label: str,
    expected_provider: str,
    failures: list[str],
) -> dict[str, Any]:
    health = result.get("macosProviderHealth")
    if not isinstance(health, dict):
        failures.append(f"{label}.macosProviderHealth is required")
        return {}
    if health.get("provider") != expected_provider:
        failures.append(f"{label}.macosProviderHealth.provider must be {expected_provider}")
    expected_values = {
        "installState": "installed",
        "approval": "approved",
        "runtimeState": "active",
        "installed": True,
        "active": True,
        "healthy": True,
        "availability": "active",
    }
    for field, expected in expected_values.items():
        if health.get(field) != expected:
            failures.append(f"{label}.macosProviderHealth.{field} must be {expected!r}")
    approval_status = health.get("approvalStatus")
    if approval_status not in {"approved", "not_required"}:
        failures.append(f"{label}.macosProviderHealth.approvalStatus must be approved")
    degraded_reasons = health.get("degradedReasons")
    if degraded_reasons not in (None, []):
        failures.append(f"{label}.macosProviderHealth.degradedReasons must be empty")
    return health


def _deployment_extension_points(result: dict[str, Any], failures: list[str]) -> list[str]:
    extension_points = result.get("extensionPoints")
    if not isinstance(extension_points, list):
        failures.append("deploymentEvidence.extensionPoints is required")
        return []
    return [item for item in extension_points if isinstance(item, str)]


def gate_artifacts(
    endpoint_security_summary: pathlib.Path,
    network_extension_summary: pathlib.Path,
    deployment_evidence_summary: pathlib.Path,
    max_run_skew_seconds: int = DEFAULT_MAX_RUN_SKEW_SECONDS,
) -> dict[str, Any]:
    deployment_verifier = load_verifier(SCRIPT_DIR / "macos-provider-deployment-evidence.py")
    es_verifier = load_verifier(SCRIPT_DIR / "endpoint-security-live-dogfood-verify.py")
    ne_verifier = load_verifier(SCRIPT_DIR / "network-extension-live-dogfood-verify.py")

    deployment_result = deployment_verifier(
        _summary_for_bundle(
            deployment_evidence_summary,
            (
                "hostInfo",
                "bundleInfo",
                "systemExtensionsCtl",
                "codesign",
                "codesignVerify",
                "codesignDeepVerify",
                "appEntitlements",
                "systemExtensionCodesign",
                "systemExtensionCodesignVerify",
                "systemExtensionEntitlements",
                "spctl",
                "stapler",
            ),
        )
    )
    es_result = es_verifier(
        _summary_for_bundle(
            endpoint_security_summary,
            (
                "agentHealth",
                "graphResponse",
                "receiptResponse",
                "probeActivityArtifact",
                "protectionState",
            ),
        )
    )
    ne_result = ne_verifier(
        _summary_for_bundle(
            network_extension_summary,
            (
                "agentHealth",
                "findingsRequest",
                "actionRequest",
                "actionResponse",
                "proofResponse",
                "rollbackResponse",
                "finalFlow",
                "postRollbackFlow",
            ),
        )
    )
    deployment_verified = deployment_result.get("verified") is True
    es_verified = es_result.get("verified") is True
    ne_verified = ne_result.get("verified") is True
    failures: list[str] = []
    if not deployment_verified:
        failures.append("deployment_evidence_unverified")
    if not es_verified:
        failures.append("endpoint_security_unverified")
    if not ne_verified:
        failures.append("network_extension_unverified")
    run_skew_seconds: int | None = None

    if deployment_verified and es_verified and ne_verified:
        for field in ("hostId", "userId"):
            deployment_value = _result_string(deployment_result, field, "deploymentEvidence", failures)
            es_value = _result_string(es_result, field, "endpointSecurity", failures)
            ne_value = _result_string(ne_result, field, "networkExtension", failures)
            values = [value for value in (deployment_value, es_value, ne_value) if value]
            if len(set(values)) > 1:
                failures.append(
                    f"{field} must match between deployment evidence, EndpointSecurity, and NetworkExtension"
                )

        for field in ("agentUrl",):
            es_value = _result_string(es_result, field, "endpointSecurity", failures)
            ne_value = _result_string(ne_result, field, "networkExtension", failures)
            if es_value and ne_value and es_value != ne_value:
                failures.append(f"{field} must match between EndpointSecurity and NetworkExtension")

        extension_points = _deployment_extension_points(deployment_result, failures)
        es_health = _result_provider_health(
            es_result,
            "endpointSecurity",
            "endpoint_security",
            failures,
        )
        ne_health = _result_provider_health(
            ne_result,
            "networkExtension",
            "network_extension",
            failures,
        )
        required_extension_points = {
            "endpoint_security": "EndpointSecurity",
            "network_extension_content_filter": "NetworkExtension",
        }
        for extension_point, label in required_extension_points.items():
            if extension_point not in extension_points:
                failures.append(f"deploymentEvidence.extensionPoints must bind {label}")
        for field in ("installState", "approval"):
            es_value = es_health.get(field)
            ne_value = ne_health.get(field)
            if es_value and ne_value and es_value != ne_value:
                failures.append(
                    f"macOS provider {field} must match between EndpointSecurity and NetworkExtension"
                )

        deployment_run_at = _parse_run_id(deployment_result.get("runId"), "deploymentEvidence", failures)
        es_run_at = _parse_run_id(es_result.get("runId"), "endpointSecurity", failures)
        ne_run_at = _parse_run_id(ne_result.get("runId"), "networkExtension", failures)
        run_ids = [
            value
            for value in (
                deployment_result.get("runId"),
                es_result.get("runId"),
                ne_result.get("runId"),
            )
            if isinstance(value, str) and value.strip()
        ]
        if len(set(run_ids)) > 1:
            failures.append(
                "runId must match between deployment evidence, EndpointSecurity, and NetworkExtension"
            )
        if max_run_skew_seconds < 0:
            failures.append("max_run_skew_seconds must be non-negative")
        if max_run_skew_seconds >= 0:
            run_skew_seconds = _max_run_skew_seconds(
                [
                    ("deploymentEvidence", deployment_run_at),
                    ("endpointSecurity", es_run_at),
                    ("networkExtension", ne_run_at),
                ],
                failures,
            )
            if run_skew_seconds is not None and run_skew_seconds > max_run_skew_seconds:
                failures.append(
                    "Deployment evidence, EndpointSecurity, and NetworkExtension runId values must be within "
                    f"{max_run_skew_seconds} seconds"
                )

    return {
        "verified": not failures,
        "failureCount": len(failures),
        "failures": failures,
        "maxRunSkewSeconds": max_run_skew_seconds,
        "runSkewSeconds": run_skew_seconds,
        "deploymentEvidenceSummary": str(deployment_evidence_summary),
        "endpointSecuritySummary": str(endpoint_security_summary),
        "networkExtensionSummary": str(network_extension_summary),
        "providerBindings": {
            "deploymentExtensionPoints": deployment_result.get("extensionPoints"),
            "endpointSecurityProviderHealth": es_result.get("macosProviderHealth"),
            "networkExtensionProviderHealth": ne_result.get("macosProviderHealth"),
        },
        "deploymentEvidence": deployment_result,
        "endpointSecurity": es_result,
        "networkExtension": ne_result,
    }


def fixture_endpoint_security_summary(output_dir: pathlib.Path) -> dict[str, Any]:
    verifier_module = load_verifier(SCRIPT_DIR / "endpoint-security-live-dogfood-verify.py")
    # Reuse the verifier's public contract indirectly by constructing the same
    # minimal shape a real dogfood run writes.
    probe_file = "/tmp/clawdstrike-es-dogfood-20260519T010203Z/probe.txt"
    import hashlib

    target_hash = "sha256:" + hashlib.sha256(probe_file.encode("utf-8")).hexdigest()
    graph_response = {
        "graph": {"nodes": {"node-probe": {"kind": "file", "label": probe_file, "attributes": {}}}}
    }
    receipt_response = {
        "receipts": [
            {
                "receipt": {
                    "receiptId": "receipt-1",
                    "metadata": {
                        "endpointDecision": {
                            "receiptFamily": "observation",
                            "sensorState": {
                                "providers": [{"providerId": "macos.endpoint_security"}]
                            },
                            "decision": {
                                "ruleId": "endpoint.observation.file_access",
                                "observationId": "obs-1",
                            },
                            "evidence": [{"key": "target", "valueHash": target_hash}],
                        }
                    },
                }
            }
        ]
    }
    probe_activity = {
        "probeFile": probe_file,
        "marker": "clawdstrike-es-dogfood-20260519T010203Z",
        "hostId": "qa-mac-1",
        "userId": "operator",
        "agentUrl": "http://127.0.0.1:9878",
        "commands": [{"argv": ["/bin/ls", probe_file], "exitCode": 0}],
    }
    provider = {
        "providerId": "macos.endpoint_security",
        "installed": True,
        "active": True,
        "healthy": True,
        "degraded": False,
        "fullDiskAccess": True,
    }
    protection_state = {
        "sensor_state": {
            "providers": [
                {"providerId": "agent-api", "installed": True, "active": True, "healthy": True},
                provider,
            ]
        },
        "receipt": {
            "receipt": {
                "metadata": {
                    "endpointDecision": {
                        "receiptFamily": "sensor_state",
                        "decision": {"ruleId": "endpoint.sensor_state"},
                        "sensorState": {"providers": [provider]},
                    }
                }
            }
        },
    }
    agent_health = fixture_agent_health()
    summary = {
        "runId": "20260519T010203Z",
        "status": "passed",
        "outputDir": str(output_dir),
        "hostId": "qa-mac-1",
        "userId": "operator",
        "agentUrl": "http://127.0.0.1:9878",
        "agentHealth": write_json_artifact(output_dir / "agent-health.json", agent_health),
        "probeFile": probe_file,
        "marker": "clawdstrike-es-dogfood-20260519T010203Z",
        "provider": provider,
        "protectionState": write_json_artifact(output_dir / "protection-state.json", protection_state),
        "beforeObservationCount": 7,
        "afterObservationCount": 8,
        "match": {
            "probeFile": probe_file,
            "marker": "clawdstrike-es-dogfood-20260519T010203Z",
            "observationCountIncreased": True,
            "matchedNodeCount": 1,
            "matches": [{"matchedProbeFile": True, "matchedMarker": False}],
        },
        "receiptMatch": {
            "probeFile": probe_file,
            "targetHash": target_hash,
            "matchedReceiptCount": 1,
            "matches": [
                {
                    "receiptId": "receipt-1",
                    "ruleId": "endpoint.observation.file_access",
                    "observationId": "obs-1",
                    "providerId": "macos.endpoint_security",
                    "targetHash": target_hash,
                }
            ],
        },
        "graphResponse": write_json_artifact(output_dir / "causal-graph-attempt-1.json", graph_response),
        "receiptResponse": write_json_artifact(
            output_dir / "observation-receipts-attempt-1.json",
            receipt_response,
        ),
        "probeActivityArtifact": write_json_artifact(
            output_dir / "probe-activity.json",
            probe_activity,
        ),
        "syntheticEndpointSecurityPostUsed": False,
        "authOpenObserver": {"started": False},
    }
    result = verifier_module(summary)
    if result.get("verified") is not True:
        raise AssertionError(f"fixture EndpointSecurity summary no longer verifies: {result}")
    return summary


def fixture_deployment_evidence_summary(output_dir: pathlib.Path) -> dict[str, Any]:
    deployment_module = load_module(SCRIPT_DIR / "macos-provider-deployment-evidence.py")
    return deployment_module.fixture_summary(output_dir)


def write_json_artifact(path: pathlib.Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def fixture_agent_health() -> dict[str, Any]:
    return {
        "status": "ok",
        "macos_host": {
            "install_state": "installed",
            "approval": "approved",
            "endpoint_security": {
                "runtime": {"state": "active"},
                "provider_state": {
                    "provider": "endpoint_security",
                    "installed": True,
                    "approval_status": "approved",
                    "active": True,
                    "healthy": True,
                    "availability": "active",
                    "degraded_reasons": [],
                    "last_healthy_timestamp": "2026-05-19T01:02:03Z",
                },
            },
            "network_extension": {
                "runtime": {"state": "active"},
                "provider_state": {
                    "provider": "network_extension",
                    "installed": True,
                    "approval_status": "approved",
                    "active": True,
                    "healthy": True,
                    "availability": "active",
                    "degraded_reasons": [],
                    "last_healthy_timestamp": "2026-05-19T01:02:03Z",
                },
            },
        },
    }


def fixture_network_extension_summary(output_dir: pathlib.Path) -> dict[str, Any]:
    verifier_module = load_verifier(SCRIPT_DIR / "network-extension-live-dogfood-verify.py")
    agent_health = fixture_agent_health()
    findings_request = {
        "observations": [
            {
                "observationId": "obs-ne-dogfood-20260519T010203Z",
                "hostId": "qa-mac-1",
                "userId": "operator",
                "sessionId": "session-ne-dogfood",
                "event": {
                    "type": "network_flow",
                    "host": "example.com",
                    "port": 443,
                    "protocol": "tcp",
                },
                "metadata": {
                    "source": "network-extension-live-dogfood",
                    "dogfoodRunId": "20260519T010203Z",
                    "agentId": "agent-ne-dogfood",
                    "workloadId": "network-extension-live-dogfood",
                    "approvalId": "approval-ne-dogfood",
                    "agentUrl": "http://127.0.0.1:9878",
                },
            }
        ],
        "honeyArtifacts": [],
    }
    action_request = {
        "action": "restrict_egress",
        "dryRun": False,
        "actor": {
            "hostId": "qa-mac-1",
            "userId": "operator",
            "sessionId": "session-ne-dogfood",
            "agentId": "agent-ne-dogfood",
            "workloadId": "network-extension-live-dogfood",
            "approvalId": "approval-ne-dogfood",
        },
    }
    action_response = {"execution": {"executionId": "resp-exec-1", "status": "succeeded"}}
    proof_response = {
        "executionId": "resp-exec-1",
        "snapshotPresent": True,
        "snapshotDecodable": True,
        "activeRestrictionCount": 1,
        "enforcementReady": True,
        "liveEnforcementProven": True,
        "liveEnforcementProofReasons": [],
        "flowCounterObserved": True,
        "observedFlowCount": 3,
        "blockedFlowCount": 2,
        "remediationRequestCount": 1,
        "droppedVerdictCount": 0,
        "providerReloadDelivery": {
            "executionId": "resp-exec-1",
            "observed": True,
            "matched": True,
            "requestId": "reload-1",
            "requestIdMatches": True,
            "generation": 7,
            "generationMatches": True,
            "policySnapshotPathMatches": True,
            "providerReloaded": True,
        },
        "networkExtensionProvider": {
            "policy_synced": True,
            "enforcement_ready": True,
        },
        "sensorState": {
            "providers": [
                {"providerId": "agent-api", "active": True, "healthy": True},
                {"providerId": "macos.network_extension", "active": True, "healthy": True},
            ]
        },
        "receipt": {
            "receipt": {
                "metadata": {
                    "endpointDecision": {
                        "receiptFamily": "sensor_state",
                        "decision": {"ruleId": "endpoint.sensor_state"},
                        "sensorState": {
                            "providers": [
                                {
                                    "providerId": "macos.network_extension",
                                    "active": True,
                                    "healthy": True,
                                }
                            ]
                        },
                    }
                }
            }
        },
    }
    rollback_response = {"rollbackTransition": {"status": "rolled_back"}}
    final_flow = {"connectSucceeded": False}
    post_rollback_flow = {"connectSucceeded": True}
    summary = {
        "runId": "20260519T010203Z",
        "status": "passed",
        "target": "example.com:443",
        "outputDir": str(output_dir),
        "agentUrl": "http://127.0.0.1:9878",
        "agentHealth": write_json_artifact(output_dir / "agent-health.json", agent_health),
        "hostId": "qa-mac-1",
        "userId": "operator",
        "sessionId": "session-ne-dogfood",
        "agentId": "agent-ne-dogfood",
        "workloadId": "network-extension-live-dogfood",
        "approvalId": "approval-ne-dogfood",
        "executionId": "resp-exec-1",
        "liveEnforcementProven": True,
        "liveEnforcementProofReasons": [],
        "blockedFlowCount": 2,
        "droppedVerdictCount": 0,
        "providerReloadDelivery": {
            "executionId": "resp-exec-1",
            "observed": True,
            "matched": True,
            "requestId": "reload-1",
            "requestIdMatches": True,
            "generation": 7,
            "generationMatches": True,
            "policySnapshotPathMatches": True,
            "providerReloaded": True,
        },
        "finalConnectSucceeded": False,
        "rollbackSkipped": False,
        "rollbackSucceeded": True,
        "postRollbackConnectSucceeded": True,
        "findingsRequest": write_json_artifact(output_dir / "findings-request.json", findings_request),
        "actionRequest": write_json_artifact(output_dir / "action-request.json", action_request),
        "actionResponse": write_json_artifact(output_dir / "response-action-response.json", action_response),
        "proofResponse": write_json_artifact(output_dir / "proof-response.json", proof_response),
        "rollbackResponse": write_json_artifact(output_dir / "rollback-response.json", rollback_response),
        "finalFlow": write_json_artifact(output_dir / "final-blocked-flow.json", final_flow),
        "postRollbackFlow": write_json_artifact(output_dir / "post-rollback-connect.json", post_rollback_flow),
    }
    result = verifier_module(summary)
    if result.get("verified") is not True:
        raise AssertionError(f"fixture NetworkExtension summary no longer verifies: {result}")
    return summary


def run_self_test() -> int:
    import tempfile

    with tempfile.TemporaryDirectory(prefix="clawdstrike-macos-dogfood-gate-") as temp_dir:
        temp_path = pathlib.Path(temp_dir)
        deployment_path = temp_path / "deployment-evidence-summary.json"
        es_path = temp_path / "endpoint-security-summary.json"
        ne_path = temp_path / "network-extension-summary.json"
        deployment_output_dir = temp_path / "deployment-artifacts"
        es_output_dir = temp_path / "es-artifacts"
        ne_output_dir = temp_path / "ne-artifacts"
        deployment_path.write_text(
            json.dumps(fixture_deployment_evidence_summary(deployment_output_dir)),
            encoding="utf-8",
        )
        es_path.write_text(json.dumps(fixture_endpoint_security_summary(es_output_dir)), encoding="utf-8")
        ne_path.write_text(json.dumps(fixture_network_extension_summary(ne_output_dir)), encoding="utf-8")

        valid = gate_artifacts(es_path, ne_path, deployment_path)
        if valid["verified"] is not True:
            print(json.dumps(valid, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        bindings = valid.get("providerBindings") or {}
        if "endpoint_security" not in (bindings.get("deploymentExtensionPoints") or []):
            print("self-test expected deployment EndpointSecurity extension binding", file=sys.stderr)
            return 1
        if "network_extension_content_filter" not in (
            bindings.get("deploymentExtensionPoints") or []
        ):
            print("self-test expected deployment NetworkExtension extension binding", file=sys.stderr)
            return 1
        if (
            (bindings.get("endpointSecurityProviderHealth") or {}).get("provider")
            != "endpoint_security"
        ):
            print("self-test expected EndpointSecurity provider health binding", file=sys.stderr)
            return 1
        if (
            (bindings.get("networkExtensionProviderHealth") or {}).get("provider")
            != "network_extension"
        ):
            print("self-test expected NetworkExtension provider health binding", file=sys.stderr)
            return 1

        mismatched_deployment = fixture_deployment_evidence_summary(deployment_output_dir)
        mismatched_deployment["hostId"] = "qa-mac-2"
        deployment_path.write_text(json.dumps(mismatched_deployment), encoding="utf-8")
        invalid = gate_artifacts(es_path, ne_path, deployment_path)
        if invalid["verified"] is True or not any("hostId must match" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        deployment_path.write_text(
            json.dumps(fixture_deployment_evidence_summary(deployment_output_dir)),
            encoding="utf-8",
        )

        mismatched_ne = fixture_network_extension_summary(ne_output_dir)
        mismatched_ne["hostId"] = "qa-mac-2"
        findings_path = pathlib.Path(mismatched_ne["findingsRequest"])
        findings_payload = json.loads(findings_path.read_text(encoding="utf-8"))
        findings_payload["observations"][0]["hostId"] = "qa-mac-2"
        findings_path.write_text(json.dumps(findings_payload), encoding="utf-8")
        action_path = pathlib.Path(mismatched_ne["actionRequest"])
        action_payload = json.loads(action_path.read_text(encoding="utf-8"))
        action_payload["actor"]["hostId"] = "qa-mac-2"
        action_path.write_text(json.dumps(action_payload), encoding="utf-8")
        ne_path.write_text(json.dumps(mismatched_ne), encoding="utf-8")
        invalid = gate_artifacts(es_path, ne_path, deployment_path)
        if invalid["verified"] is True or not any("hostId must match" in item for item in invalid["failures"]):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        stale_ne = fixture_network_extension_summary(ne_output_dir)
        stale_ne["runId"] = "20260519T030204Z"
        findings_path = pathlib.Path(stale_ne["findingsRequest"])
        findings_payload = json.loads(findings_path.read_text(encoding="utf-8"))
        findings_payload["observations"][0]["metadata"]["dogfoodRunId"] = stale_ne["runId"]
        findings_path.write_text(json.dumps(findings_payload), encoding="utf-8")
        ne_path.write_text(json.dumps(stale_ne), encoding="utf-8")
        invalid = gate_artifacts(es_path, ne_path, deployment_path)
        expected_run_mismatch = (
            "runId must match between deployment evidence, EndpointSecurity, and NetworkExtension"
        )
        if (
            invalid["verified"] is True
            or invalid["runSkewSeconds"] <= DEFAULT_MAX_RUN_SKEW_SECONDS
            or expected_run_mismatch not in invalid["failures"]
        ):
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        invalid_ne = fixture_network_extension_summary(ne_output_dir)
        invalid_ne["rollbackSkipped"] = True
        ne_path.write_text(json.dumps(invalid_ne), encoding="utf-8")
        invalid = gate_artifacts(es_path, ne_path, deployment_path)
        if invalid["verified"] is True or invalid["failures"] != ["network_extension_unverified"]:
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        invalid_es = fixture_endpoint_security_summary(es_output_dir)
        invalid_es["syntheticEndpointSecurityPostUsed"] = True
        es_path.write_text(json.dumps(invalid_es), encoding="utf-8")
        ne_path.write_text(json.dumps(fixture_network_extension_summary(ne_output_dir)), encoding="utf-8")
        invalid = gate_artifacts(es_path, ne_path, deployment_path)
        if invalid["verified"] is True or invalid["failures"] != ["endpoint_security_unverified"]:
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        invalid_deployment = fixture_deployment_evidence_summary(deployment_output_dir)
        systemextensions_path = pathlib.Path(invalid_deployment["systemExtensionsCtl"])
        systemextensions = json.loads(systemextensions_path.read_text(encoding="utf-8"))
        systemextensions["stdout"] = systemextensions["stdout"].replace("activated enabled", "activated")
        systemextensions_path.write_text(json.dumps(systemextensions), encoding="utf-8")
        deployment_path.write_text(json.dumps(invalid_deployment), encoding="utf-8")
        es_path.write_text(json.dumps(fixture_endpoint_security_summary(es_output_dir)), encoding="utf-8")
        invalid = gate_artifacts(es_path, ne_path, deployment_path)
        if invalid["verified"] is True or invalid["failures"] != ["deployment_evidence_unverified"]:
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

    print("macos provider dogfood gate self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deployment-evidence-summary", type=pathlib.Path, help="Path to deployment evidence summary.json")
    parser.add_argument("--endpoint-security-summary", type=pathlib.Path, help="Path to ES summary.json")
    parser.add_argument("--network-extension-summary", type=pathlib.Path, help="Path to NE summary.json")
    parser.add_argument(
        "--max-run-skew-seconds",
        type=int,
        default=DEFAULT_MAX_RUN_SKEW_SECONDS,
        help=(
            "Maximum allowed deployment/ES/NE runId skew in seconds "
            f"(default: {DEFAULT_MAX_RUN_SKEW_SECONDS})"
        ),
    )
    parser.add_argument("--self-test", action="store_true", help="Run built-in gate checks")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if (
        args.deployment_evidence_summary is None
        or args.endpoint_security_summary is None
        or args.network_extension_summary is None
    ):
        parser.error(
            "--deployment-evidence-summary, --endpoint-security-summary, "
            "and --network-extension-summary are required"
        )

    result = gate_artifacts(
        args.endpoint_security_summary,
        args.network_extension_summary,
        args.deployment_evidence_summary,
        max_run_skew_seconds=args.max_run_skew_seconds,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
