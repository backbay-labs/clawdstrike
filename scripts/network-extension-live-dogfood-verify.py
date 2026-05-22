#!/usr/bin/env python3
"""Verify NetworkExtension live containment dogfood summary artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import sys
import tempfile
from typing import Any


LOCAL_TARGETS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _as_dict(value: Any, field: str, failures: list[str]) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    failures.append(f"{field} must be an object")
    return {}


def _as_non_empty_string(value: Any, field: str, failures: list[str]) -> str:
    if isinstance(value, str) and value.strip():
        return value
    failures.append(f"{field} must be a non-empty string")
    return ""


def _require_run_id(value: str, field: str, failures: list[str]) -> None:
    if not value:
        return
    try:
        dt.datetime.strptime(value, "%Y%m%dT%H%M%SZ")
    except ValueError:
        failures.append(f"{field} must use YYYYMMDDTHHMMSSZ")


def _as_bool(value: Any, field: str, failures: list[str]) -> bool | None:
    if isinstance(value, bool):
        return value
    failures.append(f"{field} must be a boolean")
    return None


def _as_int(value: Any, field: str, failures: list[str]) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    failures.append(f"{field} must be an integer")
    return None


def _existing_file_in_output_dir(
    value: Any,
    field: str,
    output_dir: str,
    failures: list[str],
) -> pathlib.Path | None:
    path_text = _as_non_empty_string(value, field, failures)
    if not path_text or not output_dir:
        return None
    output_root = pathlib.Path(output_dir).expanduser().resolve()
    artifact_path = pathlib.Path(path_text).expanduser()
    if not artifact_path.is_absolute():
        artifact_path = output_root / artifact_path
    artifact_resolved = artifact_path.resolve()
    try:
        if os.path.commonpath([str(output_root), str(artifact_resolved)]) != str(output_root):
            failures.append(f"{field} must be inside outputDir")
    except ValueError:
        failures.append(f"{field} must be inside outputDir")
    if not artifact_resolved.is_file():
        failures.append(f"{field} must reference an existing file")
        return None
    return artifact_resolved


def _load_artifact_json(path: pathlib.Path | None, field: str, failures: list[str]) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception as exc:  # noqa: BLE001 - verifier output should preserve parse failure.
        failures.append(f"{field} must contain valid JSON: {exc}")
        return {}
    if not isinstance(payload, dict):
        failures.append(f"{field} must contain a JSON object")
        return {}
    return payload


def _artifact_value_matches(
    summary_value: Any,
    artifact_value: Any,
    field: str,
    failures: list[str],
) -> None:
    if summary_value != artifact_value:
        failures.append(f"{field} must match raw artifact value")


def _require_macos_provider_health(
    agent_health: dict[str, Any],
    provider_key: str,
    provider_label: str,
    failures: list[str],
) -> None:
    macos_host = agent_health.get("macos_host") or agent_health.get("macosHost")
    if not isinstance(macos_host, dict):
        failures.append("agentHealth.macos_host must be an object")
        return
    if macos_host.get("install_state") != "installed":
        failures.append("agentHealth.macos_host.install_state must be installed")
    if macos_host.get("approval") != "approved":
        failures.append("agentHealth.macos_host.approval must be approved")
    provider = macos_host.get(provider_key)
    if not isinstance(provider, dict):
        failures.append(f"agentHealth.macos_host.{provider_key} must be an object")
        return
    runtime = provider.get("runtime") or {}
    if not isinstance(runtime, dict) or runtime.get("state") != "active":
        failures.append(f"agentHealth.macos_host.{provider_key}.runtime.state must be active")
    provider_state = provider.get("provider_state") or provider.get("providerState")
    if not isinstance(provider_state, dict):
        failures.append(f"agentHealth.macos_host.{provider_key}.provider_state is required")
        return
    if provider_state.get("provider") != provider_label:
        failures.append(
            f"agentHealth.macos_host.{provider_key}.provider_state.provider must be {provider_label}"
        )
    if provider_state.get("installed") is not True:
        failures.append(f"agentHealth.macos_host.{provider_key}.provider_state.installed must be true")
    if provider_state.get("active") is not True:
        failures.append(f"agentHealth.macos_host.{provider_key}.provider_state.active must be true")
    if provider_state.get("healthy") is not True:
        failures.append(f"agentHealth.macos_host.{provider_key}.provider_state.healthy must be true")
    if provider_state.get("availability") != "active":
        failures.append(
            f"agentHealth.macos_host.{provider_key}.provider_state.availability must be active"
        )
    approval_status = provider_state.get("approval_status") or provider_state.get("approvalStatus")
    if approval_status not in {"approved", "not_required"}:
        failures.append(
            f"agentHealth.macos_host.{provider_key}.provider_state.approval_status must be approved"
        )
    degraded_reasons = provider_state.get("degraded_reasons") or provider_state.get("degradedReasons")
    if degraded_reasons not in (None, []):
        failures.append(
            f"agentHealth.macos_host.{provider_key}.provider_state.degraded_reasons must be empty"
        )


def _macos_provider_health_snapshot(
    agent_health: dict[str, Any],
    provider_key: str,
) -> dict[str, Any] | None:
    macos_host = agent_health.get("macos_host") or agent_health.get("macosHost")
    if not isinstance(macos_host, dict):
        return None
    provider = macos_host.get(provider_key)
    if not isinstance(provider, dict):
        return None
    runtime = provider.get("runtime") if isinstance(provider.get("runtime"), dict) else {}
    provider_state = provider.get("provider_state") or provider.get("providerState")
    if not isinstance(provider_state, dict):
        return None
    degraded_reasons = provider_state.get("degraded_reasons") or provider_state.get("degradedReasons")
    return {
        "installState": macos_host.get("install_state") or macos_host.get("installState"),
        "approval": macos_host.get("approval"),
        "providerKey": provider_key,
        "provider": provider_state.get("provider"),
        "runtimeState": runtime.get("state"),
        "installed": provider_state.get("installed"),
        "active": provider_state.get("active"),
        "healthy": provider_state.get("healthy"),
        "availability": provider_state.get("availability"),
        "approvalStatus": provider_state.get("approval_status") or provider_state.get("approvalStatus"),
        "degradedReasons": degraded_reasons if degraded_reasons is not None else [],
        "lastHealthyTimestamp": provider_state.get("last_healthy_timestamp")
        or provider_state.get("lastHealthyTimestamp"),
    }


def parse_target(target: str, failures: list[str]) -> tuple[str, int] | None:
    if target.startswith("["):
        end = target.find("]")
        if end == -1 or len(target) <= end + 2 or target[end + 1] != ":":
            failures.append("target must use [addr]:port for bracketed IPv6")
            return None
        host = target[1:end]
        port_text = target[end + 2:]
    else:
        if ":" not in target:
            failures.append("target must include host:port")
            return None
        host, port_text = target.rsplit(":", 1)

    host = host.strip()
    if not host:
        failures.append("target host must not be empty")
        return None
    if any(character.isspace() for character in host):
        failures.append("target host must not contain whitespace")
        return None
    if host.lower() in LOCAL_TARGETS:
        failures.append("target must not be loopback/local")
        return None
    try:
        port = int(port_text)
    except ValueError:
        failures.append("target port must be an integer")
        return None
    if port < 1 or port > 65535:
        failures.append("target port must be between 1 and 65535")
        return None
    return host, port


def verify_summary(summary: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []

    status = summary.get("status")
    if status != "passed":
        failures.append(f"status must be passed, got: {status!r}")

    output_dir = _as_non_empty_string(summary.get("outputDir"), "outputDir", failures)
    if output_dir and not pathlib.Path(output_dir).expanduser().resolve().is_dir():
        failures.append("outputDir must reference an existing directory")

    findings_request_path = _existing_file_in_output_dir(
        summary.get("findingsRequest"),
        "findingsRequest",
        output_dir,
        failures,
    )
    agent_health_path = _existing_file_in_output_dir(
        summary.get("agentHealth"),
        "agentHealth",
        output_dir,
        failures,
    )
    action_request_path = _existing_file_in_output_dir(
        summary.get("actionRequest"),
        "actionRequest",
        output_dir,
        failures,
    )
    action_response_path = _existing_file_in_output_dir(
        summary.get("actionResponse"),
        "actionResponse",
        output_dir,
        failures,
    )
    proof_response_path = _existing_file_in_output_dir(
        summary.get("proofResponse"),
        "proofResponse",
        output_dir,
        failures,
    )
    rollback_response_path = _existing_file_in_output_dir(
        summary.get("rollbackResponse"),
        "rollbackResponse",
        output_dir,
        failures,
    )
    final_flow_path = _existing_file_in_output_dir(
        summary.get("finalFlow"),
        "finalFlow",
        output_dir,
        failures,
    )
    post_rollback_flow_path = _existing_file_in_output_dir(
        summary.get("postRollbackFlow"),
        "postRollbackFlow",
        output_dir,
        failures,
    )

    findings_request = _load_artifact_json(findings_request_path, "findingsRequest", failures)
    agent_health = _load_artifact_json(agent_health_path, "agentHealth", failures)
    action_request = _load_artifact_json(action_request_path, "actionRequest", failures)
    action_response = _load_artifact_json(action_response_path, "actionResponse", failures)
    proof_response = _load_artifact_json(proof_response_path, "proofResponse", failures)
    rollback_response = _load_artifact_json(
        rollback_response_path,
        "rollbackResponse",
        failures,
    )
    final_flow = _load_artifact_json(final_flow_path, "finalFlow", failures)
    post_rollback_flow = _load_artifact_json(
        post_rollback_flow_path,
        "postRollbackFlow",
        failures,
    )
    if agent_health:
        _require_macos_provider_health(
            agent_health,
            "network_extension",
            "network_extension",
            failures,
        )
    macos_provider_health = (
        _macos_provider_health_snapshot(agent_health, "network_extension") if agent_health else None
    )

    target = _as_non_empty_string(summary.get("target"), "target", failures)
    parsed_target = parse_target(target, failures) if target else None
    run_id = _as_non_empty_string(summary.get("runId"), "runId", failures)
    _require_run_id(run_id, "runId", failures)
    host_id = _as_non_empty_string(summary.get("hostId"), "hostId", failures)
    user_id = _as_non_empty_string(summary.get("userId"), "userId", failures)
    session_id = _as_non_empty_string(summary.get("sessionId"), "sessionId", failures)
    agent_id = _as_non_empty_string(summary.get("agentId"), "agentId", failures)
    workload_id = _as_non_empty_string(summary.get("workloadId"), "workloadId", failures)
    approval_id = _as_non_empty_string(summary.get("approvalId"), "approvalId", failures)
    agent_url = _as_non_empty_string(summary.get("agentUrl"), "agentUrl", failures)

    if findings_request:
        observations = findings_request.get("observations")
        if not isinstance(observations, list) or not observations:
            failures.append("findingsRequest.observations must be a non-empty list")
        else:
            observation = observations[0] if isinstance(observations[0], dict) else {}
            if not observation:
                failures.append("findingsRequest.observations[0] must be an object")
            _artifact_value_matches(host_id, observation.get("hostId"), "hostId", failures)
            _artifact_value_matches(user_id, observation.get("userId"), "userId", failures)
            _artifact_value_matches(
                session_id,
                observation.get("sessionId"),
                "sessionId",
                failures,
            )
            metadata = observation.get("metadata") or {}
            if not isinstance(metadata, dict):
                failures.append("findingsRequest.observations[0].metadata must be an object")
                metadata = {}
            _artifact_value_matches(agent_id, metadata.get("agentId"), "agentId", failures)
            _artifact_value_matches(run_id, metadata.get("dogfoodRunId"), "runId", failures)
            _artifact_value_matches(
                workload_id,
                metadata.get("workloadId"),
                "workloadId",
                failures,
            )
            _artifact_value_matches(
                approval_id,
                metadata.get("approvalId"),
                "approvalId",
                failures,
            )
            _artifact_value_matches(agent_url, metadata.get("agentUrl"), "agentUrl", failures)
            event = observation.get("event") or {}
            if not isinstance(event, dict):
                failures.append("findingsRequest.observations[0].event must be an object")
                event = {}
            if parsed_target:
                _artifact_value_matches(parsed_target[0], event.get("host"), "targetHost", failures)
                _artifact_value_matches(parsed_target[1], event.get("port"), "targetPort", failures)

    if action_request:
        actor = action_request.get("actor") or {}
        if not isinstance(actor, dict):
            failures.append("actionRequest.actor must be an object")
            actor = {}
        _artifact_value_matches(host_id, actor.get("hostId"), "hostId", failures)
        _artifact_value_matches(user_id, actor.get("userId"), "userId", failures)
        _artifact_value_matches(session_id, actor.get("sessionId"), "sessionId", failures)
        _artifact_value_matches(agent_id, actor.get("agentId"), "agentId", failures)
        _artifact_value_matches(workload_id, actor.get("workloadId"), "workloadId", failures)
        _artifact_value_matches(approval_id, actor.get("approvalId"), "approvalId", failures)
        if action_request.get("dryRun") is not False:
            failures.append("actionRequest.dryRun must be false")
        if action_request.get("action") != "restrict_egress":
            failures.append("actionRequest.action must be restrict_egress")

    execution_id = _as_non_empty_string(summary.get("executionId"), "executionId", failures)
    if execution_id and execution_id.lower().startswith("dry"):
        failures.append("executionId must refer to a live execution, not a dry-run placeholder")
    artifact_execution_id = ((action_response.get("execution") or {}).get("executionId"))
    if artifact_execution_id:
        _artifact_value_matches(
            execution_id,
            artifact_execution_id,
            "executionId",
            failures,
        )
    elif action_response:
        failures.append("actionResponse.execution.executionId is required")
    if proof_response.get("executionId"):
        _artifact_value_matches(
            execution_id,
            proof_response.get("executionId"),
            "proofResponse.executionId",
            failures,
        )

    live_proven = _as_bool(summary.get("liveEnforcementProven"), "liveEnforcementProven", failures)
    if live_proven is not True:
        failures.append("liveEnforcementProven must be true")
    if proof_response:
        _artifact_value_matches(
            live_proven,
            proof_response.get("liveEnforcementProven"),
            "liveEnforcementProven",
            failures,
        )

    blocked_flow_count = _as_int(summary.get("blockedFlowCount"), "blockedFlowCount", failures)
    if blocked_flow_count is not None and blocked_flow_count < 1:
        failures.append("blockedFlowCount must be at least 1")
    if proof_response:
        _artifact_value_matches(
            blocked_flow_count,
            proof_response.get("blockedFlowCount"),
            "blockedFlowCount",
            failures,
        )

    dropped_verdict_count = _as_int(summary.get("droppedVerdictCount"), "droppedVerdictCount", failures)
    if dropped_verdict_count is not None and dropped_verdict_count != 0:
        failures.append("droppedVerdictCount must be 0")
    if proof_response:
        _artifact_value_matches(
            dropped_verdict_count,
            proof_response.get("droppedVerdictCount"),
            "droppedVerdictCount",
            failures,
        )

    delivery = _as_dict(summary.get("providerReloadDelivery"), "providerReloadDelivery", failures)
    if delivery.get("matched") is not True:
        failures.append("providerReloadDelivery.matched must be true")
    if proof_response:
        _artifact_value_matches(
            delivery,
            proof_response.get("providerReloadDelivery"),
            "providerReloadDelivery",
            failures,
        )
        proof_delivery = _as_dict(
            proof_response.get("providerReloadDelivery"),
            "proofResponse.providerReloadDelivery",
            failures,
        )
        _artifact_value_matches(
            execution_id,
            proof_delivery.get("executionId"),
            "proofResponse.providerReloadDelivery.executionId",
            failures,
        )
        for field in (
            "observed",
            "matched",
            "requestIdMatches",
            "generationMatches",
            "policySnapshotPathMatches",
            "providerReloaded",
        ):
            if proof_delivery.get(field) is not True:
                failures.append(f"proofResponse.providerReloadDelivery.{field} must be true")

        for field in (
            "snapshotPresent",
            "snapshotDecodable",
            "enforcementReady",
            "flowCounterObserved",
        ):
            if _as_bool(proof_response.get(field), f"proofResponse.{field}", failures) is not True:
                failures.append(f"proofResponse.{field} must be true")
        active_restriction_count = _as_int(
            proof_response.get("activeRestrictionCount"),
            "proofResponse.activeRestrictionCount",
            failures,
        )
        if active_restriction_count is not None and active_restriction_count < 1:
            failures.append("proofResponse.activeRestrictionCount must be at least 1")
        observed_flow_count = _as_int(
            proof_response.get("observedFlowCount"),
            "proofResponse.observedFlowCount",
            failures,
        )
        if observed_flow_count is not None and observed_flow_count < 1:
            failures.append("proofResponse.observedFlowCount must be at least 1")
        if (
            observed_flow_count is not None
            and blocked_flow_count is not None
            and observed_flow_count < blocked_flow_count
        ):
            failures.append("proofResponse.observedFlowCount must cover blockedFlowCount")
        provider = _as_dict(
            proof_response.get("networkExtensionProvider"),
            "proofResponse.networkExtensionProvider",
            failures,
        )
        if provider.get("policy_synced") is not True:
            failures.append("proofResponse.networkExtensionProvider.policy_synced must be true")
        if provider.get("enforcement_ready") is not True:
            failures.append("proofResponse.networkExtensionProvider.enforcement_ready must be true")
        sensor_state = _as_dict(
            proof_response.get("sensorState"),
            "proofResponse.sensorState",
            failures,
        )
        providers = sensor_state.get("providers")
        if not isinstance(providers, list) or not providers:
            failures.append("proofResponse.sensorState.providers must be a non-empty list")
            providers = []
        network_provider = next(
            (
                item
                for item in providers
                if isinstance(item, dict) and item.get("providerId") == "macos.network_extension"
            ),
            None,
        )
        if network_provider is None:
            failures.append("proofResponse.sensorState must include macos.network_extension")
        else:
            if network_provider.get("active") is not True:
                failures.append("proofResponse macos.network_extension provider must be active")
            if network_provider.get("healthy") is not True:
                failures.append("proofResponse macos.network_extension provider must be healthy")
        receipt = proof_response.get("receipt") or {}
        endpoint_decision = ((receipt.get("receipt") or {}).get("metadata") or {}).get(
            "endpointDecision"
        )
        if not isinstance(endpoint_decision, dict):
            failures.append("proofResponse.receipt must include endpointDecision metadata")
        else:
            if endpoint_decision.get("receiptFamily") != "sensor_state":
                failures.append("proofResponse.receipt receiptFamily must be sensor_state")
            if (endpoint_decision.get("decision") or {}).get("ruleId") != "endpoint.sensor_state":
                failures.append("proofResponse.receipt ruleId must be endpoint.sensor_state")
            receipt_sensor_state = endpoint_decision.get("sensorState")
            if not isinstance(receipt_sensor_state, dict):
                failures.append("proofResponse.receipt must bind sensorState")
            else:
                receipt_providers = receipt_sensor_state.get("providers")
                if not isinstance(receipt_providers, list) or not any(
                    isinstance(item, dict) and item.get("providerId") == "macos.network_extension"
                    for item in receipt_providers
                ):
                    failures.append(
                        "proofResponse.receipt sensorState must include macos.network_extension"
                    )

    final_connect = _as_bool(summary.get("finalConnectSucceeded"), "finalConnectSucceeded", failures)
    if final_connect is not False:
        failures.append("finalConnectSucceeded must be false after containment")
    if final_flow:
        _artifact_value_matches(
            final_connect,
            final_flow.get("connectSucceeded"),
            "finalConnectSucceeded",
            failures,
        )

    rollback_skipped = _as_bool(summary.get("rollbackSkipped"), "rollbackSkipped", failures)
    rollback_succeeded = _as_bool(summary.get("rollbackSucceeded"), "rollbackSucceeded", failures)
    post_rollback_connect = _as_bool(
        summary.get("postRollbackConnectSucceeded"),
        "postRollbackConnectSucceeded",
        failures,
    )
    if rollback_skipped is True:
        failures.append("rollbackSkipped must be false for a verified safe-containment pass")
    if rollback_succeeded is not True:
        failures.append("rollbackSucceeded must be true")
    if rollback_response:
        _artifact_value_matches(
            rollback_succeeded,
            bool(rollback_response.get("rollbackTransition")),
            "rollbackSucceeded",
            failures,
        )
    if post_rollback_connect is not True:
        failures.append("postRollbackConnectSucceeded must be true")
    if post_rollback_flow:
        _artifact_value_matches(
            post_rollback_connect,
            post_rollback_flow.get("connectSucceeded"),
            "postRollbackConnectSucceeded",
            failures,
        )

    reasons = summary.get("liveEnforcementProofReasons")
    if not isinstance(reasons, list):
        failures.append("liveEnforcementProofReasons must be a list")
    elif reasons:
        warnings.append("liveEnforcementProofReasons was non-empty despite strict pass")
    if proof_response:
        _artifact_value_matches(
            reasons,
            proof_response.get("liveEnforcementProofReasons", []),
            "liveEnforcementProofReasons",
            failures,
        )

    verified = not failures
    return {
        "verified": verified,
        "failureCount": len(failures),
        "failures": failures,
        "warnings": warnings,
        "runId": run_id or None,
        "outputDir": output_dir or None,
        "hostId": host_id or None,
        "userId": user_id or None,
        "sessionId": session_id or None,
        "agentId": agent_id or None,
        "workloadId": workload_id or None,
        "approvalId": approval_id or None,
        "agentUrl": agent_url or None,
        "macosProviderHealth": macos_provider_health,
        "target": target or None,
        "targetHost": parsed_target[0] if parsed_target else None,
        "targetPort": parsed_target[1] if parsed_target else None,
        "executionId": execution_id or None,
    }


def _write_json(path: pathlib.Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return str(path)


def _valid_summary(output_dir: pathlib.Path) -> dict[str, Any]:
    agent_health = {
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
    action_response = {
        "execution": {
            "executionId": "resp-exec-1",
            "status": "succeeded",
        }
    }
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
    return {
        "runId": "20260519T010203Z",
        "status": "passed",
        "target": "example.com:443",
        "outputDir": str(output_dir),
        "agentUrl": "http://127.0.0.1:9878",
        "agentHealth": _write_json(output_dir / "agent-health.json", agent_health),
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
        "findingsRequest": _write_json(output_dir / "findings-request.json", findings_request),
        "actionRequest": _write_json(output_dir / "action-request.json", action_request),
        "actionResponse": _write_json(output_dir / "action-response.json", action_response),
        "proofResponse": _write_json(output_dir / "proof-response.json", proof_response),
        "rollbackResponse": _write_json(output_dir / "rollback-response.json", rollback_response),
        "finalFlow": _write_json(output_dir / "final-blocked-flow.json", final_flow),
        "postRollbackFlow": _write_json(
            output_dir / "post-rollback-connect.json",
            post_rollback_flow,
        ),
    }


def run_self_test() -> int:
    temp_dir = tempfile.TemporaryDirectory(prefix="clawdstrike-ne-dogfood-verify-")
    output_dir = pathlib.Path(temp_dir.name)

    valid = verify_summary(_valid_summary(output_dir))
    if not valid["verified"]:
        print(json.dumps(valid, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    provider_health = valid.get("macosProviderHealth") or {}
    if provider_health.get("provider") != "network_extension":
        print("self-test expected NetworkExtension provider health snapshot", file=sys.stderr)
        return 1
    if provider_health.get("installState") != "installed" or provider_health.get("approval") != "approved":
        print("self-test expected installed and approved macOS provider health", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["runId"] = "not-a-run-id"
    findings_path = pathlib.Path(invalid_summary["findingsRequest"])
    findings_payload = json.loads(findings_path.read_text(encoding="utf-8"))
    findings_payload["observations"][0]["metadata"]["dogfoodRunId"] = "not-a-run-id"
    findings_path.write_text(json.dumps(findings_payload), encoding="utf-8")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected malformed runId to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["finalConnectSucceeded"] = True
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected final connection success to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["rollbackSkipped"] = True
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected skipped rollback to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["providerReloadDelivery"]["matched"] = False
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected provider reload mismatch to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["target"] = "example.com:99999"
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected impossible target port to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["target"] = "127.0.0.1:443"
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected loopback target to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["proofResponse"] = str(output_dir / "missing-proof-response.json")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected missing proof artifact to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    health_path = pathlib.Path(invalid_summary["agentHealth"])
    health_payload = json.loads(health_path.read_text(encoding="utf-8"))
    health_payload["macos_host"]["network_extension"]["provider_state"]["availability"] = "inactive"
    health_path.write_text(json.dumps(health_payload), encoding="utf-8")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected inactive NetworkExtension provider attestation to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    action_path = pathlib.Path(invalid_summary["actionRequest"])
    action_payload = json.loads(action_path.read_text(encoding="utf-8"))
    action_payload["actor"]["hostId"] = "other-host"
    action_path.write_text(json.dumps(action_payload), encoding="utf-8")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected action-request host mismatch to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    proof_path = pathlib.Path(invalid_summary["proofResponse"])
    proof_payload = json.loads(proof_path.read_text(encoding="utf-8"))
    proof_payload["blockedFlowCount"] = 99
    proof_path.write_text(json.dumps(proof_payload), encoding="utf-8")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected summary/proof mismatch to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    proof_path = pathlib.Path(invalid_summary["proofResponse"])
    proof_payload = json.loads(proof_path.read_text(encoding="utf-8"))
    proof_payload["networkExtensionProvider"]["enforcement_ready"] = False
    proof_path.write_text(json.dumps(proof_payload), encoding="utf-8")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected provider enforcement readiness to fail", file=sys.stderr)
        return 1

    ipv6_summary = _valid_summary(output_dir)
    ipv6_summary["target"] = "[2001:db8::1]:443"
    findings_path = pathlib.Path(ipv6_summary["findingsRequest"])
    findings_payload = json.loads(findings_path.read_text(encoding="utf-8"))
    findings_payload["observations"][0]["event"]["host"] = "2001:db8::1"
    findings_path.write_text(json.dumps(findings_payload), encoding="utf-8")
    ipv6 = verify_summary(ipv6_summary)
    if not ipv6["verified"]:
        print(json.dumps(ipv6, indent=2, sort_keys=True), file=sys.stderr)
        return 1

    print("network-extension live dogfood verifier self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", nargs="?", help="Path to network-extension dogfood summary.json")
    parser.add_argument("--self-test", action="store_true", help="Run built-in verifier checks")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if not args.summary:
        parser.error("summary is required unless --self-test is used")

    with open(args.summary, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise SystemExit("summary must be a JSON object")

    result = verify_summary(payload)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
