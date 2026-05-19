#!/usr/bin/env python3
"""Verify EndpointSecurity live dogfood summary artifacts."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import sys
import tempfile
from typing import Any


ACCEPTED_RULE_IDS = {
    "endpoint.observation.file_access",
    "endpoint.observation.policy_decision",
}
BOOTSTRAP_ONLY_REASON = "live_authorization_signal_missing"


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


def _is_within_directory(path: str, directory: str) -> bool:
    try:
        real_path = os.path.realpath(path)
        real_directory = os.path.realpath(directory)
        return os.path.commonpath([real_path, real_directory]) == real_directory
    except ValueError:
        return False


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


def verify_summary(summary: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []

    status = summary.get("status")
    if status != "passed":
        failures.append(f"status must be passed, got: {status!r}")

    output_dir = _as_non_empty_string(summary.get("outputDir"), "outputDir", failures)
    if output_dir and not pathlib.Path(output_dir).expanduser().resolve().is_dir():
        failures.append("outputDir must reference an existing directory")

    graph_response_path = _existing_file_in_output_dir(
        summary.get("graphResponse"),
        "graphResponse",
        output_dir,
        failures,
    )
    receipt_response_path = _existing_file_in_output_dir(
        summary.get("receiptResponse"),
        "receiptResponse",
        output_dir,
        failures,
    )
    probe_activity_path = _existing_file_in_output_dir(
        summary.get("probeActivityArtifact"),
        "probeActivityArtifact",
        output_dir,
        failures,
    )
    agent_health_path = _existing_file_in_output_dir(
        summary.get("agentHealth"),
        "agentHealth",
        output_dir,
        failures,
    )
    protection_state_path = _existing_file_in_output_dir(
        summary.get("protectionState"),
        "protectionState",
        output_dir,
        failures,
    )
    graph_response = _load_artifact_json(graph_response_path, "graphResponse", failures)
    receipt_response = _load_artifact_json(receipt_response_path, "receiptResponse", failures)
    probe_activity_artifact = _load_artifact_json(
        probe_activity_path,
        "probeActivityArtifact",
        failures,
    )
    agent_health = _load_artifact_json(agent_health_path, "agentHealth", failures)
    protection_state = _load_artifact_json(
        protection_state_path,
        "protectionState",
        failures,
    )
    if agent_health:
        _require_macos_provider_health(
            agent_health,
            "endpoint_security",
            "endpoint_security",
            failures,
        )
    macos_provider_health = (
        _macos_provider_health_snapshot(agent_health, "endpoint_security") if agent_health else None
    )

    synthetic_used = _as_bool(
        summary.get("syntheticEndpointSecurityPostUsed"),
        "syntheticEndpointSecurityPostUsed",
        failures,
    )
    if synthetic_used is not False:
        failures.append("syntheticEndpointSecurityPostUsed must be false")

    run_id = _as_non_empty_string(summary.get("runId"), "runId", failures)
    _require_run_id(run_id, "runId", failures)
    host_id = _as_non_empty_string(summary.get("hostId"), "hostId", failures)
    user_id = _as_non_empty_string(summary.get("userId"), "userId", failures)
    agent_url = _as_non_empty_string(summary.get("agentUrl"), "agentUrl", failures)
    marker = _as_non_empty_string(summary.get("marker"), "marker", failures)
    probe_file = _as_non_empty_string(summary.get("probeFile"), "probeFile", failures)
    if run_id and marker and run_id not in marker:
        failures.append("marker must contain runId")
    if marker and probe_file and marker not in probe_file:
        failures.append("probeFile must contain marker")
    if marker and not marker.startswith("clawdstrike-es-dogfood-"):
        failures.append("marker must start with clawdstrike-es-dogfood-")
    if probe_file and not os.path.isabs(probe_file):
        failures.append("probeFile must be an absolute path")
    if probe_file and any(character.isspace() for character in probe_file):
        failures.append("probeFile must not contain whitespace")
    if probe_activity_artifact:
        if probe_activity_artifact.get("probeFile") != probe_file:
            failures.append("probeActivityArtifact.probeFile must match summary probeFile")
        if probe_activity_artifact.get("marker") != marker:
            failures.append("probeActivityArtifact.marker must match summary marker")
        _artifact_value_matches(
            host_id,
            probe_activity_artifact.get("hostId"),
            "hostId",
            failures,
        )
        _artifact_value_matches(
            user_id,
            probe_activity_artifact.get("userId"),
            "userId",
            failures,
        )
        _artifact_value_matches(
            agent_url,
            probe_activity_artifact.get("agentUrl"),
            "agentUrl",
            failures,
        )
        commands = probe_activity_artifact.get("commands")
        if not isinstance(commands, list) or not commands:
            failures.append("probeActivityArtifact.commands must be a non-empty list")

    provider = _as_dict(summary.get("provider"), "provider", failures)
    if provider.get("providerId") != "macos.endpoint_security":
        failures.append("provider.providerId must be macos.endpoint_security")
    for field in ("installed", "active"):
        if provider.get(field) is not True:
            failures.append(f"provider.{field} must be true")
    if provider.get("fullDiskAccess") is False:
        failures.append("provider.fullDiskAccess must not be false")

    reasons = provider.get("degradationReasons") or provider.get("degradedReasons") or []
    reason_set = {str(reason) for reason in reasons} if isinstance(reasons, list) else set()
    bootstrap_only = reason_set == {BOOTSTRAP_ONLY_REASON}
    if provider.get("healthy") is not True or provider.get("degraded") is True:
        if not bootstrap_only:
            failures.append(
                "provider may only be unhealthy/degraded for live_authorization_signal_missing bootstrap"
            )
        else:
            warnings.append("provider was in first-signal bootstrap state before probe")
    if protection_state:
        sensor_state = protection_state.get("sensor_state") or protection_state.get("sensorState")
        if not isinstance(sensor_state, dict):
            failures.append("protectionState.sensor_state must be an object")
            sensor_state = {}
        providers = sensor_state.get("providers")
        if not isinstance(providers, list) or not providers:
            failures.append("protectionState.sensor_state.providers must be a non-empty list")
            providers = []
        protection_provider = next(
            (
                item
                for item in providers
                if isinstance(item, dict) and item.get("providerId") == "macos.endpoint_security"
            ),
            None,
        )
        if protection_provider is None:
            failures.append("protectionState must include macos.endpoint_security provider")
        else:
            _artifact_value_matches(
                provider,
                protection_provider,
                "provider",
                failures,
            )
        receipt = protection_state.get("receipt") or {}
        endpoint_decision = ((receipt.get("receipt") or {}).get("metadata") or {}).get(
            "endpointDecision"
        )
        if not isinstance(endpoint_decision, dict):
            failures.append("protectionState.receipt must include endpointDecision metadata")
        else:
            if endpoint_decision.get("receiptFamily") != "sensor_state":
                failures.append("protectionState.receipt receiptFamily must be sensor_state")
            if (endpoint_decision.get("decision") or {}).get("ruleId") != "endpoint.sensor_state":
                failures.append("protectionState.receipt ruleId must be endpoint.sensor_state")
            receipt_sensor_state = endpoint_decision.get("sensorState")
            if not isinstance(receipt_sensor_state, dict):
                failures.append("protectionState.receipt must bind sensorState")
            else:
                receipt_providers = receipt_sensor_state.get("providers")
                if not isinstance(receipt_providers, list) or not any(
                    isinstance(item, dict) and item.get("providerId") == "macos.endpoint_security"
                    for item in receipt_providers
                ):
                    failures.append(
                        "protectionState.receipt sensorState must include macos.endpoint_security"
                    )

    before_count = _as_int(summary.get("beforeObservationCount"), "beforeObservationCount", failures)
    after_count = _as_int(summary.get("afterObservationCount"), "afterObservationCount", failures)
    if before_count is not None and after_count is not None and after_count <= before_count:
        failures.append("afterObservationCount must be greater than beforeObservationCount")

    match = _as_dict(summary.get("match"), "match", failures)
    if match.get("probeFile") != probe_file:
        failures.append("match.probeFile must match summary probeFile")
    if match.get("marker") != marker:
        failures.append("match.marker must match summary marker")
    if match.get("observationCountIncreased") is not True:
        failures.append("match.observationCountIncreased must be true")
    matched_node_count = _as_int(match.get("matchedNodeCount"), "match.matchedNodeCount", failures)
    if matched_node_count is not None and matched_node_count < 1:
        failures.append("match.matchedNodeCount must be at least 1")
    graph_matches = match.get("matches")
    if not isinstance(graph_matches, list) or not graph_matches:
        failures.append("match.matches must be a non-empty list")
    elif not any(
        isinstance(item, dict)
        and (item.get("matchedProbeFile") is True or item.get("matchedMarker") is True)
        for item in graph_matches
    ):
        failures.append("match.matches must include a probe-file or marker match")
    if graph_response:
        graph_nodes = (graph_response.get("graph") or {}).get("nodes")
        if not isinstance(graph_nodes, (dict, list)) or not graph_nodes:
            failures.append("graphResponse must contain non-empty graph.nodes")

    receipt_match = _as_dict(summary.get("receiptMatch"), "receiptMatch", failures)
    if receipt_match.get("probeFile") != probe_file:
        failures.append("receiptMatch.probeFile must match summary probeFile")
    expected_hash = "sha256:" + hashlib.sha256(probe_file.encode("utf-8")).hexdigest()
    if receipt_match.get("targetHash") != expected_hash:
        failures.append("receiptMatch.targetHash must be the sha256 hash of probeFile")
    matched_receipt_count = _as_int(
        receipt_match.get("matchedReceiptCount"),
        "receiptMatch.matchedReceiptCount",
        failures,
    )
    if matched_receipt_count is not None and matched_receipt_count < 1:
        failures.append("receiptMatch.matchedReceiptCount must be at least 1")
    receipt_matches = receipt_match.get("matches")
    if not isinstance(receipt_matches, list) or not receipt_matches:
        failures.append("receiptMatch.matches must be a non-empty list")
    else:
        for index, item in enumerate(receipt_matches):
            if not isinstance(item, dict):
                failures.append(f"receiptMatch.matches[{index}] must be an object")
                continue
            if item.get("providerId") != "macos.endpoint_security":
                failures.append(f"receiptMatch.matches[{index}].providerId must be macos.endpoint_security")
            if item.get("ruleId") not in ACCEPTED_RULE_IDS:
                failures.append(f"receiptMatch.matches[{index}].ruleId is not an accepted observation rule")
            if item.get("targetHash") != expected_hash:
                failures.append(f"receiptMatch.matches[{index}].targetHash must match probeFile hash")
            _as_non_empty_string(item.get("receiptId"), f"receiptMatch.matches[{index}].receiptId", failures)
            _as_non_empty_string(
                item.get("observationId"),
                f"receiptMatch.matches[{index}].observationId",
                failures,
            )
    if receipt_response:
        receipts = receipt_response.get("receipts")
        if not isinstance(receipts, list) or not receipts:
            failures.append("receiptResponse must contain a non-empty receipts list")
        else:
            receipt_ids = {
                ((receipt.get("receipt") or {}).get("receiptId"))
                for receipt in receipts
                if isinstance(receipt, dict)
            }
            for index, item in enumerate(receipt_matches if isinstance(receipt_matches, list) else []):
                if isinstance(item, dict) and item.get("receiptId") not in receipt_ids:
                    failures.append(
                        f"receiptMatch.matches[{index}].receiptId must exist in receiptResponse"
                    )

    observer = summary.get("authOpenObserver")
    if observer is not None:
        observer = _as_dict(observer, "authOpenObserver", failures)
        observer_started = observer.get("started")
        if not isinstance(observer_started, bool):
            failures.append("authOpenObserver.started must be a boolean when present")
        if observer_started is True:
            pid = _as_int(observer.get("pid"), "authOpenObserver.pid", failures)
            if pid is not None and pid < 1:
                failures.append("authOpenObserver.pid must be positive when observer started")
            _as_non_empty_string(
                observer.get("runtimeSnapshotPath"),
                "authOpenObserver.runtimeSnapshotPath",
                failures,
            )
            _as_non_empty_string(observer.get("command"), "authOpenObserver.command", failures)
            stdout = _as_non_empty_string(observer.get("stdout"), "authOpenObserver.stdout", failures)
            stderr = _as_non_empty_string(observer.get("stderr"), "authOpenObserver.stderr", failures)
            if output_dir and stdout and not _is_within_directory(stdout, output_dir):
                failures.append("authOpenObserver.stdout must be inside outputDir")
            if output_dir and stderr and not _is_within_directory(stderr, output_dir):
                failures.append("authOpenObserver.stderr must be inside outputDir")

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
        "agentUrl": agent_url or None,
        "macosProviderHealth": macos_provider_health,
        "probeFile": probe_file or None,
        "targetHash": expected_hash if probe_file else None,
    }


def _write_json(path: pathlib.Path, payload: dict[str, Any]) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return str(path)


def _valid_summary(output_dir: pathlib.Path) -> dict[str, Any]:
    probe_file = "/tmp/clawdstrike-es-dogfood-20260519T010203Z/probe.txt"
    target_hash = "sha256:" + hashlib.sha256(probe_file.encode("utf-8")).hexdigest()
    graph_response = {
        "graph": {
            "nodes": {
                "node-download": {
                    "kind": "file",
                    "label": probe_file,
                    "attributes": {},
                }
            }
        }
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
                            "evidence": [
                                {"key": "target", "valueHash": target_hash},
                            ],
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
    return {
        "runId": "20260519T010203Z",
        "status": "passed",
        "outputDir": str(output_dir),
        "hostId": "qa-mac-1",
        "userId": "operator",
        "agentUrl": "http://127.0.0.1:9878",
        "agentHealth": _write_json(output_dir / "agent-health.json", agent_health),
        "probeFile": probe_file,
        "marker": "clawdstrike-es-dogfood-20260519T010203Z",
        "provider": provider,
        "protectionState": _write_json(output_dir / "protection-state.json", protection_state),
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
        "graphResponse": _write_json(output_dir / "causal-graph-attempt-1.json", graph_response),
        "receiptResponse": _write_json(
            output_dir / "observation-receipts-attempt-1.json",
            receipt_response,
        ),
        "probeActivityArtifact": _write_json(
            output_dir / "probe-activity.json",
            probe_activity,
        ),
        "syntheticEndpointSecurityPostUsed": False,
        "authOpenObserver": {"started": False},
    }


def run_self_test() -> int:
    temp_dir = tempfile.TemporaryDirectory(prefix="clawdstrike-es-dogfood-verify-")
    output_dir = pathlib.Path(temp_dir.name)

    valid = verify_summary(_valid_summary(output_dir))
    if not valid["verified"]:
        print(json.dumps(valid, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    provider_health = valid.get("macosProviderHealth") or {}
    if provider_health.get("provider") != "endpoint_security":
        print("self-test expected EndpointSecurity provider health snapshot", file=sys.stderr)
        return 1
    if provider_health.get("installState") != "installed" or provider_health.get("approval") != "approved":
        print("self-test expected installed and approved macOS provider health", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["runId"] = "not-a-run-id"
    invalid_summary["marker"] = "clawdstrike-es-dogfood-not-a-run-id"
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected malformed runId to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["syntheticEndpointSecurityPostUsed"] = True
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected synthetic summary to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["receiptMatch"]["matches"][0]["providerId"] = "agent.api"
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected wrong provider to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["probeFile"] = "relative/probe.txt"
    invalid_summary["match"]["probeFile"] = "relative/probe.txt"
    invalid_summary["receiptMatch"]["probeFile"] = "relative/probe.txt"
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected relative probe path to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["receiptResponse"] = str(output_dir / "missing-receipts.json")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected missing receipt artifact to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["protectionState"] = str(output_dir / "missing-protection-state.json")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected missing protection-state artifact to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    health_path = pathlib.Path(invalid_summary["agentHealth"])
    health_payload = json.loads(health_path.read_text(encoding="utf-8"))
    health_payload["macos_host"]["approval"] = "approval_blocked"
    health_path.write_text(json.dumps(health_payload), encoding="utf-8")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected blocked macOS approval to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    protection_path = pathlib.Path(invalid_summary["protectionState"])
    protection_payload = json.loads(protection_path.read_text(encoding="utf-8"))
    protection_payload["sensor_state"]["providers"][1]["active"] = False
    protection_path.write_text(json.dumps(protection_payload), encoding="utf-8")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected protection-state provider mismatch to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    probe_artifact = pathlib.Path(invalid_summary["probeActivityArtifact"])
    probe_payload = json.loads(probe_artifact.read_text(encoding="utf-8"))
    probe_payload["marker"] = "wrong-marker"
    probe_artifact.write_text(json.dumps(probe_payload), encoding="utf-8")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected mismatched probe artifact to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    probe_artifact = pathlib.Path(invalid_summary["probeActivityArtifact"])
    probe_payload = json.loads(probe_artifact.read_text(encoding="utf-8"))
    probe_payload["hostId"] = "other-host"
    probe_artifact.write_text(json.dumps(probe_payload), encoding="utf-8")
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected mismatched probe host artifact to fail", file=sys.stderr)
        return 1

    invalid_summary = _valid_summary(output_dir)
    invalid_summary["authOpenObserver"] = {
        "started": True,
        "pid": 42,
        "runtimeSnapshotPath": "/tmp/es-runtime.json",
        "stdout": "/tmp/outside-observer.stdout.json",
        "stderr": "/tmp/clawdstrike-es-dogfood-output/auth-open-observer.stderr.log",
        "command": "endpoint-security-status-tool observe-auth-open 120",
    }
    invalid = verify_summary(invalid_summary)
    if invalid["verified"]:
        print("self-test expected observer stdout outside outputDir to fail", file=sys.stderr)
        return 1

    observer_summary = _valid_summary(output_dir)
    _write_json(output_dir / "auth-open-observer.stdout.json", {"events": []})
    (output_dir / "auth-open-observer.stderr.log").write_text("", encoding="utf-8")
    observer_summary["authOpenObserver"] = {
        "started": True,
        "pid": 42,
        "runtimeSnapshotPath": "/tmp/es-runtime.json",
        "stdout": str(output_dir / "auth-open-observer.stdout.json"),
        "stderr": str(output_dir / "auth-open-observer.stderr.log"),
        "command": "endpoint-security-status-tool observe-auth-open 120",
    }
    observer_valid = verify_summary(observer_summary)
    if not observer_valid["verified"]:
        print(json.dumps(observer_valid, indent=2, sort_keys=True), file=sys.stderr)
        return 1

    print("endpoint-security live dogfood verifier self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("summary", nargs="?", help="Path to endpoint-security dogfood summary.json")
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
