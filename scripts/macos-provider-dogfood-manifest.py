#!/usr/bin/env python3
"""Write a hash manifest for macOS provider dogfood evidence bundles."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import pathlib
import plistlib
import shutil
import sys
import tempfile
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent


def _load_gate_module() -> Any:
    path = SCRIPT_DIR / "macos-provider-dogfood-gate.py"
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load gate module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _artifact(path: pathlib.Path, root: pathlib.Path) -> dict[str, Any]:
    resolved = path.resolve()
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
    return {
        "path": str(resolved),
        "relativePath": str(resolved.relative_to(root)),
        "sha256": f"sha256:{digest}",
        "bytes": resolved.stat().st_size,
    }


def _nonnegative_int(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def _reject_unsupported_fields(
    value: dict[str, Any],
    allowed: set[str],
    label: str,
    failures: list[str],
) -> None:
    unsupported_fields = sorted(set(value) - allowed)
    if unsupported_fields:
        failures.append(f"{label} contains unsupported fields: {', '.join(unsupported_fields)}")


def _require_nonnegative_int_field(
    value: dict[str, Any],
    field: str,
    label: str,
    failures: list[str],
) -> None:
    if _nonnegative_int(value.get(field)) is None:
        failures.append(f"{label}.{field} must be a non-negative integer")


def _require_optional_nonnegative_int_field(
    value: dict[str, Any],
    field: str,
    label: str,
    failures: list[str],
) -> None:
    if value.get(field) is not None and _nonnegative_int(value.get(field)) is None:
        failures.append(f"{label}.{field} must be null or a non-negative integer")


def _require_bool_field(
    value: dict[str, Any],
    field: str,
    label: str,
    failures: list[str],
) -> None:
    if not isinstance(value.get(field), bool):
        failures.append(f"{label}.{field} must be a boolean")


def _require_string_list_field(
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


GATE_RESULT_FIELDS = {
    "verified",
    "failureCount",
    "failures",
    "maxRunSkewSeconds",
    "runSkewSeconds",
    "deploymentEvidenceSummary",
    "endpointSecuritySummary",
    "networkExtensionSummary",
    "providerBindings",
    "deploymentEvidence",
    "endpointSecurity",
    "networkExtension",
}
GATE_PROVIDER_BINDINGS_FIELDS = {
    "deploymentExtensionPoints",
    "endpointSecurityProviderHealth",
    "networkExtensionProviderHealth",
}
GATE_PROVIDER_HEALTH_FIELDS = {
    "provider",
    "providerKey",
    "installState",
    "approval",
    "runtimeState",
    "installed",
    "active",
    "healthy",
    "availability",
    "approvalStatus",
    "degradedReasons",
    "lastHealthyTimestamp",
}
GATE_DEPLOYMENT_EVIDENCE_FIELDS = {
    "verified",
    "failureCount",
    "failures",
    "warnings",
    "runId",
    "hostId",
    "userId",
    "teamId",
    "appBundleId",
    "systemExtensionBundleId",
    "bundlePath",
    "systemExtensionPath",
    "extensionPoints",
    "systemExtensionStatusLine",
}
GATE_ENDPOINT_SECURITY_FIELDS = {
    "verified",
    "failureCount",
    "failures",
    "warnings",
    "runId",
    "hostId",
    "userId",
    "agentUrl",
    "macosProviderHealth",
    "outputDir",
    "probeFile",
    "targetHash",
}
GATE_NETWORK_EXTENSION_FIELDS = {
    "verified",
    "failureCount",
    "failures",
    "warnings",
    "runId",
    "hostId",
    "userId",
    "sessionId",
    "agentId",
    "workloadId",
    "approvalId",
    "agentUrl",
    "macosProviderHealth",
    "outputDir",
    "target",
    "targetHost",
    "targetPort",
    "executionId",
}
GATE_SECTION_FIELDS = {
    "deploymentEvidence": GATE_DEPLOYMENT_EVIDENCE_FIELDS,
    "endpointSecurity": GATE_ENDPOINT_SECURITY_FIELDS,
    "networkExtension": GATE_NETWORK_EXTENSION_FIELDS,
}


def _portable_inventory(files: list[dict[str, Any]]) -> list[dict[str, Any]]:
    portable: list[dict[str, Any]] = []
    for index, item in enumerate(files):
        if not isinstance(item, dict):
            portable.append({"relativePath": f"<invalid:{index}>", "sha256": "", "bytes": -1})
            continue
        byte_count = _nonnegative_int(item.get("bytes"))
        if byte_count is None:
            byte_count = -1
        portable.append(
            {
                "relativePath": str(item.get("relativePath", "")),
                "sha256": str(item.get("sha256", "")),
                "bytes": byte_count,
            }
        )
    return portable


def _inventory_hash(files: list[dict[str, Any]]) -> str:
    canonical = json.dumps(
        _portable_inventory(files),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _artifact_inventory(root: pathlib.Path, manifest_path: pathlib.Path) -> dict[str, Any]:
    root = root.resolve()
    manifest_path = manifest_path.resolve()
    files = [
        _artifact(path, root)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.resolve() != manifest_path
    ]
    return {
        "fileCount": len(files),
        "totalBytes": sum(int(item["bytes"]) for item in files),
        "sha256": _inventory_hash(files),
        "files": files,
    }


def _load_json_object(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _artifact_path_from_manifest(
    root: pathlib.Path,
    artifact: Any,
    label: str,
    failures: list[str],
) -> pathlib.Path | None:
    if not isinstance(artifact, dict):
        failures.append(f"artifacts.{label} must be an object")
        return None
    _reject_unsupported_fields(
        artifact,
        {"path", "relativePath", "sha256", "bytes"},
        f"artifacts.{label}",
        failures,
    )
    relative_path = artifact.get("relativePath")
    if not isinstance(relative_path, str) or not relative_path.strip():
        failures.append(f"artifacts.{label} must include relativePath")
        return None
    relative = pathlib.PurePath(relative_path)
    if relative.is_absolute():
        failures.append(f"artifacts.{label}.relativePath must be relative")
        return None
    resolved = (root / relative_path).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        failures.append(f"artifacts.{label}.relativePath must stay inside runRoot")
        return None
    return resolved



def _path_matches_manifest_artifact(
    value: Any,
    current_root: pathlib.Path,
    recorded_root: pathlib.Path | None,
    relative_path: str,
) -> bool:
    if not isinstance(value, str) or not value.strip() or not relative_path.strip():
        return False
    relative = pathlib.PurePath(relative_path)
    value_path = pathlib.Path(value)
    if not value_path.is_absolute():
        return pathlib.PurePath(value).parts == relative.parts
    resolved = value_path.expanduser().resolve()
    accepted = [(current_root / relative_path).resolve()]
    if recorded_root is not None:
        accepted.append((recorded_root / relative_path).resolve())
    return resolved in accepted


def _require_gate_artifact_binding(
    gate_payload: dict[str, Any],
    artifacts: dict[str, Any],
    current_root: pathlib.Path,
    recorded_root: pathlib.Path | None,
    failures: list[str],
) -> None:
    for field in (
        "deploymentEvidenceSummary",
        "endpointSecuritySummary",
        "networkExtensionSummary",
    ):
        artifact = artifacts.get(field)
        relative_path = artifact.get("relativePath") if isinstance(artifact, dict) else None
        if not isinstance(relative_path, str) or not relative_path.strip():
            failures.append(f"artifacts.{field}.relativePath is required before gate binding")
            continue
        if not _path_matches_manifest_artifact(
            gate_payload.get(field),
            current_root,
            recorded_root,
            relative_path,
        ):
            failures.append(f"gateResult.{field} must reference artifacts.{field}")


def _require_gate_provider_bindings(gate_payload: dict[str, Any], failures: list[str]) -> None:
    bindings = gate_payload.get("providerBindings")
    if not isinstance(bindings, dict):
        failures.append("gateResult.providerBindings must be an object")
        return
    extension_points = bindings.get("deploymentExtensionPoints")
    if not isinstance(extension_points, list):
        failures.append("gateResult.providerBindings.deploymentExtensionPoints must be a list")
        extension_points = []
    for extension_point in ("endpoint_security", "network_extension_content_filter"):
        if extension_point not in extension_points:
            failures.append(
                "gateResult.providerBindings.deploymentExtensionPoints must include "
                f"{extension_point}"
            )
    provider_expectations = {
        "endpointSecurityProviderHealth": "endpoint_security",
        "networkExtensionProviderHealth": "network_extension",
    }
    for field, provider in provider_expectations.items():
        health = bindings.get(field)
        if not isinstance(health, dict):
            failures.append(f"gateResult.providerBindings.{field} must be an object")
            continue
        if health.get("provider") != provider:
            failures.append(f"gateResult.providerBindings.{field}.provider must be {provider}")


def _reject_unsupported_gate_fields(gate_payload: dict[str, Any], failures: list[str]) -> None:
    _reject_unsupported_fields(gate_payload, GATE_RESULT_FIELDS, "gateResult", failures)
    _require_nonnegative_int_field(gate_payload, "failureCount", "gateResult", failures)
    _require_nonnegative_int_field(gate_payload, "maxRunSkewSeconds", "gateResult", failures)
    _require_optional_nonnegative_int_field(gate_payload, "runSkewSeconds", "gateResult", failures)
    bindings = gate_payload.get("providerBindings")
    if isinstance(bindings, dict):
        _reject_unsupported_fields(
            bindings,
            GATE_PROVIDER_BINDINGS_FIELDS,
            "gateResult.providerBindings",
            failures,
        )
        _require_string_list_field(
            bindings,
            "deploymentExtensionPoints",
            "gateResult.providerBindings",
            failures,
        )
        for field in ("endpointSecurityProviderHealth", "networkExtensionProviderHealth"):
            health = bindings.get(field)
            if isinstance(health, dict):
                _reject_unsupported_fields(
                    health,
                    GATE_PROVIDER_HEALTH_FIELDS,
                    f"gateResult.providerBindings.{field}",
                    failures,
                )
                _require_bool_field(
                    health,
                    "installed",
                    f"gateResult.providerBindings.{field}",
                    failures,
                )
                _require_bool_field(
                    health,
                    "active",
                    f"gateResult.providerBindings.{field}",
                    failures,
                )
                _require_bool_field(
                    health,
                    "healthy",
                    f"gateResult.providerBindings.{field}",
                    failures,
                )
    for section, allowed_fields in GATE_SECTION_FIELDS.items():
        result = gate_payload.get(section)
        if not isinstance(result, dict):
            continue
        _reject_unsupported_fields(result, allowed_fields, f"gateResult.{section}", failures)
        _require_bool_field(result, "verified", f"gateResult.{section}", failures)
        _require_nonnegative_int_field(result, "failureCount", f"gateResult.{section}", failures)
        if section == "deploymentEvidence":
            _require_string_list_field(result, "extensionPoints", f"gateResult.{section}", failures)
        if section == "networkExtension":
            _require_nonnegative_int_field(result, "targetPort", f"gateResult.{section}", failures)
        health = result.get("macosProviderHealth")
        if isinstance(health, dict):
            _reject_unsupported_fields(
                health,
                GATE_PROVIDER_HEALTH_FIELDS,
                f"gateResult.{section}.macosProviderHealth",
                failures,
            )
            _require_bool_field(
                health,
                "installed",
                f"gateResult.{section}.macosProviderHealth",
                failures,
            )
            _require_bool_field(
                health,
                "active",
                f"gateResult.{section}.macosProviderHealth",
                failures,
            )
            _require_bool_field(
                health,
                "healthy",
                f"gateResult.{section}.macosProviderHealth",
                failures,
            )


def _project_fields(source: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(source, dict):
        return {}
    return {field: source.get(field) for field in fields}


def _gate_portable_projection(gate_payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "verified": gate_payload.get("verified"),
        "failureCount": gate_payload.get("failureCount"),
        "failures": gate_payload.get("failures"),
        "maxRunSkewSeconds": gate_payload.get("maxRunSkewSeconds"),
        "runSkewSeconds": gate_payload.get("runSkewSeconds"),
        "providerBindings": gate_payload.get("providerBindings"),
        "deploymentEvidence": _project_fields(
            gate_payload.get("deploymentEvidence"),
            (
                "verified",
                "failureCount",
                "failures",
                "warnings",
                "runId",
                "hostId",
                "userId",
                "teamId",
                "appBundleId",
                "systemExtensionBundleId",
                "bundlePath",
                "systemExtensionPath",
                "extensionPoints",
                "systemExtensionStatusLine",
            ),
        ),
        "endpointSecurity": _project_fields(
            gate_payload.get("endpointSecurity"),
            (
                "verified",
                "failureCount",
                "failures",
                "warnings",
                "runId",
                "hostId",
                "userId",
                "agentUrl",
                "macosProviderHealth",
                "probeFile",
                "targetHash",
            ),
        ),
        "networkExtension": _project_fields(
            gate_payload.get("networkExtension"),
            (
                "verified",
                "failureCount",
                "failures",
                "warnings",
                "runId",
                "hostId",
                "userId",
                "sessionId",
                "agentId",
                "workloadId",
                "approvalId",
                "agentUrl",
                "macosProviderHealth",
                "target",
                "targetHost",
                "targetPort",
                "executionId",
            ),
        ),
    }


def verify_manifest(manifest_path: pathlib.Path) -> dict[str, Any]:
    failures: list[str] = []
    warnings: list[str] = []
    manifest_path = manifest_path.resolve()
    try:
        manifest = _load_json_object(manifest_path)
    except Exception as exc:  # noqa: BLE001 - verification output should preserve parse failure.
        return {
            "verified": False,
            "failureCount": 1,
            "failures": [f"manifest must be a JSON object: {exc}"],
            "warnings": [],
        }

    root = manifest_path.parent.resolve()
    _reject_unsupported_fields(
        manifest,
        {
            "schemaVersion",
            "runId",
            "generatedAt",
            "runRoot",
            "target",
            "evidenceMode",
            "hostId",
            "userId",
            "maxRunSkewSeconds",
            "artifacts",
            "artifactInventory",
        },
        "manifest",
        failures,
    )
    if manifest.get("schemaVersion") != 1 or isinstance(manifest.get("schemaVersion"), bool):
        failures.append("schemaVersion must be 1")
    if not isinstance(manifest.get("generatedAt"), str) or not manifest["generatedAt"].strip():
        failures.append("generatedAt must be a non-empty string")
    if manifest.get("evidenceMode") not in {"live", "fixture"}:
        failures.append("evidenceMode must be live or fixture")
    if not isinstance(manifest.get("runId"), str) or not manifest["runId"].strip():
        failures.append("runId must be a non-empty string")
    recorded_root = manifest.get("runRoot")
    recorded_root_path = None
    if not isinstance(recorded_root, str) or not recorded_root.strip():
        failures.append("runRoot must be a non-empty string")
    else:
        recorded_root_candidate = pathlib.Path(recorded_root).expanduser()
        if not recorded_root_candidate.is_absolute():
            failures.append("runRoot must be an absolute path")
        else:
            recorded_root_path = recorded_root_candidate.resolve()
            if recorded_root_path != root:
                warnings.append("manifest was verified from a different runRoot path than recorded")
    for field in ("target", "hostId", "userId"):
        if not isinstance(manifest.get(field), str) or not manifest[field].strip():
            failures.append(f"{field} must be a non-empty string")

    artifacts = manifest.get("artifacts")
    expected_artifact_names = {
        "deploymentEvidenceSummary",
        "endpointSecuritySummary",
        "networkExtensionSummary",
        "gateResult",
    }
    if not isinstance(artifacts, dict):
        failures.append("artifacts must be an object")
        artifacts = {}
    else:
        _reject_unsupported_fields(artifacts, expected_artifact_names, "artifacts", failures)
    max_run_skew_seconds = manifest.get("maxRunSkewSeconds")
    if not isinstance(max_run_skew_seconds, int) or isinstance(max_run_skew_seconds, bool):
        failures.append("maxRunSkewSeconds must be an integer")
        max_run_skew_seconds = 0
    current_inventory = _artifact_inventory(root, manifest_path)
    expected_inventory = manifest.get("artifactInventory")
    if not isinstance(expected_inventory, dict):
        failures.append("artifactInventory must be an object")
        expected_inventory = {}
    else:
        _reject_unsupported_fields(
            expected_inventory,
            {"fileCount", "totalBytes", "sha256", "files"},
            "artifactInventory",
            failures,
        )
    expected_file_count = expected_inventory.get("fileCount")
    if _nonnegative_int(expected_file_count) is None:
        failures.append("artifactInventory.fileCount must be a non-negative integer")
    elif expected_file_count != current_inventory["fileCount"]:
        failures.append("artifactInventory.fileCount does not match current files")
    expected_total_bytes = expected_inventory.get("totalBytes")
    if _nonnegative_int(expected_total_bytes) is None:
        failures.append("artifactInventory.totalBytes must be a non-negative integer")
    elif expected_total_bytes != current_inventory["totalBytes"]:
        failures.append("artifactInventory.totalBytes does not match current files")
    if expected_inventory.get("sha256") != current_inventory["sha256"]:
        failures.append("artifactInventory.sha256 does not match current files")
    expected_files = expected_inventory.get("files")
    if not isinstance(expected_files, list):
        failures.append("artifactInventory.files must be a list")
        expected_files = []
    for index, item in enumerate(expected_files):
        if not isinstance(item, dict):
            failures.append(f"artifactInventory.files[{index}] must be an object")
            continue
        _reject_unsupported_fields(
            item,
            {"path", "relativePath", "sha256", "bytes"},
            f"artifactInventory.files[{index}]",
            failures,
        )
        item_bytes = item.get("bytes")
        if _nonnegative_int(item_bytes) is None:
            failures.append(f"artifactInventory.files[{index}].bytes must be a non-negative integer")
    if _portable_inventory(expected_files) != _portable_inventory(current_inventory["files"]):
        failures.append("artifactInventory.files do not match current files")

    selected_paths: dict[str, pathlib.Path] = {}
    for name in sorted(expected_artifact_names):
        artifact = artifacts.get(name)
        path = _artifact_path_from_manifest(root, artifact, name, failures)
        if path is None:
            continue
        if not path.is_file():
            failures.append(f"artifacts.{name} file is missing")
            continue
        selected_paths[name] = path
        current = _artifact(path, root)
        for field in ("relativePath", "sha256"):
            if artifact.get(field) != current[field]:
                failures.append(f"artifacts.{name}.{field} does not match current file")
        artifact_bytes = artifact.get("bytes")
        if _nonnegative_int(artifact_bytes) is None:
            failures.append(f"artifacts.{name}.bytes must be a non-negative integer")
        elif artifact_bytes != current["bytes"]:
            failures.append(f"artifacts.{name}.bytes does not match current file")

    gate_path = selected_paths.get("gateResult")
    fresh_gate_verified: bool | None = None
    gate_payload: dict[str, Any] | None = None
    if gate_path is not None and gate_path.is_file():
        try:
            gate_payload = _load_json_object(gate_path)
            _reject_unsupported_gate_fields(gate_payload, failures)
            if gate_payload.get("verified") is not True:
                failures.append("gateResult.verified must be true")
            if gate_payload.get("maxRunSkewSeconds") != max_run_skew_seconds:
                failures.append("gateResult.maxRunSkewSeconds must match manifest maxRunSkewSeconds")
            _require_gate_artifact_binding(
                gate_payload,
                artifacts,
                root,
                recorded_root_path,
                failures,
            )
            _require_gate_provider_bindings(gate_payload, failures)
            for section in ("deploymentEvidence", "endpointSecurity", "networkExtension"):
                result = gate_payload.get(section)
                if not isinstance(result, dict):
                    failures.append(f"gateResult.{section} must be an object")
                    continue
                for field in ("hostId", "userId"):
                    if result.get(field) != manifest.get(field):
                        failures.append(f"gateResult.{section}.{field} must match manifest {field}")
            deployment_result = gate_payload.get("deploymentEvidence")
            if isinstance(deployment_result, dict) and deployment_result.get("runId") != manifest.get("runId"):
                failures.append("gateResult.deploymentEvidence.runId must match manifest runId")
            es_result = gate_payload.get("endpointSecurity")
            if isinstance(es_result, dict) and es_result.get("runId") != manifest.get("runId"):
                failures.append("gateResult.endpointSecurity.runId must match manifest runId")
            ne_result = gate_payload.get("networkExtension")
            if isinstance(ne_result, dict) and ne_result.get("runId") != manifest.get("runId"):
                failures.append("gateResult.networkExtension.runId must match manifest runId")
            network_result = gate_payload.get("networkExtension")
            if isinstance(network_result, dict) and network_result.get("target") != manifest.get("target"):
                failures.append("gateResult.networkExtension.target must match manifest target")
        except Exception as exc:  # noqa: BLE001 - preserve parse failure in verifier output.
            failures.append(f"gateResult must be valid JSON: {exc}")

    deployment_summary_path = selected_paths.get("deploymentEvidenceSummary")
    es_summary_path = selected_paths.get("endpointSecuritySummary")
    ne_summary_path = selected_paths.get("networkExtensionSummary")
    if deployment_summary_path is not None and es_summary_path is not None and ne_summary_path is not None:
        try:
            gate_module = _load_gate_module()
            fresh_gate = gate_module.gate_artifacts(
                es_summary_path,
                ne_summary_path,
                deployment_summary_path,
                max_run_skew_seconds=max_run_skew_seconds,
            )
            fresh_gate_verified = fresh_gate.get("verified") is True
            if not fresh_gate_verified:
                failures.append("fresh gate verification failed")
            elif gate_payload is not None and _gate_portable_projection(
                gate_payload
            ) != _gate_portable_projection(fresh_gate):
                failures.append("gateResult portable projection must match fresh gate verification")
        except Exception as exc:  # noqa: BLE001 - preserve gate failure in verifier output.
            failures.append(f"fresh gate verification failed: {exc}")

    return {
        "verified": not failures,
        "failureCount": len(failures),
        "failures": failures,
        "warnings": warnings,
        "runId": manifest.get("runId"),
        "runRoot": str(root),
        "fileCount": current_inventory["fileCount"],
        "totalBytes": current_inventory["totalBytes"],
        "inventorySha256": current_inventory["sha256"],
        "freshGateVerified": fresh_gate_verified,
    }


def write_manifest(
    manifest_path: pathlib.Path,
    run_id: str,
    run_root: pathlib.Path,
    target: str,
    host_id: str,
    user_id: str,
    deployment_evidence_summary: pathlib.Path,
    endpoint_security_summary: pathlib.Path,
    network_extension_summary: pathlib.Path,
    gate_result: pathlib.Path,
    max_run_skew_seconds: int,
    evidence_mode: str = "live",
) -> dict[str, Any]:
    run_root = run_root.resolve()
    manifest_path = manifest_path.resolve()
    if max_run_skew_seconds < 0:
        raise ValueError("max_run_skew_seconds must be non-negative")
    if evidence_mode not in {"live", "fixture"}:
        raise ValueError("evidence_mode must be live or fixture")
    for path in (deployment_evidence_summary, endpoint_security_summary, network_extension_summary, gate_result):
        resolved = path.resolve()
        if not resolved.is_file():
            raise FileNotFoundError(str(resolved))
        resolved.relative_to(run_root)

    manifest = {
        "schemaVersion": 1,
        "runId": run_id,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "runRoot": str(run_root),
        "target": target,
        "evidenceMode": evidence_mode,
        "hostId": host_id,
        "userId": user_id,
        "maxRunSkewSeconds": max_run_skew_seconds,
        "artifacts": {
            "deploymentEvidenceSummary": _artifact(deployment_evidence_summary, run_root),
            "endpointSecuritySummary": _artifact(endpoint_security_summary, run_root),
            "networkExtensionSummary": _artifact(network_extension_summary, run_root),
            "gateResult": _artifact(gate_result, run_root),
        },
        "artifactInventory": _artifact_inventory(run_root, manifest_path),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-macos-provider-manifest-") as temp_dir:
        root = pathlib.Path(temp_dir)
        gate_module = _load_gate_module()
        deployment_output_dir = root / "deployment-evidence"
        es_output_dir = root / "endpoint-security"
        ne_output_dir = root / "network-extension"
        deployment_summary = deployment_output_dir / "summary.json"
        es_summary = es_output_dir / "summary.json"
        ne_summary = ne_output_dir / "summary.json"
        gate_result = root / "gate-result.json"
        deployment_summary.write_text(
            json.dumps(gate_module.fixture_deployment_evidence_summary(deployment_output_dir)),
            encoding="utf-8",
        )
        es_summary.write_text(
            json.dumps(gate_module.fixture_endpoint_security_summary(es_output_dir)),
            encoding="utf-8",
        )
        ne_summary.write_text(
            json.dumps(gate_module.fixture_network_extension_summary(ne_output_dir)),
            encoding="utf-8",
        )
        gate_payload = gate_module.gate_artifacts(es_summary, ne_summary, deployment_summary)
        gate_result.write_text(json.dumps(gate_payload), encoding="utf-8")
        deployment_extra = deployment_output_dir / "codesign-verify.json"
        extra = ne_output_dir / "proof-response.json"
        manifest_path = root / "manifest.json"
        manifest = write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        if not manifest_path.is_file():
            print("self-test expected manifest file", file=sys.stderr)
            return 1
        inventory = manifest["artifactInventory"]
        if inventory["fileCount"] < 12:
            print(json.dumps(manifest, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        paths = {item["relativePath"] for item in inventory["files"]}
        if (
            "manifest.json" in paths
            or "deployment-evidence/systemextensionsctl-list.json" not in paths
            or "endpoint-security/probe-activity.json" not in paths
            or "network-extension/proof-response.json" not in paths
        ):
            print(json.dumps(manifest, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        verified = verify_manifest(manifest_path)
        if verified["verified"] is not True:
            print(json.dumps(verified, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["schemaVersion"] = True
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        if invalid["verified"] is True or "schemaVersion must be 1" not in invalid["failures"]:
            print("self-test expected boolean manifest schemaVersion to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )

        manifest_payload = _load_json_object(manifest_path)
        manifest_payload.pop("runRoot", None)
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        if invalid["verified"] is True or "runRoot must be a non-empty string" not in invalid["failures"]:
            print("self-test expected missing manifest runRoot to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["runRoot"] = "relative-output-root"
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        if invalid["verified"] is True or "runRoot must be an absolute path" not in invalid["failures"]:
            print("self-test expected relative manifest runRoot to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )

        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["operatorNote"] = "unverified"
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        hidden_manifest_failure = "manifest contains unsupported fields: operatorNote"
        if invalid["verified"] is True or hidden_manifest_failure not in invalid["failures"]:
            print("self-test expected hidden manifest field to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["artifacts"]["endpointSecuritySummary"]["sourcePath"] = str(es_summary)
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        artifact_hidden_failure = (
            "artifacts.endpointSecuritySummary contains unsupported fields: sourcePath"
        )
        if invalid["verified"] is True or artifact_hidden_failure not in invalid["failures"]:
            print("self-test expected hidden selected artifact field to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["artifactInventory"]["sourcePath"] = str(root)
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        inventory_hidden_failure = "artifactInventory contains unsupported fields: sourcePath"
        if invalid["verified"] is True or inventory_hidden_failure not in invalid["failures"]:
            print("self-test expected hidden inventory field to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["artifactInventory"]["files"][0]["sourcePath"] = str(root)
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        file_hidden_failure = "artifactInventory.files[0] contains unsupported fields: sourcePath"
        if invalid["verified"] is True or file_hidden_failure not in invalid["failures"]:
            print("self-test expected hidden inventory file field to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["artifactInventory"]["fileCount"] = True
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        file_count_failure = "artifactInventory.fileCount must be a non-negative integer"
        if invalid["verified"] is True or file_count_failure not in invalid["failures"]:
            print("self-test expected boolean inventory fileCount to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["artifactInventory"]["files"][0]["bytes"] = True
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        inventory_bytes_failure = "artifactInventory.files do not match current files"
        if invalid["verified"] is True or inventory_bytes_failure not in invalid["failures"]:
            print("self-test expected boolean inventory file bytes to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["artifacts"]["endpointSecuritySummary"]["bytes"] = True
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        artifact_bytes_failure = "artifacts.endpointSecuritySummary.bytes must be a non-negative integer"
        if invalid["verified"] is True or artifact_bytes_failure not in invalid["failures"]:
            print("self-test expected boolean selected artifact bytes to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["artifacts"]["endpointSecuritySummary"]["relativePath"] = (
            "../outside-endpoint-security-summary.json"
        )
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        outside_path_failure = (
            "artifacts.endpointSecuritySummary.relativePath must stay inside runRoot"
        )
        if invalid["verified"] is True or outside_path_failure not in invalid["failures"]:
            print("self-test expected artifact relativePath escape to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )

        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["target"] = "example.org:443"
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        target_failure = "gateResult.networkExtension.target must match manifest target"
        if invalid["verified"] is True or target_failure not in invalid["failures"]:
            print("self-test expected edited manifest target to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["target"] = "example.com:443"
        manifest_payload["runId"] = "20260519T010204Z"
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        run_id_failure = "gateResult.deploymentEvidence.runId must match manifest runId"
        if invalid["verified"] is True or run_id_failure not in invalid["failures"]:
            print("self-test expected edited manifest runId to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        manifest_payload = _load_json_object(manifest_path)
        manifest_payload["runId"] = "20260519T010203Z"
        manifest_path.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        es_drifted_gate = json.loads(json.dumps(gate_payload))
        es_drifted_gate["endpointSecurity"]["runId"] = "20260519T010204Z"
        gate_result.write_text(json.dumps(es_drifted_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        es_run_id_failure = "gateResult.endpointSecurity.runId must match manifest runId"
        if invalid["verified"] is True or es_run_id_failure not in invalid["failures"]:
            print("self-test expected saved gate ES runId drift to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        gate_result.write_text(json.dumps(gate_payload), encoding="utf-8")

        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )

        stale_gate = dict(gate_payload)
        stale_gate["endpointSecuritySummary"] = str(
            root / "other-run" / "endpoint-security" / "summary.json"
        )
        gate_result.write_text(json.dumps(stale_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        expected_failure = (
            "gateResult.endpointSecuritySummary must reference "
            "artifacts.endpointSecuritySummary"
        )
        if invalid["verified"] is True or expected_failure not in invalid["failures"]:
            print("self-test expected stale saved gate summary path to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        missing_bindings_gate = dict(gate_payload)
        missing_bindings_gate.pop("providerBindings", None)
        gate_result.write_text(json.dumps(missing_bindings_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        if invalid["verified"] is True or "gateResult.providerBindings must be an object" not in invalid["failures"]:
            print("self-test expected missing saved gate provider bindings to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        hidden_gate = json.loads(json.dumps(gate_payload))
        hidden_gate["operatorNote"] = "unverified"
        gate_result.write_text(json.dumps(hidden_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        hidden_gate_failure = "gateResult contains unsupported fields: operatorNote"
        if invalid["verified"] is True or hidden_gate_failure not in invalid["failures"]:
            print("self-test expected hidden saved gate field to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        hidden_gate = json.loads(json.dumps(gate_payload))
        hidden_gate["endpointSecurity"]["sourcePath"] = str(es_summary)
        gate_result.write_text(json.dumps(hidden_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        hidden_gate_section_failure = (
            "gateResult.endpointSecurity contains unsupported fields: sourcePath"
        )
        if invalid["verified"] is True or hidden_gate_section_failure not in invalid["failures"]:
            print("self-test expected hidden saved gate section field to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        hidden_gate = json.loads(json.dumps(gate_payload))
        hidden_gate["providerBindings"]["sourcePath"] = str(root)
        gate_result.write_text(json.dumps(hidden_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        hidden_gate_bindings_failure = (
            "gateResult.providerBindings contains unsupported fields: sourcePath"
        )
        if invalid["verified"] is True or hidden_gate_bindings_failure not in invalid["failures"]:
            print("self-test expected hidden saved gate bindings field to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        hidden_gate = json.loads(json.dumps(gate_payload))
        hidden_gate["providerBindings"]["endpointSecurityProviderHealth"]["sourcePath"] = str(root)
        gate_result.write_text(json.dumps(hidden_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        hidden_gate_provider_health_failure = (
            "gateResult.providerBindings.endpointSecurityProviderHealth "
            "contains unsupported fields: sourcePath"
        )
        if (
            invalid["verified"] is True
            or hidden_gate_provider_health_failure not in invalid["failures"]
        ):
            print("self-test expected hidden saved gate provider health field to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        hidden_gate = json.loads(json.dumps(gate_payload))
        hidden_gate["networkExtension"]["macosProviderHealth"]["sourcePath"] = str(root)
        gate_result.write_text(json.dumps(hidden_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        hidden_gate_section_health_failure = (
            "gateResult.networkExtension.macosProviderHealth "
            "contains unsupported fields: sourcePath"
        )
        if (
            invalid["verified"] is True
            or hidden_gate_section_health_failure not in invalid["failures"]
        ):
            print("self-test expected hidden saved gate section health field to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bool_gate = json.loads(json.dumps(gate_payload))
        bool_gate["failureCount"] = False
        gate_result.write_text(json.dumps(bool_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        bool_gate_failure = "gateResult.failureCount must be a non-negative integer"
        if invalid["verified"] is True or bool_gate_failure not in invalid["failures"]:
            print("self-test expected boolean saved gate failureCount to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bool_gate = json.loads(json.dumps(gate_payload))
        bool_gate["runSkewSeconds"] = False
        gate_result.write_text(json.dumps(bool_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        bool_gate_skew_failure = "gateResult.runSkewSeconds must be null or a non-negative integer"
        if invalid["verified"] is True or bool_gate_skew_failure not in invalid["failures"]:
            print("self-test expected boolean saved gate runSkewSeconds to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bool_gate = json.loads(json.dumps(gate_payload))
        bool_gate["endpointSecurity"]["failureCount"] = False
        gate_result.write_text(json.dumps(bool_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        bool_gate_section_failure = (
            "gateResult.endpointSecurity.failureCount must be a non-negative integer"
        )
        if invalid["verified"] is True or bool_gate_section_failure not in invalid["failures"]:
            print("self-test expected boolean saved gate section failureCount to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bool_gate = json.loads(json.dumps(gate_payload))
        bool_gate["endpointSecurity"]["verified"] = 1
        gate_result.write_text(json.dumps(bool_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        bool_gate_section_verified_failure = (
            "gateResult.endpointSecurity.verified must be a boolean"
        )
        if (
            invalid["verified"] is True
            or bool_gate_section_verified_failure not in invalid["failures"]
        ):
            print("self-test expected numeric saved gate section verified to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        typed_gate = json.loads(json.dumps(gate_payload))
        typed_gate["providerBindings"]["deploymentExtensionPoints"].append(1)
        gate_result.write_text(json.dumps(typed_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        typed_gate_bindings_failure = (
            "gateResult.providerBindings.deploymentExtensionPoints[2] must be a string"
        )
        if invalid["verified"] is True or typed_gate_bindings_failure not in invalid["failures"]:
            print("self-test expected non-string saved gate binding extension point to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        typed_gate = json.loads(json.dumps(gate_payload))
        typed_gate["deploymentEvidence"]["extensionPoints"].append(1)
        gate_result.write_text(json.dumps(typed_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        typed_gate_section_list_failure = (
            "gateResult.deploymentEvidence.extensionPoints[2] must be a string"
        )
        if invalid["verified"] is True or typed_gate_section_list_failure not in invalid["failures"]:
            print("self-test expected non-string saved gate section extension point to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bool_gate = json.loads(json.dumps(gate_payload))
        bool_gate["providerBindings"]["endpointSecurityProviderHealth"]["active"] = 1
        gate_result.write_text(json.dumps(bool_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        bool_gate_provider_health_failure = (
            "gateResult.providerBindings.endpointSecurityProviderHealth.active must be a boolean"
        )
        if (
            invalid["verified"] is True
            or bool_gate_provider_health_failure not in invalid["failures"]
        ):
            print("self-test expected numeric saved gate provider-health active to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bool_gate = json.loads(json.dumps(gate_payload))
        bool_gate["networkExtension"]["macosProviderHealth"]["healthy"] = 1
        gate_result.write_text(json.dumps(bool_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        bool_gate_section_health_failure = (
            "gateResult.networkExtension.macosProviderHealth.healthy must be a boolean"
        )
        if (
            invalid["verified"] is True
            or bool_gate_section_health_failure not in invalid["failures"]
        ):
            print("self-test expected numeric saved gate section health to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        drifted_gate = json.loads(json.dumps(gate_payload))
        drifted_gate["networkExtension"]["targetPort"] = 8443
        gate_result.write_text(json.dumps(drifted_gate), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        projection_failure = "gateResult portable projection must match fresh gate verification"
        if invalid["verified"] is True or projection_failure not in invalid["failures"]:
            print("self-test expected drifted saved gate projection to fail", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        gate_result.write_text(json.dumps(gate_payload), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        relocated_root = root.parent / f"{root.name}-relocated"
        shutil.copytree(root, relocated_root)
        relocated = verify_manifest(relocated_root / "manifest.json")
        if relocated["verified"] is not True:
            print(json.dumps(relocated, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if "manifest was verified from a different runRoot path than recorded" not in relocated["warnings"]:
            print(json.dumps(relocated, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        shutil.rmtree(relocated_root)
        extra.write_text(json.dumps({"liveEnforcementProven": False}), encoding="utf-8")
        invalid = verify_manifest(manifest_path)
        if invalid["verified"] is True:
            print("self-test expected artifact mutation to fail verification", file=sys.stderr)
            return 1
        ne_summary.write_text(
            json.dumps(gate_module.fixture_network_extension_summary(ne_output_dir)),
            encoding="utf-8",
        )
        deployment_extra.write_text(
            json.dumps(
                {
                    "argv": ["codesign", "--verify", str("/Applications/ClawdStrike Agent.app")],
                    "exitCode": 0,
                    "stdout": "",
                    "stderr": "valid on disk\n",
                }
            ),
            encoding="utf-8",
        )
        invalid = verify_manifest(manifest_path)
        if invalid["verified"] is True:
            print("self-test expected deployment evidence mutation to fail verification", file=sys.stderr)
            return 1
        deployment_summary.write_text(
            json.dumps(gate_module.fixture_deployment_evidence_summary(deployment_output_dir)),
            encoding="utf-8",
        )
        gate_result.write_text(
            json.dumps(gate_module.gate_artifacts(es_summary, ne_summary, deployment_summary)),
            encoding="utf-8",
        )
        entitlement_artifact = deployment_output_dir / "system-extension-entitlements.json"
        entitlement_payload = json.loads(entitlement_artifact.read_text(encoding="utf-8"))
        entitlement_payload["stdout"] = plistlib.dumps(
            {
                "com.apple.developer.endpoint-security.client": True,
                "com.apple.developer.networking.networkextension": [],
            }
        ).decode("utf-8")
        entitlement_artifact.write_text(json.dumps(entitlement_payload), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010203Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        if invalid["verified"] is True or "fresh gate verification failed" not in invalid["failures"]:
            print("self-test expected fresh gate to reject mutated deployment entitlements", file=sys.stderr)
            print(json.dumps(invalid, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        deployment_summary.write_text(
            json.dumps(gate_module.fixture_deployment_evidence_summary(deployment_output_dir)),
            encoding="utf-8",
        )
        ne_summary.write_text(
            json.dumps(gate_module.fixture_network_extension_summary(ne_output_dir)),
            encoding="utf-8",
        )
        gate_result.write_text(
            json.dumps(gate_module.gate_artifacts(es_summary, ne_summary, deployment_summary)),
            encoding="utf-8",
        )
        gate_result.write_text(json.dumps({"verified": False}), encoding="utf-8")
        write_manifest(
            manifest_path=manifest_path,
            run_id="20260519T010204Z",
            run_root=root,
            target="example.com:443",
            host_id="qa-mac-1",
            user_id="operator",
            deployment_evidence_summary=deployment_summary,
            endpoint_security_summary=es_summary,
            network_extension_summary=ne_summary,
            gate_result=gate_result,
            max_run_skew_seconds=3600,
        )
        invalid = verify_manifest(manifest_path)
        if invalid["verified"] is True:
            print("self-test expected unverified gate result to fail", file=sys.stderr)
            return 1
    print("macos provider dogfood manifest self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--run-id")
    parser.add_argument("--run-root", type=pathlib.Path)
    parser.add_argument("--target")
    parser.add_argument("--host-id")
    parser.add_argument("--user-id")
    parser.add_argument("--deployment-evidence-summary", type=pathlib.Path)
    parser.add_argument("--endpoint-security-summary", type=pathlib.Path)
    parser.add_argument("--network-extension-summary", type=pathlib.Path)
    parser.add_argument("--gate-result", type=pathlib.Path)
    parser.add_argument("--max-run-skew-seconds", type=int)
    parser.add_argument("--evidence-mode", choices=("live", "fixture"), default="live")
    parser.add_argument("--verify", action="store_true", help="Verify an existing manifest")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    if args.verify:
        if args.manifest is None:
            parser.error("--manifest is required with --verify")
        result = verify_manifest(args.manifest)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["verified"] else 1

    required = [
        "manifest",
        "run_id",
        "run_root",
        "target",
        "host_id",
        "user_id",
        "deployment_evidence_summary",
        "endpoint_security_summary",
        "network_extension_summary",
        "gate_result",
        "max_run_skew_seconds",
    ]
    missing = [name.replace("_", "-") for name in required if getattr(args, name) is None]
    if missing:
        parser.error("missing required arguments: " + ", ".join(f"--{name}" for name in missing))

    write_manifest(
        manifest_path=args.manifest,
        run_id=args.run_id,
        run_root=args.run_root,
        target=args.target,
        host_id=args.host_id,
        user_id=args.user_id,
        deployment_evidence_summary=args.deployment_evidence_summary,
        endpoint_security_summary=args.endpoint_security_summary,
        network_extension_summary=args.network_extension_summary,
        gate_result=args.gate_result,
        max_run_skew_seconds=args.max_run_skew_seconds,
        evidence_mode=args.evidence_mode,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
