#!/usr/bin/env python3
"""Verify one Endpoint Decision Engine qualification evidence bundle."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import shutil
import sys
import tempfile
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
READINESS_AUDIT = SCRIPT_DIR / "endpoint-decision-engine-readiness-audit.py"
MAX_METADATA_ENTRIES = 16
MAX_METADATA_KEY_BYTES = 64
MAX_METADATA_VALUE_BYTES = 512
SOURCE_MANIFEST_NAME = "supplemental-proof-source-manifest.json"
SOURCE_MANIFEST_KIND = "clawdstrike.endpoint_decision_engine.supplemental_proof_source_manifest.v1"
SUMMARY_HASH_FIELD = "qualificationSummarySha256"
SUMMARY_FIELDS = {
    "schemaVersion",
    "bundleDir",
    "manifestPath",
    "auditPath",
    "ready",
    "counts",
    "auditSha256",
    "qualificationMetadata",
    "externalEvidenceAllowed",
    "externalEvidence",
    "externalOutputAllowed",
    "externalOutput",
    "supplementalSourceManifest",
    "proofs",
    "missingProofs",
    "unresolved",
    "failed",
    "persistedAuditVerified",
    "sourceReverified",
    "persistedAuditVerification",
    SUMMARY_HASH_FIELD,
}
SOURCE_MANIFEST_SUMMARY_FIELDS = {
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
    "policy",
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


def load_audit_module() -> Any:
    spec = importlib.util.spec_from_file_location("ede_readiness_audit", READINESS_AUDIT)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load readiness audit module: {READINESS_AUDIT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except OSError as exc:
        raise ValueError(f"{path} is not readable: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def write_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def file_record(path: pathlib.Path, display_path: pathlib.Path | str | None = None) -> dict[str, Any]:
    stat = path.stat()
    return {
        "path": str(display_path if display_path is not None else path),
        "sha256": file_sha256(path),
        "byteSize": stat.st_size,
    }


def qualification_summary_sha256(summary: dict[str, Any]) -> str:
    payload = dict(summary)
    payload.pop(SUMMARY_HASH_FIELD, None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def attach_summary_digest(summary: dict[str, Any]) -> dict[str, Any]:
    payload = dict(summary)
    payload[SUMMARY_HASH_FIELD] = qualification_summary_sha256(payload)
    return payload


def is_nonnegative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def require_boolean(value: dict[str, Any], field: str, label: str, failures: list[str]) -> None:
    if not isinstance(value.get(field), bool):
        failures.append(f"{label}.{field} must be a boolean")


def require_string_list(value: dict[str, Any], field: str, label: str, failures: list[str]) -> None:
    items = value.get(field)
    if not isinstance(items, list):
        failures.append(f"{label}.{field} must be a list")
        return
    for index, item in enumerate(items):
        if not isinstance(item, str):
            failures.append(f"{label}.{field}[{index}] must be a string")


def require_string_map(value: dict[str, Any], field: str, label: str, failures: list[str]) -> None:
    items = value.get(field)
    if not isinstance(items, dict):
        failures.append(f"{label}.{field} must be a string map")
        return
    for key, item in items.items():
        if not isinstance(key, str) or not isinstance(item, str):
            failures.append(f"{label}.{field} must be a string map")
            return


def require_count_map(value: dict[str, Any], field: str, label: str, failures: list[str]) -> None:
    counts = value.get(field)
    if not isinstance(counts, dict):
        failures.append(f"{label}.{field} must be an object of non-negative integer counts")
        return
    for key, count in counts.items():
        if not isinstance(key, str) or not is_nonnegative_int(count):
            failures.append(f"{label}.{field} must be an object of non-negative integer counts")
            return


def require_nonnegative_int_field(
    value: dict[str, Any],
    field: str,
    label: str,
    failures: list[str],
) -> None:
    if not is_nonnegative_int(value.get(field)):
        failures.append(f"{label}.{field} must be a non-negative integer")


def validate_summary_schema(summary: dict[str, Any], failures: list[str]) -> None:
    require_boolean(summary, "ready", "summary", failures)
    require_count_map(summary, "counts", "summary", failures)
    require_string_map(summary, "qualificationMetadata", "summary", failures)
    require_boolean(summary, "externalEvidenceAllowed", "summary", failures)
    require_string_map(summary, "externalEvidence", "summary", failures)
    require_boolean(summary, "externalOutputAllowed", "summary", failures)
    external_output = summary.get("externalOutput")
    if external_output is not None and not isinstance(external_output, str):
        failures.append("summary.externalOutput must be a string path or null")
    require_string_map(summary, "proofs", "summary", failures)
    for field in ("missingProofs", "unresolved", "failed"):
        require_string_list(summary, field, "summary", failures)
    require_boolean(summary, "persistedAuditVerified", "summary", failures)
    require_boolean(summary, "sourceReverified", "summary", failures)
    if not isinstance(summary.get("persistedAuditVerification"), dict):
        failures.append("summary.persistedAuditVerification must be an object")
    source_manifest = summary.get("supplementalSourceManifest")
    if source_manifest is not None and not isinstance(source_manifest, dict):
        failures.append("summary.supplementalSourceManifest must be an object or null")


def validate_source_manifest_summary_schema(
    source_manifest: dict[str, Any],
    failures: list[str],
) -> None:
    require_boolean(source_manifest, "verified", "summary supplementalSourceManifest", failures)
    for field in ("sourceArtifactCount", "generatedProofCount", "bridgeScriptCount"):
        require_nonnegative_int_field(
            source_manifest,
            field,
            "summary supplementalSourceManifest",
            failures,
        )
    require_string_map(
        source_manifest,
        "externalSourceArtifacts",
        "summary supplementalSourceManifest",
        failures,
    )
    if not isinstance(source_manifest.get("policy"), dict):
        failures.append("summary supplementalSourceManifest.policy must be an object")


def verify_qualification_summary_file(path: pathlib.Path) -> dict[str, Any]:
    failures: list[str] = []
    audit_verification: dict[str, Any] | None = None
    audit_module = load_audit_module()
    try:
        summary = load_json_object(path)
    except ValueError as exc:
        return {
            "verified": False,
            "failureCount": 1,
            "failures": [f"qualification summary must be a JSON object: {exc}"],
            "summaryPath": str(path.expanduser().resolve()),
        }
    if summary.get("schemaVersion") != 1 or isinstance(summary.get("schemaVersion"), bool):
        failures.append("schemaVersion must be 1")
    unsupported_summary_fields = sorted(set(summary) - SUMMARY_FIELDS)
    if unsupported_summary_fields:
        failures.append(
            "qualification summary contains unsupported fields: "
            + ", ".join(unsupported_summary_fields)
        )
    validate_summary_schema(summary, failures)
    recorded = summary.get(SUMMARY_HASH_FIELD)
    if not isinstance(recorded, str) or not recorded.startswith("sha256:"):
        failures.append(f"{SUMMARY_HASH_FIELD} must be present")
        recorded = ""
    current = qualification_summary_sha256(summary)
    if recorded and recorded != current:
        failures.append(f"{SUMMARY_HASH_FIELD} does not match current summary payload")

    audit_path_value = summary.get("auditPath")
    if not isinstance(audit_path_value, str) or not audit_path_value.strip():
        failures.append("auditPath must be a non-empty path")
    else:
        audit_path = pathlib.Path(audit_path_value)
        audit_verification = audit_module.verify_audit_file(audit_path)
        if audit_verification.get("verified") is not True:
            failures.append("persisted readiness audit verification failed")
        if summary.get("ready") is not audit_verification.get("ready"):
            failures.append("summary ready value does not match persisted readiness audit")
        try:
            audit_payload = load_json_object(audit_path)
        except ValueError as exc:
            failures.append(f"persisted readiness audit must be readable for summary cross-check: {exc}")
        else:
            if summary.get("auditSha256") != audit_payload.get("auditSha256"):
                failures.append("summary auditSha256 does not match persisted readiness audit")
            if summary.get("counts") != audit_payload.get("counts"):
                failures.append("summary counts do not match persisted readiness audit")
            if summary.get("unresolved") != audit_payload.get("unresolved"):
                failures.append("summary unresolved list does not match persisted readiness audit")
            failed_from_audit = sorted(
                item.get("key")
                for item in audit_payload.get("checklist", [])
                if isinstance(item, dict) and item.get("status") == "failed"
            )
            if summary.get("failed") != failed_from_audit:
                failures.append("summary failed list does not match persisted readiness audit")
            missing_from_audit = sorted(
                item.get("key")
                for item in audit_payload.get("checklist", [])
                if isinstance(item, dict) and item.get("status") == "missing"
            )
            if summary.get("missingProofs") != missing_from_audit:
                failures.append("summary missingProofs list does not match persisted readiness audit")
            if summary.get("persistedAuditVerified") is not audit_verification.get("verified"):
                failures.append("summary persistedAuditVerified does not match audit verification")
            if summary.get("sourceReverified") is not audit_verification.get("sourceReverified"):
                failures.append("summary sourceReverified does not match audit verification")
            if summary.get("persistedAuditVerification") != audit_verification:
                failures.append("summary persistedAuditVerification does not match audit verification")
            bundle_dir_value = summary.get("bundleDir")
            bundle_dir: pathlib.Path | None = None
            if not isinstance(bundle_dir_value, str) or not bundle_dir_value.strip():
                failures.append("bundleDir must be a non-empty path")
            else:
                bundle_dir = pathlib.Path(bundle_dir_value).expanduser().resolve()
            expected_external_evidence: dict[str, str] = {}
            provenance = audit_payload.get("provenance") if isinstance(audit_payload.get("provenance"), dict) else {}
            if summary.get("bundleDir") != provenance.get("qualificationBundleDir"):
                failures.append("summary bundleDir does not match persisted audit provenance")
            if summary.get("externalEvidenceAllowed") is not provenance.get("externalEvidenceAllowed"):
                failures.append("summary externalEvidenceAllowed does not match audit provenance")
            if summary.get("externalOutputAllowed") is not provenance.get("externalOutputAllowed"):
                failures.append("summary externalOutputAllowed does not match audit provenance")
            provenance_metadata = provenance.get("qualificationMetadata")
            if not isinstance(provenance_metadata, dict):
                provenance_metadata = {}
            if summary.get("qualificationMetadata") != provenance_metadata:
                failures.append("summary qualificationMetadata does not match persisted audit provenance")
            manifest_path_value = provenance.get("macosProviderManifest")
            if summary.get("manifestPath") != manifest_path_value:
                failures.append("summary manifestPath does not match persisted readiness audit provenance")
            elif isinstance(manifest_path_value, str) and bundle_dir is not None:
                manifest_path = pathlib.Path(manifest_path_value).expanduser().resolve()
                if not is_inside_bundle(manifest_path, bundle_dir):
                    expected_external_evidence["manifest"] = str(manifest_path)
            supplemental_proofs = provenance.get("supplementalProofs")
            supplemental_proof_paths: dict[str, pathlib.Path] = {}
            if summary.get("proofs") != supplemental_proofs:
                failures.append("summary proofs do not match persisted readiness audit provenance")
            elif isinstance(supplemental_proofs, dict) and bundle_dir is not None:
                for key, proof_path_value in sorted(supplemental_proofs.items()):
                    if isinstance(proof_path_value, str):
                        proof_path = pathlib.Path(proof_path_value).expanduser().resolve()
                        if isinstance(key, str):
                            supplemental_proof_paths[key] = proof_path
                        if not is_inside_bundle(proof_path, bundle_dir):
                            expected_external_evidence[f"proof:{key}"] = str(proof_path)
            source_manifest = (
                summary.get("supplementalSourceManifest")
                if isinstance(summary.get("supplementalSourceManifest"), dict)
                else None
            )
            provenance_source_manifest = provenance.get("supplementalSourceManifest")
            if isinstance(provenance_source_manifest, dict) and bundle_dir is not None:
                provenance_source_manifest_path = provenance_source_manifest.get("path")
                if isinstance(provenance_source_manifest_path, str):
                    source_manifest_path = pathlib.Path(
                        provenance_source_manifest_path
                    ).expanduser().resolve()
                    if not is_inside_bundle(source_manifest_path, bundle_dir):
                        expected_external_evidence["supplementalSourceManifest"] = str(
                            source_manifest_path
                        )
            if source_manifest is None and provenance_source_manifest is not None:
                failures.append("summary missing supplementalSourceManifest recorded by audit provenance")
            elif source_manifest is not None:
                unsupported_source_summary_fields = sorted(
                    set(source_manifest) - SOURCE_MANIFEST_SUMMARY_FIELDS
                )
                if unsupported_source_summary_fields:
                    failures.append(
                        "summary supplementalSourceManifest contains unsupported fields: "
                        + ", ".join(unsupported_source_summary_fields)
                    )
                validate_source_manifest_summary_schema(source_manifest, failures)
                if not isinstance(provenance_source_manifest, dict):
                    failures.append("summary supplementalSourceManifest missing from audit provenance")
                elif source_manifest.get("path") != provenance_source_manifest.get("path"):
                    failures.append("summary supplementalSourceManifest path does not match audit provenance")
                elif source_manifest.get("sha256") != provenance_source_manifest.get("sha256"):
                    failures.append("summary supplementalSourceManifest sha256 does not match audit provenance")
                elif bundle_dir is not None and isinstance(source_manifest.get("path"), str):
                    try:
                        verified_source_manifest = verify_supplemental_source_manifest(
                            pathlib.Path(source_manifest["path"]).expanduser().resolve(),
                            bundle_dir,
                            set(audit_module.SUPPLEMENTAL_PROOF_KEYS),
                            True,
                            supplemental_proof_paths,
                        )
                    except ValueError as exc:
                        failures.append(
                            f"summary supplementalSourceManifest failed live verification: {exc}"
                        )
                    else:
                        for field in (
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
                            "policy",
                        ):
                            if source_manifest.get(field) != verified_source_manifest.get(field):
                                failures.append(
                                    f"summary supplementalSourceManifest {field} "
                                    "does not match live source manifest verification"
                                )
                        external_sources = verified_source_manifest.get("externalSourceArtifacts")
                        if isinstance(external_sources, dict):
                            for key, source_path in sorted(external_sources.items()):
                                if isinstance(key, str) and isinstance(source_path, str):
                                    expected_external_evidence[key] = source_path
            external_evidence = summary.get("externalEvidence")
            if not isinstance(external_evidence, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in getattr(external_evidence, "items", lambda: [])()
            ):
                failures.append("summary externalEvidence must be a string map")
            elif external_evidence != expected_external_evidence:
                failures.append("summary externalEvidence does not match persisted evidence paths")
            if expected_external_evidence and summary.get("externalEvidenceAllowed") is not True:
                failures.append("summary externalEvidenceAllowed must be true for external evidence")
            audit_path_resolved = audit_path.expanduser().resolve()
            external_output = summary.get("externalOutput")
            if external_output is not None and not isinstance(external_output, str):
                failures.append("summary externalOutput must be a string path or null")
            elif bundle_dir is not None and not is_inside_bundle(audit_path_resolved, bundle_dir):
                if external_output != str(audit_path_resolved):
                    failures.append("summary externalOutput does not match auditPath outside bundle")
                if summary.get("externalOutputAllowed") is not True:
                    failures.append("summary externalOutputAllowed must be true for external audit output")
            elif external_output is not None:
                failures.append("summary externalOutput must be null when audit output is inside bundle")

    return {
        "verified": not failures,
        "failureCount": len(failures),
        "failures": failures,
        "summaryPath": str(path.expanduser().resolve()),
        "recordedSummarySha256": recorded or None,
        "currentSummarySha256": current,
        "persistedAuditVerification": audit_verification,
    }


def resolve_existing_file(path: pathlib.Path, label: str) -> pathlib.Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"{label} must reference an existing file: {resolved}")
    return resolved


def ensure_inside_bundle(
    path: pathlib.Path,
    bundle_dir: pathlib.Path,
    label: str,
    allow_external: bool,
) -> pathlib.Path:
    resolved = path.expanduser().resolve()
    if allow_external:
        return resolved
    try:
        resolved.relative_to(bundle_dir)
    except ValueError as exc:
        raise ValueError(
            f"{label} must be inside --bundle-dir or pass --allow-external-evidence: {resolved}"
        ) from exc
    return resolved


def is_inside_bundle(path: pathlib.Path, bundle_dir: pathlib.Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(bundle_dir)
    except ValueError:
        return False
    return True


def is_inside_directory(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        path.expanduser().resolve().relative_to(root.expanduser().resolve())
    except ValueError:
        return False
    return True


def resolve_manifest_dir_path(raw_path: Any, base_dir: pathlib.Path, label: str) -> pathlib.Path:
    if not isinstance(raw_path, str) or not raw_path.strip():
        raise ValueError(f"{label} must be a non-empty path")
    candidate = pathlib.Path(raw_path).expanduser()
    candidate = candidate if candidate.is_absolute() else base_dir / candidate
    resolved = candidate.expanduser().resolve()
    if not resolved.is_dir():
        raise ValueError(f"{label} must reference an existing directory: {resolved}")
    return resolved


def ensure_output_path(
    path: pathlib.Path,
    bundle_dir: pathlib.Path,
    allow_external_output: bool,
) -> pathlib.Path:
    resolved = path.expanduser().resolve()
    if resolved.exists() and resolved.is_dir():
        raise ValueError(f"--output must reference a file, not a directory: {resolved}")
    if not allow_external_output and not is_inside_bundle(resolved, bundle_dir):
        raise ValueError(
            f"--output must be inside --bundle-dir or pass --allow-external-output: {resolved}"
        )
    return resolved


def parse_proof_spec(spec: str) -> tuple[str, pathlib.Path]:
    if "=" not in spec:
        raise ValueError(f"proof spec must be KEY=PATH: {spec}")
    key, value = spec.split("=", 1)
    key = key.strip()
    if not key:
        raise ValueError(f"proof spec has empty key: {spec}")
    return key, resolve_existing_file(pathlib.Path(value), f"proof {key}")


def parse_metadata_specs(specs: list[str]) -> dict[str, str]:
    if len(specs) > MAX_METADATA_ENTRIES:
        raise ValueError(f"at most {MAX_METADATA_ENTRIES} metadata entries are allowed")
    metadata: dict[str, str] = {}
    for spec in specs:
        if "=" not in spec:
            raise ValueError(f"metadata spec must be KEY=VALUE: {spec}")
        key, value = spec.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"metadata spec has empty key: {spec}")
        if len(key.encode("utf-8")) > MAX_METADATA_KEY_BYTES:
            raise ValueError(f"metadata key is too long: {key}")
        if not value:
            raise ValueError(f"metadata value must be non-empty for key: {key}")
        if len(value.encode("utf-8")) > MAX_METADATA_VALUE_BYTES:
            raise ValueError(f"metadata value is too long for key: {key}")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError(f"metadata value contains control characters for key: {key}")
        if any(
            char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
            for char in key
        ):
            raise ValueError(f"metadata key uses unsupported characters: {key}")
        if key in metadata:
            raise ValueError(f"duplicate metadata key: {key}")
        metadata[key] = value
    return metadata


def default_manifest_candidates(bundle_dir: pathlib.Path) -> list[pathlib.Path]:
    return [
        bundle_dir / "manifest.json",
        bundle_dir / "macos-provider" / "manifest.json",
        bundle_dir / "dogfood" / "manifest.json",
    ]


def discover_manifest(bundle_dir: pathlib.Path, explicit: pathlib.Path | None) -> pathlib.Path:
    if explicit is not None:
        return resolve_existing_file(explicit, "--manifest")
    for candidate in default_manifest_candidates(bundle_dir):
        if candidate.is_file():
            return candidate.resolve()
    matches = sorted(path.resolve() for path in bundle_dir.rglob("manifest.json") if path.is_file())
    if not matches:
        raise ValueError(
            "bundle does not contain manifest.json; pass --manifest or include the macOS "
            "provider dogfood manifest"
        )
    if len(matches) > 1:
        relative = [str(path.relative_to(bundle_dir)) for path in matches]
        raise ValueError(
            "bundle contains multiple manifest.json files; pass --manifest explicitly: "
            + ", ".join(relative)
        )
    return matches[0]


def default_proof_roots(bundle_dir: pathlib.Path) -> list[pathlib.Path]:
    preferred = [
        bundle_dir / "supplemental-proofs",
        bundle_dir / "supplemental",
        bundle_dir / "proofs",
    ]
    existing = [path for path in preferred if path.is_dir()]
    return existing if existing else [bundle_dir]


def proof_key_from_file(path: pathlib.Path, supported_keys: set[str]) -> str | None:
    try:
        payload = load_json_object(path)
    except ValueError:
        return None
    key = payload.get("key")
    if isinstance(key, str) and key in supported_keys and payload.get("verified") is True:
        return key
    return None


def discover_proofs(
    bundle_dir: pathlib.Path,
    proof_roots: list[pathlib.Path],
    explicit_specs: list[str],
    supported_keys: set[str],
    manifest_path: pathlib.Path,
    output_path: pathlib.Path,
    allow_external: bool,
) -> dict[str, pathlib.Path]:
    proofs: dict[str, pathlib.Path] = {}
    for spec in explicit_specs:
        key, path = parse_proof_spec(spec)
        if key not in supported_keys:
            raise ValueError(f"unsupported supplemental proof key: {key}")
        path = ensure_inside_bundle(path, bundle_dir, f"proof {key}", allow_external)
        if key in proofs:
            raise ValueError(f"duplicate supplemental proof key: {key}")
        proofs[key] = path

    ignored = {manifest_path.resolve()}
    for root in proof_roots:
        resolved_root = root.expanduser().resolve()
        if not resolved_root.is_dir():
            raise ValueError(f"--proof-root must reference an existing directory: {resolved_root}")
        ensure_inside_bundle(
            resolved_root,
            bundle_dir,
            "--proof-root",
            allow_external,
        )
        for path in sorted(resolved_root.rglob("*.json")):
            resolved = path.resolve()
            if resolved in ignored:
                continue
            key = proof_key_from_file(resolved, supported_keys)
            if key is None:
                continue
            if key in proofs and proofs[key] != resolved:
                raise ValueError(
                    f"duplicate supplemental proof for {key}: {proofs[key]} and {resolved}"
                )
            proofs[key] = resolved
    return proofs


def discover_supplemental_source_manifest(
    bundle_dir: pathlib.Path,
    proof_roots: list[pathlib.Path],
    allow_external: bool,
) -> pathlib.Path | None:
    matches: list[pathlib.Path] = []
    for root in proof_roots:
        resolved_root = root.expanduser().resolve()
        candidate = resolved_root / SOURCE_MANIFEST_NAME
        if candidate.is_file():
            matches.append(
                ensure_inside_bundle(
                    candidate,
                    bundle_dir,
                    "supplemental source manifest",
                    allow_external,
                )
            )
    unique = sorted({path.resolve() for path in matches})
    if not unique:
        return None
    if len(unique) > 1:
        raise ValueError(
            "multiple supplemental source manifests discovered: "
            + ", ".join(str(path) for path in unique)
        )
    return unique[0]


def verify_file_record(
    record: Any,
    label: str,
    bundle_dir: pathlib.Path,
    allow_external: bool,
    base_dir: pathlib.Path,
    source_root: pathlib.Path | None = None,
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError(f"{label} must be an object")
    unsupported_fields = sorted(set(record) - {"path", "sha256", "byteSize"})
    if unsupported_fields:
        raise ValueError(
            f"{label} contains unsupported fields: {', '.join(unsupported_fields)}"
        )
    raw_path = record.get("path")
    expected_hash = record.get("sha256")
    expected_size = record.get("byteSize")
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError(f"{label} missing path")
    if not isinstance(expected_hash, str) or not expected_hash.startswith("sha256:"):
        raise ValueError(f"{label} missing sha256")
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
        raise ValueError(f"{label} missing byteSize")
    raw_candidate = pathlib.Path(raw_path)
    candidate = raw_candidate if raw_candidate.is_absolute() else base_dir / raw_candidate
    path = resolve_existing_file(candidate, label)
    if not allow_external:
        ensure_inside_bundle(path, bundle_dir, label, allow_external=False)
    if source_root is not None and not is_inside_directory(path, source_root):
        if not allow_external or is_inside_bundle(path, bundle_dir):
            raise ValueError(f"{label} must resolve under supplemental sourceRoot")
    actual_size = path.stat().st_size
    actual_hash = file_sha256(path)
    if actual_size != expected_size:
        raise ValueError(f"{label} byteSize mismatch: expected {expected_size}, got {actual_size}")
    if actual_hash != expected_hash:
        raise ValueError(f"{label} sha256 mismatch: expected {expected_hash}, got {actual_hash}")
    return {
        "path": str(path),
        "sha256": actual_hash,
        "byteSize": actual_size,
        "external": not is_inside_bundle(path, bundle_dir),
    }


def verify_tool_record(record: Any, label: str) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise ValueError(f"{label} must be an object")
    unsupported_fields = sorted(set(record) - {"path", "sha256", "byteSize"})
    if unsupported_fields:
        raise ValueError(
            f"{label} contains unsupported fields: {', '.join(unsupported_fields)}"
        )
    raw_path = record.get("path")
    expected_hash = record.get("sha256")
    expected_size = record.get("byteSize")
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError(f"{label} missing path")
    if not isinstance(expected_hash, str) or not expected_hash.startswith("sha256:"):
        raise ValueError(f"{label} missing sha256")
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 0:
        raise ValueError(f"{label} missing byteSize")
    path = resolve_existing_file(pathlib.Path(raw_path), label)
    actual_size = path.stat().st_size
    actual_hash = file_sha256(path)
    if actual_size != expected_size:
        raise ValueError(f"{label} byteSize mismatch: expected {expected_size}, got {actual_size}")
    if actual_hash != expected_hash:
        raise ValueError(f"{label} sha256 mismatch: expected {expected_hash}, got {actual_hash}")
    return {
        "path": str(path),
        "sha256": actual_hash,
        "byteSize": actual_size,
    }


def resolve_source_policy_ref_path(policy_ref: str, base_dir: pathlib.Path) -> pathlib.Path | None:
    candidate = pathlib.Path(policy_ref).expanduser()
    resolved = candidate if candidate.is_absolute() else base_dir / candidate
    return resolved if resolved.is_file() else None


def verify_source_manifest_policy(policy: Any, base_dir: pathlib.Path) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise ValueError("supplemental source manifest policy must be an object")
    unsupported_fields = sorted(
        set(policy) - {"currentPolicyRef", "proposedPolicyRef", "proposedPolicyHash", "policyEpoch"}
    )
    if unsupported_fields:
        raise ValueError(
            "supplemental source manifest policy contains unsupported fields: "
            + ", ".join(unsupported_fields)
        )
    for field in ("currentPolicyRef", "proposedPolicyRef"):
        value = policy.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"supplemental source manifest policy.{field} must be non-empty")
    proposed_hash = policy.get("proposedPolicyHash")
    if (
        not isinstance(proposed_hash, str)
        or not proposed_hash.startswith("sha256:")
        or len(proposed_hash) != 71
    ):
        raise ValueError(
            "supplemental source manifest policy.proposedPolicyHash must be sha256:<64-hex>"
        )
    try:
        int(proposed_hash.removeprefix("sha256:"), 16)
    except ValueError as exc:
        raise ValueError(
            "supplemental source manifest policy.proposedPolicyHash must be sha256:<64-hex>"
        ) from exc
    proposed_path = resolve_source_policy_ref_path(policy["proposedPolicyRef"], base_dir)
    if proposed_path is not None and file_sha256(proposed_path) != proposed_hash:
        raise ValueError(
            "supplemental source manifest policy.proposedPolicyHash no longer matches proposedPolicyRef file"
        )
    policy_epoch = policy.get("policyEpoch")
    if not isinstance(policy_epoch, int) or isinstance(policy_epoch, bool) or policy_epoch < 1:
        raise ValueError(
            "supplemental source manifest policy.policyEpoch must be a positive integer"
        )
    return {
        "currentPolicyRef": policy["currentPolicyRef"],
        "proposedPolicyRef": policy["proposedPolicyRef"],
        "proposedPolicyHash": proposed_hash,
        "policyEpoch": policy_epoch,
    }


def verify_supplemental_source_manifest(
    source_manifest_path: pathlib.Path,
    bundle_dir: pathlib.Path,
    supported_keys: set[str],
    allow_external: bool,
    proofs: dict[str, pathlib.Path] | None = None,
) -> dict[str, Any]:
    proofs = proofs or {}
    payload = load_json_object(source_manifest_path)
    unsupported_manifest_fields = sorted(
        set(payload)
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
        raise ValueError(
            "supplemental source manifest contains unsupported fields: "
            + ", ".join(unsupported_manifest_fields)
        )
    if payload.get("schemaVersion") != 1 or isinstance(payload.get("schemaVersion"), bool):
        raise ValueError("supplemental source manifest schemaVersion must be 1")
    if payload.get("kind") != SOURCE_MANIFEST_KIND:
        raise ValueError("supplemental source manifest kind is unsupported")
    if not isinstance(payload.get("generatedAt"), str) or not payload["generatedAt"].strip():
        raise ValueError("supplemental source manifest generatedAt must be a non-empty string")
    evidence_mode = payload.get("evidenceMode")
    if evidence_mode not in {"live", "fixture"}:
        raise ValueError("supplemental source manifest evidenceMode must be live or fixture")
    expected_keys = payload.get("expectedProofKeys")
    if not isinstance(expected_keys, list) or any(not isinstance(key, str) for key in expected_keys):
        raise ValueError("supplemental source manifest expectedProofKeys must be a string list")
    if sorted(expected_keys) != sorted(supported_keys):
        raise ValueError("supplemental source manifest expectedProofKeys do not match verifier keys")
    proof_root = resolve_manifest_dir_path(
        payload.get("proofRoot"),
        source_manifest_path.parent,
        "supplemental source manifest proofRoot",
    )
    if proof_root != source_manifest_path.parent.expanduser().resolve():
        raise ValueError("supplemental source manifest proofRoot must resolve to manifest parent")
    source_root = resolve_manifest_dir_path(
        payload.get("sourceRoot"),
        source_manifest_path.parent,
        "supplemental source manifest sourceRoot",
    )
    if not is_inside_directory(source_root, proof_root):
        raise ValueError("supplemental source manifest sourceRoot must resolve inside proofRoot")
    verified_policy = verify_source_manifest_policy(payload.get("policy"), source_manifest_path.parent)

    source_artifacts = payload.get("sourceArtifacts")
    if not isinstance(source_artifacts, dict):
        raise ValueError("supplemental source manifest sourceArtifacts must be an object")
    unsupported_source_artifact_fields = sorted(
        set(source_artifacts) - {"policyEvents", "policyImpactJson", "coverageInputs"}
    )
    if unsupported_source_artifact_fields:
        raise ValueError(
            "supplemental source manifest sourceArtifacts contains unsupported fields: "
            + ", ".join(unsupported_source_artifact_fields)
        )
    verified_sources = {
        "policyEvents": verify_file_record(
            source_artifacts.get("policyEvents"),
            "supplemental source policyEvents",
            bundle_dir,
            allow_external,
            source_manifest_path.parent,
            source_root,
        ),
        "policyImpactJson": verify_file_record(
            source_artifacts.get("policyImpactJson"),
            "supplemental source policyImpactJson",
            bundle_dir,
            allow_external,
            source_manifest_path.parent,
            source_root,
        ),
    }
    coverage_inputs = source_artifacts.get("coverageInputs")
    if not isinstance(coverage_inputs, dict):
        raise ValueError("supplemental source manifest coverageInputs must be an object")
    expected_coverage_keys = sorted(supported_keys - {"policy_simulation_impact"})
    if sorted(coverage_inputs) != expected_coverage_keys:
        raise ValueError("supplemental source manifest coverageInputs do not match verifier keys")
    verified_coverage = {
        key: verify_file_record(
            coverage_inputs[key],
            f"supplemental source coverageInputs.{key}",
            bundle_dir,
            allow_external,
            source_manifest_path.parent,
            source_root,
        )
        for key in expected_coverage_keys
    }

    generated_proofs = payload.get("generatedProofs")
    if not isinstance(generated_proofs, dict):
        raise ValueError("supplemental source manifest generatedProofs must be an object")
    if sorted(generated_proofs) != sorted(supported_keys):
        raise ValueError("supplemental source manifest generatedProofs do not match verifier keys")
    verified_generated_proofs: dict[str, dict[str, Any]] = {}
    for key in sorted(supported_keys):
        generated_record = verify_file_record(
            generated_proofs[key],
            f"supplemental generatedProofs.{key}",
            bundle_dir,
            allow_external,
            source_manifest_path.parent,
        )
        generated_path = pathlib.Path(generated_record["path"])
        if not is_inside_directory(generated_path, proof_root):
            if not allow_external or is_inside_bundle(generated_path, bundle_dir):
                raise ValueError(
                    f"supplemental generatedProofs.{key} must resolve under supplemental proofRoot"
                )
        expected_proof_path = proofs.get(key)
        if expected_proof_path is not None and generated_path.resolve() != expected_proof_path.resolve():
            raise ValueError(
                f"supplemental generatedProofs.{key} does not match discovered proof path"
            )
        verified_generated_proofs[key] = generated_record

    bridge_scripts = payload.get("bridgeScripts")
    if not isinstance(bridge_scripts, dict):
        raise ValueError("supplemental source manifest bridgeScripts must be an object")
    if sorted(bridge_scripts) != sorted(supported_keys):
        raise ValueError("supplemental source manifest bridgeScripts do not match verifier keys")
    verified_bridges = {
        key: verify_tool_record(bridge_scripts[key], f"supplemental bridgeScripts.{key}")
        for key in sorted(supported_keys)
    }
    for key, record in sorted(verified_bridges.items()):
        expected_script = EXPECTED_BRIDGE_SCRIPTS.get(key)
        if expected_script is None:
            raise ValueError(f"supplemental bridgeScripts.{key} is unsupported")
        expected_path = SCRIPT_DIR / expected_script
        if pathlib.Path(record["path"]).expanduser().resolve() != expected_path.resolve():
            raise ValueError(
                f"supplemental bridgeScripts.{key} must reference {expected_path}"
            )

    external_source_artifacts = {
        f"source:{key}": value["path"]
        for key, value in {
            "policyEvents": verified_sources["policyEvents"],
            "policyImpactJson": verified_sources["policyImpactJson"],
            **{f"coverageInputs.{key}": value for key, value in verified_coverage.items()},
        }.items()
        if value.get("external") is True
    }
    return {
        "path": str(source_manifest_path),
        "sha256": file_sha256(source_manifest_path),
        "verified": True,
        "evidenceMode": evidence_mode,
        "proofRoot": str(proof_root),
        "sourceRoot": str(source_root),
        "sourceArtifactCount": 2 + len(verified_coverage),
        "generatedProofCount": len(verified_generated_proofs),
        "bridgeScriptCount": len(verified_bridges),
        "externalSourceArtifacts": external_source_artifacts,
        "policy": verified_policy,
    }


def summarize_audit(audit: dict[str, Any]) -> tuple[list[str], list[str]]:
    checklist = audit.get("checklist")
    if not isinstance(checklist, list):
        return [], []
    unresolved = [
        item.get("key")
        for item in checklist
        if isinstance(item, dict) and item.get("status") != "verified"
    ]
    failed = [
        item.get("key")
        for item in checklist
        if isinstance(item, dict) and item.get("status") == "failed"
    ]
    return [key for key in unresolved if isinstance(key, str)], [
        key for key in failed if isinstance(key, str)
    ]


def qualify_bundle(args: argparse.Namespace) -> dict[str, Any]:
    audit_module = load_audit_module()
    qualification_metadata = parse_metadata_specs(getattr(args, "metadata", []))
    supported_keys = set(audit_module.SUPPLEMENTAL_PROOF_KEYS)
    bundle_dir = args.bundle_dir.expanduser().resolve()
    if not bundle_dir.is_dir():
        raise ValueError(f"--bundle-dir must reference an existing directory: {bundle_dir}")

    allow_external_output = bool(getattr(args, "allow_external_output", False))
    default_output = bundle_dir / "endpoint-decision-engine-readiness-audit.json"
    output_path = ensure_output_path(
        args.output if args.output is not None else default_output,
        bundle_dir,
        allow_external_output,
    )
    manifest_path = discover_manifest(bundle_dir, args.manifest)
    allow_external = bool(getattr(args, "allow_external_evidence", False))
    manifest_path = ensure_inside_bundle(
        manifest_path,
        bundle_dir,
        "--manifest",
        allow_external,
    )
    proof_roots = (
        [path.expanduser().resolve() for path in args.proof_root]
        if args.proof_root
        else default_proof_roots(bundle_dir)
    )
    proofs = discover_proofs(
        bundle_dir,
        proof_roots,
        args.proof,
        supported_keys,
        manifest_path,
        output_path,
        allow_external,
    )
    missing_proofs = sorted(supported_keys - set(proofs))
    source_manifest_path = discover_supplemental_source_manifest(
        bundle_dir,
        proof_roots,
        allow_external,
    )
    if not missing_proofs and source_manifest_path is None:
        raise ValueError("complete supplemental proof set requires supplemental source manifest")
    source_manifest_summary = (
        verify_supplemental_source_manifest(
            source_manifest_path,
            bundle_dir,
            supported_keys,
            allow_external,
            proofs,
        )
        if source_manifest_path is not None
        else None
    )
    proof_paths = {path.resolve() for path in proofs.values()}
    input_paths = {manifest_path.resolve(), *proof_paths}
    if source_manifest_path is not None:
        input_paths.add(source_manifest_path.resolve())
    if output_path.resolve() in input_paths:
        raise ValueError(f"--output must not overwrite input evidence: {output_path}")

    source_manifest_external_artifacts = (
        source_manifest_summary.get("externalSourceArtifacts", {})
        if isinstance(source_manifest_summary, dict)
        else {}
    )
    audit = audit_module.build_audit(
        manifest_path,
        proofs,
        source_manifest_path,
        source_manifest_external_artifacts,
    )
    audit = dict(audit)
    provenance = dict(audit.get("provenance") if isinstance(audit.get("provenance"), dict) else {})
    provenance["qualificationBundleDir"] = str(bundle_dir)
    provenance["qualificationMetadata"] = qualification_metadata
    provenance["externalEvidenceAllowed"] = allow_external
    provenance["externalOutputAllowed"] = allow_external_output
    audit["provenance"] = provenance
    audit = audit_module.attach_audit_digest(audit)
    if source_manifest_summary is not None:
        audit = dict(audit)
        provenance = dict(audit.get("provenance") if isinstance(audit.get("provenance"), dict) else {})
        provenance["supplementalSourceManifest"] = {
            "path": source_manifest_summary["path"],
            "sha256": source_manifest_summary["sha256"],
            "verified": source_manifest_summary["verified"],
            "evidenceMode": source_manifest_summary["evidenceMode"],
            "proofRoot": source_manifest_summary["proofRoot"],
            "sourceRoot": source_manifest_summary["sourceRoot"],
            "sourceArtifactCount": source_manifest_summary["sourceArtifactCount"],
            "generatedProofCount": source_manifest_summary["generatedProofCount"],
            "bridgeScriptCount": source_manifest_summary["bridgeScriptCount"],
            "externalSourceArtifacts": source_manifest_summary["externalSourceArtifacts"],
        }
        audit["provenance"] = provenance
        audit = audit_module.attach_audit_digest(audit)
    write_json(output_path, audit)
    persisted = audit_module.verify_audit_file(output_path)
    unresolved, failed = summarize_audit(audit)
    external_evidence: dict[str, str] = {}
    if not is_inside_bundle(manifest_path, bundle_dir):
        external_evidence["manifest"] = str(manifest_path)
    for key, path in sorted(proofs.items()):
        if not is_inside_bundle(path, bundle_dir):
            external_evidence[f"proof:{key}"] = str(path)
    if source_manifest_path is not None and not is_inside_bundle(source_manifest_path, bundle_dir):
        external_evidence["supplementalSourceManifest"] = str(source_manifest_path)
    if source_manifest_summary is not None:
        for key, path in source_manifest_summary.get("externalSourceArtifacts", {}).items():
            external_evidence[key] = path
    result = {
        "schemaVersion": 1,
        "bundleDir": str(bundle_dir),
        "manifestPath": str(manifest_path),
        "auditPath": str(output_path),
        "ready": audit.get("ready") is True,
        "counts": audit.get("counts"),
        "auditSha256": audit.get("auditSha256"),
        "qualificationMetadata": qualification_metadata,
        "externalEvidenceAllowed": allow_external,
        "externalEvidence": external_evidence,
        "externalOutputAllowed": allow_external_output,
        "externalOutput": (
            str(output_path) if not is_inside_bundle(output_path, bundle_dir) else None
        ),
        "supplementalSourceManifest": source_manifest_summary,
        "proofs": {key: str(path) for key, path in sorted(proofs.items())},
        "missingProofs": missing_proofs,
        "unresolved": unresolved,
        "failed": failed,
        "persistedAuditVerified": persisted.get("verified") is True,
        "sourceReverified": persisted.get("sourceReverified") is True,
        "persistedAuditVerification": persisted,
    }
    return attach_summary_digest(result)


def create_synthetic_manifest(audit_module: Any, root: pathlib.Path) -> pathlib.Path:
    gate_module = audit_module.load_module(SCRIPT_DIR / "macos-provider-dogfood-gate.py")
    manifest_module = audit_module.load_module(SCRIPT_DIR / "macos-provider-dogfood-manifest.py")
    dogfood_root = root / "dogfood"
    deployment_dir = dogfood_root / "deployment-evidence"
    es_dir = dogfood_root / "endpoint-security"
    ne_dir = dogfood_root / "network-extension"
    deployment_summary_path = deployment_dir / "summary.json"
    es_summary_path = es_dir / "summary.json"
    ne_summary_path = ne_dir / "summary.json"
    gate_result_path = dogfood_root / "gate-result.json"
    manifest_path = dogfood_root / "manifest.json"

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
        raise ValueError("synthetic gate fixture did not verify")
    write_json(gate_result_path, gate_result)
    manifest_module.write_manifest(
        manifest_path=manifest_path,
        run_id="20260519T010203Z",
        run_root=dogfood_root,
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
    return manifest_path


def create_synthetic_bundle(root: pathlib.Path) -> pathlib.Path:
    audit_module = load_audit_module()
    bundle_dir = root / "qualification-bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    create_synthetic_manifest(audit_module, bundle_dir)
    proof_root = bundle_dir / "supplemental-proofs"
    for key in sorted(audit_module.SUPPLEMENTAL_PROOF_KEYS):
        audit_module.write_supplemental_proof(
            proof_root,
            key,
            dict(audit_module.SUPPLEMENTAL_EVIDENCE_TEMPLATES[key]),
        )
    create_synthetic_source_manifest(proof_root, set(audit_module.SUPPLEMENTAL_PROOF_KEYS))
    return bundle_dir


def create_synthetic_source_manifest(proof_root: pathlib.Path, supported_keys: set[str]) -> pathlib.Path:
    source_root = proof_root / "source-artifacts"
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
                "receiptId": "simulation:qualification-fixture",
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
        coverage_inputs[key] = file_record(path, path.relative_to(proof_root))
    generated_proofs = {
        key: file_record(
            proof_root / "supplemental" / key / "proof.json",
            pathlib.Path("supplemental") / key / "proof.json",
        )
        for key in sorted(supported_keys)
    }
    source_manifest = {
        "schemaVersion": 1,
        "kind": SOURCE_MANIFEST_KIND,
        "generatedAt": "2026-05-19T00:00:00Z",
        "evidenceMode": "fixture",
        "proofRoot": ".",
        "sourceRoot": "source-artifacts",
        "expectedProofKeys": sorted(supported_keys),
        "policy": {
            "currentPolicyRef": str(current_policy.relative_to(proof_root)),
            "proposedPolicyRef": str(proposed_policy.relative_to(proof_root)),
            "proposedPolicyHash": file_sha256(proposed_policy),
            "policyEpoch": 7,
        },
        "sourceArtifacts": {
            "policyEvents": file_record(policy_events, policy_events.relative_to(proof_root)),
            "policyImpactJson": file_record(policy_impact, policy_impact.relative_to(proof_root)),
            "coverageInputs": coverage_inputs,
        },
        "generatedProofs": generated_proofs,
        "bridgeScripts": {
            key: file_record(SCRIPT_DIR / EXPECTED_BRIDGE_SCRIPTS[key])
            for key in sorted(supported_keys)
        },
    }
    manifest_path = proof_root / SOURCE_MANIFEST_NAME
    write_json(manifest_path, source_manifest)
    return manifest_path


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-ede-qualification-") as temp_dir:
        root = pathlib.Path(temp_dir)
        bundle_dir = create_synthetic_bundle(root)
        result = qualify_bundle(
            argparse.Namespace(
                bundle_dir=bundle_dir,
                manifest=None,
                proof_root=[],
                proof=[],
                output=None,
                allow_external_evidence=False,
                allow_external_output=False,
                metadata=[
                    "driver=self-test",
                    "macos_provider_replace_output=false",
                ],
            )
        )
        if result["ready"] is True:
            print("self-test expected complete synthetic bundle to fail production readiness", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if result["persistedAuditVerified"] is not True or result["sourceReverified"] is not True:
            print("self-test expected persisted audit source verification to pass", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if result["externalEvidence"]:
            print("self-test expected default synthetic bundle to be self-contained", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if result["externalOutput"] is not None:
            print("self-test expected default audit output to stay inside bundle", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if result["qualificationMetadata"].get("driver") != "self-test":
            print("self-test expected qualification metadata to be reported", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        persisted_audit = load_json_object(pathlib.Path(result["auditPath"]))
        persisted_metadata = (
            persisted_audit.get("provenance", {}).get("qualificationMetadata")
            if isinstance(persisted_audit.get("provenance"), dict)
            else None
        )
        if persisted_metadata != result["qualificationMetadata"]:
            print("self-test expected qualification metadata to be audit-bound", file=sys.stderr)
            print(json.dumps(persisted_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        persisted_bundle_dir = (
            persisted_audit.get("provenance", {}).get("qualificationBundleDir")
            if isinstance(persisted_audit.get("provenance"), dict)
            else None
        )
        if persisted_bundle_dir != result["bundleDir"]:
            print("self-test expected qualification bundle directory to be audit-bound", file=sys.stderr)
            print(json.dumps(persisted_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        persisted_external_flags = (
            persisted_audit.get("provenance", {})
            if isinstance(persisted_audit.get("provenance"), dict)
            else {}
        )
        if (
            persisted_external_flags.get("externalEvidenceAllowed")
            is not result["externalEvidenceAllowed"]
            or persisted_external_flags.get("externalOutputAllowed")
            is not result["externalOutputAllowed"]
        ):
            print("self-test expected external trust-boundary flags to be audit-bound", file=sys.stderr)
            print(json.dumps(persisted_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if not isinstance(result.get(SUMMARY_HASH_FIELD), str):
            print("self-test expected qualification summary digest", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        summary_path = root / "qualification-summary.json"
        write_json(summary_path, result)
        verified_summary = verify_qualification_summary_file(summary_path)
        if verified_summary["verified"] is not True:
            print("self-test expected qualification summary verification to pass", file=sys.stderr)
            print(json.dumps(verified_summary, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        bool_schema_summary = dict(result)
        bool_schema_summary["schemaVersion"] = True
        bool_schema_summary = attach_summary_digest(bool_schema_summary)
        write_json(summary_path, bool_schema_summary)
        bool_schema_summary_verification = verify_qualification_summary_file(summary_path)
        if (
            bool_schema_summary_verification["verified"] is True
            or "schemaVersion must be 1" not in bool_schema_summary_verification["failures"]
        ):
            print(
                "self-test expected hash-rebound boolean qualification summary schemaVersion to fail verification",
                file=sys.stderr,
            )
            print(json.dumps(bool_schema_summary_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        mutated_summary = dict(result)
        mutated_summary["ready"] = True
        write_json(summary_path, mutated_summary)
        invalid_summary = verify_qualification_summary_file(summary_path)
        if invalid_summary["verified"] is True:
            print("self-test expected mutated qualification summary to fail verification", file=sys.stderr)
            print(json.dumps(invalid_summary, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        rebound_summary = dict(result)
        rebound_summary["counts"] = {"verified": 999}
        rebound_summary = attach_summary_digest(rebound_summary)
        write_json(summary_path, rebound_summary)
        invalid_rebound_summary = verify_qualification_summary_file(summary_path)
        if invalid_rebound_summary["verified"] is True:
            print(
                "self-test expected hash-rebound qualification summary drift to fail verification",
                file=sys.stderr,
            )
            print(json.dumps(invalid_rebound_summary, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        rebound_bool_count_summary = dict(result)
        rebound_bool_count_summary["counts"] = {"verified": True}
        rebound_bool_count_summary = attach_summary_digest(rebound_bool_count_summary)
        write_json(summary_path, rebound_bool_count_summary)
        invalid_rebound_bool_count_summary = verify_qualification_summary_file(summary_path)
        bool_count_failure = "summary.counts must be an object of non-negative integer counts"
        if (
            invalid_rebound_bool_count_summary["verified"] is True
            or bool_count_failure not in invalid_rebound_bool_count_summary["failures"]
        ):
            print(
                "self-test expected hash-rebound boolean qualification summary count to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_bool_count_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        rebound_hidden_summary = dict(result)
        rebound_hidden_summary["operatorNote"] = "unverified"
        rebound_hidden_summary = attach_summary_digest(rebound_hidden_summary)
        write_json(summary_path, rebound_hidden_summary)
        invalid_rebound_hidden_summary = verify_qualification_summary_file(summary_path)
        if invalid_rebound_hidden_summary["verified"] is True:
            print(
                "self-test expected hash-rebound hidden qualification summary field to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_hidden_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        rebound_status_summary = dict(result)
        rebound_status_summary["failed"] = ["policy_simulation_impact"]
        rebound_status_summary["persistedAuditVerified"] = False
        rebound_status_summary = attach_summary_digest(rebound_status_summary)
        write_json(summary_path, rebound_status_summary)
        invalid_rebound_status_summary = verify_qualification_summary_file(summary_path)
        if invalid_rebound_status_summary["verified"] is True:
            print(
                "self-test expected hash-rebound qualification summary status drift to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_status_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        rebound_persisted_verification_summary = dict(result)
        rebound_persisted_verification = dict(
            rebound_persisted_verification_summary["persistedAuditVerification"]
        )
        rebound_persisted_verification["verified"] = False
        rebound_persisted_verification_summary[
            "persistedAuditVerification"
        ] = rebound_persisted_verification
        rebound_persisted_verification_summary = attach_summary_digest(
            rebound_persisted_verification_summary
        )
        write_json(summary_path, rebound_persisted_verification_summary)
        invalid_rebound_persisted_verification_summary = verify_qualification_summary_file(
            summary_path
        )
        if invalid_rebound_persisted_verification_summary["verified"] is True:
            print(
                "self-test expected hash-rebound persisted audit verification payload drift to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(
                    invalid_rebound_persisted_verification_summary,
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 1
        rebound_bundle_summary = dict(result)
        rebound_bundle_summary["bundleDir"] = str(root)
        rebound_bundle_summary = attach_summary_digest(rebound_bundle_summary)
        write_json(summary_path, rebound_bundle_summary)
        invalid_rebound_bundle_summary = verify_qualification_summary_file(summary_path)
        if invalid_rebound_bundle_summary["verified"] is True:
            print(
                "self-test expected hash-rebound qualification bundleDir drift to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_bundle_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        rebound_external_flag_summary = dict(result)
        rebound_external_flag_summary["externalEvidenceAllowed"] = True
        rebound_external_flag_summary["externalOutputAllowed"] = True
        rebound_external_flag_summary = attach_summary_digest(rebound_external_flag_summary)
        write_json(summary_path, rebound_external_flag_summary)
        invalid_rebound_external_flag_summary = verify_qualification_summary_file(summary_path)
        if invalid_rebound_external_flag_summary["verified"] is True:
            print(
                "self-test expected hash-rebound external trust-boundary flag drift to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_external_flag_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        rebound_metadata_summary = dict(result)
        rebound_metadata = dict(rebound_metadata_summary["qualificationMetadata"])
        rebound_metadata["driver"] = "tampered"
        rebound_metadata_summary["qualificationMetadata"] = rebound_metadata
        rebound_metadata_summary = attach_summary_digest(rebound_metadata_summary)
        write_json(summary_path, rebound_metadata_summary)
        invalid_rebound_metadata_summary = verify_qualification_summary_file(summary_path)
        if invalid_rebound_metadata_summary["verified"] is True:
            print(
                "self-test expected hash-rebound qualification metadata drift to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_metadata_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        rebound_source_field_summary = dict(result)
        rebound_source_manifest = dict(rebound_source_field_summary["supplementalSourceManifest"])
        rebound_source_manifest["operatorNote"] = "unverified"
        rebound_source_field_summary["supplementalSourceManifest"] = rebound_source_manifest
        rebound_source_field_summary = attach_summary_digest(rebound_source_field_summary)
        write_json(summary_path, rebound_source_field_summary)
        invalid_rebound_source_field_summary = verify_qualification_summary_file(summary_path)
        if invalid_rebound_source_field_summary["verified"] is True:
            print(
                "self-test expected hash-rebound hidden source-manifest summary field to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_source_field_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        rebound_source_bool_summary = dict(result)
        rebound_source_manifest = dict(rebound_source_bool_summary["supplementalSourceManifest"])
        rebound_source_manifest["verified"] = 1
        rebound_source_bool_summary["supplementalSourceManifest"] = rebound_source_manifest
        rebound_source_bool_summary = attach_summary_digest(rebound_source_bool_summary)
        write_json(summary_path, rebound_source_bool_summary)
        invalid_rebound_source_bool_summary = verify_qualification_summary_file(summary_path)
        source_bool_failure = "summary supplementalSourceManifest.verified must be a boolean"
        if (
            invalid_rebound_source_bool_summary["verified"] is True
            or source_bool_failure not in invalid_rebound_source_bool_summary["failures"]
        ):
            print(
                "self-test expected hash-rebound numeric source-manifest verified to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_source_bool_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        rebound_source_count_summary = dict(result)
        rebound_source_manifest = dict(rebound_source_count_summary["supplementalSourceManifest"])
        rebound_source_manifest["sourceArtifactCount"] = True
        rebound_source_count_summary["supplementalSourceManifest"] = rebound_source_manifest
        rebound_source_count_summary = attach_summary_digest(rebound_source_count_summary)
        write_json(summary_path, rebound_source_count_summary)
        invalid_rebound_source_count_summary = verify_qualification_summary_file(summary_path)
        source_count_failure = (
            "summary supplementalSourceManifest.sourceArtifactCount must be a non-negative integer"
        )
        if (
            invalid_rebound_source_count_summary["verified"] is True
            or source_count_failure not in invalid_rebound_source_count_summary["failures"]
        ):
            print(
                "self-test expected hash-rebound boolean source-manifest count to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_source_count_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        write_json(summary_path, result)
        source_manifest = result.get("supplementalSourceManifest")
        if not isinstance(source_manifest, dict) or source_manifest.get("verified") is not True:
            print("self-test expected supplemental source manifest to verify", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if source_manifest.get("sourceArtifactCount") != 8:
            print("self-test expected supplemental source manifest to cover staged source artifacts", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if source_manifest.get("generatedProofCount") != 7:
            print("self-test expected supplemental source manifest to bind generated proofs", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        persisted_source_manifest = persisted_audit.get("provenance", {}).get(
            "supplementalSourceManifest"
        )
        if not isinstance(persisted_source_manifest, dict):
            print("self-test expected persisted audit to record supplemental source manifest", file=sys.stderr)
            print(json.dumps(persisted_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if persisted_source_manifest.get("verified") is not True:
            print("self-test expected persisted audit to record verified source manifest", file=sys.stderr)
            print(json.dumps(persisted_audit, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        rebound_source_verified_summary = dict(result)
        rebound_source_manifest = dict(rebound_source_verified_summary["supplementalSourceManifest"])
        rebound_source_manifest["verified"] = False
        rebound_source_verified_summary["supplementalSourceManifest"] = rebound_source_manifest
        rebound_source_verified_summary = attach_summary_digest(rebound_source_verified_summary)
        write_json(summary_path, rebound_source_verified_summary)
        invalid_rebound_source_verified_summary = verify_qualification_summary_file(summary_path)
        if invalid_rebound_source_verified_summary["verified"] is True:
            print(
                "self-test expected hash-rebound supplemental source verified drift to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_source_verified_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        rebound_source_mode_summary = dict(result)
        rebound_source_manifest = dict(rebound_source_mode_summary["supplementalSourceManifest"])
        rebound_source_manifest["evidenceMode"] = "live"
        rebound_source_mode_summary["supplementalSourceManifest"] = rebound_source_manifest
        rebound_source_mode_summary = attach_summary_digest(rebound_source_mode_summary)
        write_json(summary_path, rebound_source_mode_summary)
        invalid_rebound_source_mode_summary = verify_qualification_summary_file(summary_path)
        if invalid_rebound_source_mode_summary["verified"] is True:
            print(
                "self-test expected hash-rebound supplemental source evidenceMode drift to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(invalid_rebound_source_mode_summary, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1

        persisted_source_drift_bundle = root / "persisted-source-drift-bundle"
        shutil.copytree(bundle_dir, persisted_source_drift_bundle)
        persisted_source_drift_result = qualify_bundle(
            argparse.Namespace(
                bundle_dir=persisted_source_drift_bundle,
                manifest=None,
                proof_root=[],
                proof=[],
                output=None,
                allow_external_evidence=False,
                allow_external_output=False,
                metadata=[],
            )
        )
        persisted_source_drift_file = (
            persisted_source_drift_bundle
            / "supplemental-proofs"
            / "source-artifacts"
            / "policy-events.jsonl"
        )
        with persisted_source_drift_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"schemaVersion": 1, "eventId": "evt-3"}) + "\n")
        persisted_source_drift_verification = load_audit_module().verify_audit_file(
            pathlib.Path(persisted_source_drift_result["auditPath"])
        )
        if persisted_source_drift_verification["verified"] is True:
            print(
                "self-test expected persisted audit verification to fail after staged source drift",
                file=sys.stderr,
            )
            print(
                json.dumps(persisted_source_drift_verification, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        persisted_source_drift_summary = root / "persisted-source-drift-summary.json"
        write_json(persisted_source_drift_summary, persisted_source_drift_result)
        persisted_source_drift_summary_verification = verify_qualification_summary_file(
            persisted_source_drift_summary
        )
        if persisted_source_drift_summary_verification["verified"] is True:
            print(
                "self-test expected qualification summary verification to fail after staged source drift",
                file=sys.stderr,
            )
            print(
                json.dumps(
                    persisted_source_drift_summary_verification,
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 1

        missing_source_manifest_bundle = root / "missing-source-manifest-bundle"
        shutil.copytree(bundle_dir, missing_source_manifest_bundle)
        (
            missing_source_manifest_bundle
            / "supplemental-proofs"
            / SOURCE_MANIFEST_NAME
        ).unlink()
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=missing_source_manifest_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected complete bundle without supplemental source manifest to fail",
                file=sys.stderr,
            )
            return 1

        bool_schema_source_bundle = root / "bool-schema-source-manifest-bundle"
        shutil.copytree(bundle_dir, bool_schema_source_bundle)
        bool_schema_manifest_path = (
            bool_schema_source_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        )
        bool_schema_manifest = load_json_object(bool_schema_manifest_path)
        bool_schema_manifest["schemaVersion"] = True
        write_json(bool_schema_manifest_path, bool_schema_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=bool_schema_source_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected boolean supplemental source schemaVersion to fail",
                file=sys.stderr,
            )
            return 1

        bool_size_source_bundle = root / "bool-byte-size-source-manifest-bundle"
        shutil.copytree(bundle_dir, bool_size_source_bundle)
        bool_size_manifest_path = (
            bool_size_source_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        )
        bool_size_manifest = load_json_object(bool_size_manifest_path)
        bool_size_manifest["sourceArtifacts"]["policyEvents"]["byteSize"] = True
        write_json(bool_size_manifest_path, bool_size_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=bool_size_source_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected boolean supplemental source byteSize to fail",
                file=sys.stderr,
            )
            return 1

        source_path_source_bundle = root / "source-path-source-manifest-bundle"
        shutil.copytree(bundle_dir, source_path_source_bundle)
        source_path_manifest_path = (
            source_path_source_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        )
        source_path_manifest = load_json_object(source_path_manifest_path)
        source_path_manifest["sourceArtifacts"]["policyEvents"]["sourcePath"] = str(
            root / "operator-origin-policy-events.jsonl"
        )
        write_json(source_path_manifest_path, source_path_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=source_path_source_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected supplemental source sourcePath to fail",
                file=sys.stderr,
            )
            return 1

        hidden_source_bundle = root / "hidden-field-source-manifest-bundle"
        shutil.copytree(bundle_dir, hidden_source_bundle)
        hidden_source_manifest_path = (
            hidden_source_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        )
        hidden_source_manifest = load_json_object(hidden_source_manifest_path)
        hidden_source_manifest["operatorNote"] = "unverified"
        write_json(hidden_source_manifest_path, hidden_source_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=hidden_source_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected hidden supplemental source manifest field to fail",
                file=sys.stderr,
            )
            return 1

        hidden_policy_bundle = root / "hidden-policy-source-manifest-bundle"
        shutil.copytree(bundle_dir, hidden_policy_bundle)
        hidden_policy_manifest_path = (
            hidden_policy_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        )
        hidden_policy_manifest = load_json_object(hidden_policy_manifest_path)
        hidden_policy_manifest["policy"]["reviewTicket"] = "unverified"
        write_json(hidden_policy_manifest_path, hidden_policy_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=hidden_policy_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected hidden supplemental source policy field to fail",
                file=sys.stderr,
            )
            return 1

        missing_generated_bundle = root / "missing-generated-source-manifest-bundle"
        shutil.copytree(bundle_dir, missing_generated_bundle)
        missing_generated_manifest_path = (
            missing_generated_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        )
        missing_generated_manifest = load_json_object(missing_generated_manifest_path)
        missing_generated_manifest.pop("generatedProofs", None)
        write_json(missing_generated_manifest_path, missing_generated_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=missing_generated_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected supplemental source manifest without generated proofs to fail",
                file=sys.stderr,
            )
            return 1

        missing_bridge_bundle = root / "missing-bridge-source-manifest-bundle"
        shutil.copytree(bundle_dir, missing_bridge_bundle)
        bridge_manifest_path = missing_bridge_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        bridge_manifest = load_json_object(bridge_manifest_path)
        bridge_manifest.pop("bridgeScripts", None)
        write_json(bridge_manifest_path, bridge_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=missing_bridge_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected supplemental source manifest without bridge scripts to fail",
                file=sys.stderr,
            )
            return 1

        wrong_bridge_bundle = root / "wrong-bridge-source-manifest-bundle"
        shutil.copytree(bundle_dir, wrong_bridge_bundle)
        wrong_bridge_manifest_path = wrong_bridge_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        wrong_bridge_manifest = load_json_object(wrong_bridge_manifest_path)
        wrong_bridge_manifest["bridgeScripts"]["policy_simulation_impact"] = file_record(
            READINESS_AUDIT
        )
        write_json(wrong_bridge_manifest_path, wrong_bridge_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=wrong_bridge_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected supplemental source manifest with wrong bridge script to fail",
                file=sys.stderr,
            )
            return 1
        invalid_policy_bundle = root / "invalid-policy-source-manifest-bundle"
        shutil.copytree(bundle_dir, invalid_policy_bundle)
        invalid_policy_manifest_path = invalid_policy_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        invalid_policy_manifest = load_json_object(invalid_policy_manifest_path)
        invalid_policy_manifest["policy"]["policyEpoch"] = 0
        write_json(invalid_policy_manifest_path, invalid_policy_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=invalid_policy_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected supplemental source manifest with invalid policy to fail",
                file=sys.stderr,
            )
            return 1
        mismatched_policy_bundle = root / "mismatched-policy-source-manifest-bundle"
        shutil.copytree(bundle_dir, mismatched_policy_bundle)
        mismatched_policy_manifest_path = (
            mismatched_policy_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        )
        mismatched_policy_manifest = load_json_object(mismatched_policy_manifest_path)
        mismatched_policy_manifest["policy"]["proposedPolicyHash"] = "sha256:" + ("ab" * 32)
        write_json(mismatched_policy_manifest_path, mismatched_policy_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=mismatched_policy_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected supplemental source manifest with mismatched policy hash to fail",
                file=sys.stderr,
            )
            return 1
        wrong_source_root_bundle = root / "wrong-source-root-bundle"
        shutil.copytree(bundle_dir, wrong_source_root_bundle)
        wrong_source_root_manifest_path = (
            wrong_source_root_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        )
        wrong_source_root_manifest = load_json_object(wrong_source_root_manifest_path)
        wrong_source_root_manifest["sourceRoot"] = "source-artifacts/policies"
        write_json(wrong_source_root_manifest_path, wrong_source_root_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=wrong_source_root_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print(
                "self-test expected supplemental source records outside sourceRoot to fail",
                file=sys.stderr,
            )
            return 1
        for bad_metadata in (
            ["driver=self-test", "driver=duplicate"],
            ["bad key=value"],
            ["empty="],
            ["control=line\nbreak"],
            [f"key{index}=value" for index in range(MAX_METADATA_ENTRIES + 1)],
        ):
            try:
                qualify_bundle(
                    argparse.Namespace(
                        bundle_dir=bundle_dir,
                        manifest=None,
                        proof_root=[],
                        proof=[],
                        output=None,
                        allow_external_evidence=False,
                        allow_external_output=False,
                        metadata=bad_metadata,
                    )
                )
            except ValueError:
                pass
            else:
                print("self-test expected invalid metadata to fail", file=sys.stderr)
                print(json.dumps({"metadata": bad_metadata}, indent=2, sort_keys=True), file=sys.stderr)
                return 1

        source_mutation_bundle = root / "source-mutation-bundle"
        shutil.copytree(bundle_dir, source_mutation_bundle)
        mutated_source = (
            source_mutation_bundle
            / "supplemental-proofs"
            / "source-artifacts"
            / "policy-events.jsonl"
        )
        with mutated_source.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"schemaVersion": 1, "eventId": "evt-2"}) + "\n")
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=source_mutation_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                    metadata=[],
                )
            )
        except ValueError:
            pass
        else:
            print("self-test expected supplemental source artifact mutation to fail", file=sys.stderr)
            return 1

        missing_bundle = root / "missing-proof-bundle"
        shutil.copytree(bundle_dir, missing_bundle)
        missing_path = next(
            missing_bundle.rglob("cross_platform_sensor_breadth/proof.json")
        )
        missing_path.unlink()
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=missing_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                )
            )
        except ValueError:
            pass
        else:
            print("self-test expected missing generated proof record target to fail", file=sys.stderr)
            return 1

        duplicate_bundle = root / "duplicate-proof-bundle"
        shutil.copytree(bundle_dir, duplicate_bundle)
        duplicate_src = next(
            duplicate_bundle.rglob("policy_simulation_impact/proof.json")
        )
        duplicate_dst = duplicate_bundle / "supplemental-proofs" / "duplicate-policy-proof.json"
        shutil.copy2(duplicate_src, duplicate_dst)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=duplicate_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                )
            )
        except ValueError:
            pass
        else:
            print("self-test expected duplicate supplemental proof discovery to fail", file=sys.stderr)
            return 1

        output_overlap_bundle = root / "output-overlap-bundle"
        shutil.copytree(bundle_dir, output_overlap_bundle)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=output_overlap_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=output_overlap_bundle / "dogfood" / "manifest.json",
                    allow_external_evidence=False,
                    allow_external_output=False,
                )
            )
        except ValueError:
            pass
        else:
            print("self-test expected audit output manifest overwrite to fail", file=sys.stderr)
            return 1

        output_proof_bundle = root / "output-proof-overlap-bundle"
        shutil.copytree(bundle_dir, output_proof_bundle)
        proof_output = next(output_proof_bundle.rglob("policy_simulation_impact/proof.json"))
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=output_proof_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=proof_output,
                    allow_external_evidence=False,
                    allow_external_output=False,
                )
            )
        except ValueError:
            pass
        else:
            print("self-test expected audit output proof overwrite to fail", file=sys.stderr)
            return 1

        external_output_bundle = root / "external-output-bundle"
        shutil.copytree(bundle_dir, external_output_bundle)
        external_output = root / "external-audit.json"
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=external_output_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[],
                    output=external_output,
                    allow_external_evidence=False,
                    allow_external_output=False,
                )
            )
        except ValueError:
            pass
        else:
            print("self-test expected external audit output to require opt-in", file=sys.stderr)
            return 1

        external_output_result = qualify_bundle(
            argparse.Namespace(
                bundle_dir=external_output_bundle,
                manifest=None,
                proof_root=[],
                proof=[],
                output=external_output,
                allow_external_evidence=False,
                allow_external_output=True,
            )
        )
        if external_output_result["ready"] is True:
            print("self-test expected external output fixture bundle to fail production readiness", file=sys.stderr)
            print(json.dumps(external_output_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if external_output_result["externalOutput"] != str(external_output.resolve()):
            print("self-test expected external audit output path to be reported", file=sys.stderr)
            print(json.dumps(external_output_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        external_output_summary = root / "external-output-summary.json"
        write_json(external_output_summary, external_output_result)
        external_output_summary_verification = verify_qualification_summary_file(
            external_output_summary
        )
        if external_output_summary_verification["verified"] is not True:
            print("self-test expected external output summary to verify", file=sys.stderr)
            print(
                json.dumps(external_output_summary_verification, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        hidden_external_output = dict(external_output_result)
        hidden_external_output["externalOutput"] = None
        hidden_external_output["externalOutputAllowed"] = False
        hidden_external_output = attach_summary_digest(hidden_external_output)
        write_json(external_output_summary, hidden_external_output)
        hidden_external_output_verification = verify_qualification_summary_file(
            external_output_summary
        )
        if hidden_external_output_verification["verified"] is True:
            print(
                "self-test expected hidden external output summary to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(hidden_external_output_verification, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1

        external_bundle = root / "external-proof-bundle"
        shutil.copytree(bundle_dir, external_bundle)
        external_root = root / "external-proofs"
        external_root.mkdir()
        internal_proof = next(
            external_bundle.rglob("cross_platform_sensor_breadth/proof.json")
        )
        external_proof_dir = external_root / "cross_platform_sensor_breadth"
        shutil.copytree(internal_proof.parent, external_proof_dir)
        external_proof = external_proof_dir / "proof.json"
        shutil.rmtree(internal_proof.parent)
        external_spec = f"cross_platform_sensor_breadth={external_proof}"
        external_source_manifest_path = external_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        external_source_manifest = load_json_object(external_source_manifest_path)
        external_source_manifest["generatedProofs"]["cross_platform_sensor_breadth"] = file_record(
            external_proof
        )
        write_json(external_source_manifest_path, external_source_manifest)
        try:
            qualify_bundle(
                argparse.Namespace(
                    bundle_dir=external_bundle,
                    manifest=None,
                    proof_root=[],
                    proof=[external_spec],
                    output=None,
                    allow_external_evidence=False,
                    allow_external_output=False,
                )
            )
        except ValueError:
            pass
        else:
            print("self-test expected external proof to require opt-in", file=sys.stderr)
            return 1

        external_result = qualify_bundle(
            argparse.Namespace(
                bundle_dir=external_bundle,
                manifest=None,
                proof_root=[],
                proof=[external_spec],
                output=None,
                allow_external_evidence=True,
                allow_external_output=False,
            )
        )
        if external_result["ready"] is True:
            print("self-test expected external proof fixture bundle to fail production readiness", file=sys.stderr)
            print(json.dumps(external_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if external_result["externalEvidenceAllowed"] is not True:
            print("self-test expected external evidence opt-in to be reported", file=sys.stderr)
            print(json.dumps(external_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if "proof:cross_platform_sensor_breadth" not in external_result["externalEvidence"]:
            print("self-test expected external proof path to be reported", file=sys.stderr)
            print(json.dumps(external_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        external_summary = root / "external-proof-summary.json"
        write_json(external_summary, external_result)
        external_summary_verification = verify_qualification_summary_file(external_summary)
        if external_summary_verification["verified"] is not True:
            print("self-test expected external proof summary to verify", file=sys.stderr)
            print(
                json.dumps(external_summary_verification, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        hidden_external = dict(external_result)
        hidden_external["externalEvidence"] = {}
        hidden_external["externalEvidenceAllowed"] = False
        hidden_external = attach_summary_digest(hidden_external)
        write_json(external_summary, hidden_external)
        hidden_external_verification = verify_qualification_summary_file(external_summary)
        if hidden_external_verification["verified"] is True:
            print(
                "self-test expected hidden external proof summary to fail verification",
                file=sys.stderr,
            )
            print(json.dumps(hidden_external_verification, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        external_source_bundle = root / "external-source-bundle"
        shutil.copytree(bundle_dir, external_source_bundle)
        external_source_root = root / "external-source-artifacts"
        external_source_root.mkdir()
        source_manifest_path = external_source_bundle / "supplemental-proofs" / SOURCE_MANIFEST_NAME
        internal_policy_events = (
            external_source_bundle
            / "supplemental-proofs"
            / "source-artifacts"
            / "policy-events.jsonl"
        )
        external_policy_events = external_source_root / "policy-events.jsonl"
        shutil.copy2(internal_policy_events, external_policy_events)
        source_manifest_payload = load_json_object(source_manifest_path)
        source_artifacts = source_manifest_payload.get("sourceArtifacts")
        if not isinstance(source_artifacts, dict):
            print("self-test expected sourceArtifacts in source manifest", file=sys.stderr)
            return 1
        source_artifacts["policyEvents"] = file_record(external_policy_events)
        write_json(source_manifest_path, source_manifest_payload)
        external_source_result = qualify_bundle(
            argparse.Namespace(
                bundle_dir=external_source_bundle,
                manifest=None,
                proof_root=[],
                proof=[],
                output=None,
                allow_external_evidence=True,
                allow_external_output=False,
                metadata=[],
            )
        )
        external_source_evidence = external_source_result["externalEvidence"]
        if external_source_evidence.get("source:policyEvents") != str(
            external_policy_events.resolve()
        ):
            print("self-test expected external staged source path to be reported", file=sys.stderr)
            print(json.dumps(external_source_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        external_source_summary = root / "external-source-summary.json"
        write_json(external_source_summary, external_source_result)
        external_source_summary_verification = verify_qualification_summary_file(
            external_source_summary
        )
        if external_source_summary_verification["verified"] is not True:
            print("self-test expected external staged source summary to verify", file=sys.stderr)
            print(
                json.dumps(external_source_summary_verification, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        hidden_external_source = dict(external_source_result)
        hidden_external_source_evidence = dict(hidden_external_source["externalEvidence"])
        hidden_external_source_evidence.pop("source:policyEvents", None)
        hidden_external_source["externalEvidence"] = hidden_external_source_evidence
        hidden_source_manifest = dict(hidden_external_source["supplementalSourceManifest"])
        hidden_source_manifest["externalSourceArtifacts"] = {}
        hidden_external_source["supplementalSourceManifest"] = hidden_source_manifest
        hidden_external_source = attach_summary_digest(hidden_external_source)
        write_json(external_source_summary, hidden_external_source)
        hidden_external_source_verification = verify_qualification_summary_file(
            external_source_summary
        )
        if hidden_external_source_verification["verified"] is True:
            print(
                "self-test expected hidden external staged source summary to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(hidden_external_source_verification, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1
        tampered_policy_source = dict(external_source_result)
        tampered_policy_manifest = dict(tampered_policy_source["supplementalSourceManifest"])
        tampered_policy = dict(tampered_policy_manifest["policy"])
        tampered_policy["policyEpoch"] = tampered_policy["policyEpoch"] + 1
        tampered_policy_manifest["policy"] = tampered_policy
        tampered_policy_source["supplementalSourceManifest"] = tampered_policy_manifest
        tampered_policy_source = attach_summary_digest(tampered_policy_source)
        write_json(external_source_summary, tampered_policy_source)
        tampered_policy_source_verification = verify_qualification_summary_file(
            external_source_summary
        )
        if tampered_policy_source_verification["verified"] is True:
            print(
                "self-test expected tampered source policy summary to fail verification",
                file=sys.stderr,
            )
            print(
                json.dumps(tampered_policy_source_verification, indent=2, sort_keys=True),
                file=sys.stderr,
            )
            return 1

    print("endpoint decision engine qualification bundle self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path)
    parser.add_argument("--proof-root", action="append", default=[], type=pathlib.Path)
    parser.add_argument(
        "--proof",
        action="append",
        default=[],
        metavar="KEY=PATH",
        help="Explicit supplemental proof path. May be repeated.",
    )
    parser.add_argument(
        "--allow-external-evidence",
        action="store_true",
        help="Allow --manifest, --proof-root, or --proof paths outside --bundle-dir.",
    )
    parser.add_argument(
        "--allow-external-output",
        action="store_true",
        help="Allow --output to write the persisted audit outside --bundle-dir.",
    )
    parser.add_argument(
        "--metadata",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Driver/operator metadata to include in the qualification summary.",
    )
    parser.add_argument("--output", type=pathlib.Path)
    parser.add_argument(
        "--verify-summary",
        type=pathlib.Path,
        help="Verify a persisted qualification summary JSON and its referenced readiness audit.",
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if args.verify_summary is not None:
        result = verify_qualification_summary_file(args.verify_summary)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["verified"] else 1
    if args.bundle_dir is None:
        parser.error("--bundle-dir is required")

    try:
        result = qualify_bundle(args)
    except ValueError as exc:
        print(f"qualification bundle failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ready"] and result["persistedAuditVerified"] else 1


if __name__ == "__main__":
    sys.exit(main())
