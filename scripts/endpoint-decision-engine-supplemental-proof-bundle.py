#!/usr/bin/env python3
"""Build the strict supplemental proof root for Endpoint Decision Engine qualification."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
EXPECTED_PROOFS = {
    "policy_simulation_impact": "policy-simulation-impact-proof.py",
    "ai_agent_developer_workstation": "ai-agent-developer-workstation-proof.py",
    "endpoint_deception": "endpoint-deception-proof.py",
    "supply_chain_runtime_guard": "supply-chain-runtime-guard-proof.py",
    "privacy_preserving_telemetry": "privacy-preserving-telemetry-proof.py",
    "operator_workflows": "operator-workflows-proof.py",
    "cross_platform_sensor_breadth": "cross-platform-sensor-breadth-proof.py",
}
SOURCE_MANIFEST_NAME = "supplemental-proof-source-manifest.json"
SOURCE_MANIFEST_KIND = "clawdstrike.endpoint_decision_engine.supplemental_proof_source_manifest.v1"
SOURCE_ARTIFACTS_DIR = "source-artifacts"
SOURCE_COVERAGE_FILENAMES = {
    "ai_agent_developer_workstation": "ai-agent-coverage.json",
    "endpoint_deception": "endpoint-deception-coverage.json",
    "supply_chain_runtime_guard": "supply-chain-coverage.json",
    "privacy_preserving_telemetry": "privacy-coverage.json",
    "operator_workflows": "operator-workflows-coverage.json",
    "cross_platform_sensor_breadth": "sensor-breadth-coverage.json",
}


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
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


def copy_source_artifact(
    source: pathlib.Path,
    target: pathlib.Path,
    base_dir: pathlib.Path,
) -> dict[str, Any]:
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return file_record(target, target.relative_to(base_dir))


def require_file(path: pathlib.Path, label: str) -> pathlib.Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise ValueError(f"{label} must reference an existing file: {resolved}")
    return resolved


def require_sha256(value: str | None, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:") or len(value) != 71:
        raise ValueError(f"{label} must be sha256:<64-hex>")
    try:
        int(value.removeprefix("sha256:"), 16)
    except ValueError as exc:
        raise ValueError(f"{label} must be sha256:<64-hex>") from exc
    return value


def enforce_local_policy_hash(policy_ref: str, policy_hash: str) -> None:
    policy_path = pathlib.Path(policy_ref).expanduser()
    if not policy_path.is_file():
        return
    actual_hash = file_sha256(policy_path.resolve())
    if actual_hash != policy_hash:
        raise ValueError(
            "--policy-proposed-hash must match local --policy-proposed-ref file"
        )


def require_non_empty_text(value: str | None, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty")
    return value


def validate_output_dir(path: pathlib.Path) -> pathlib.Path:
    resolved = path.expanduser().resolve()
    if resolved.exists() and not resolved.is_dir():
        raise ValueError(f"--out-dir exists but is not a directory: {resolved}")
    parent = resolved.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    if not parent.is_dir():
        raise ValueError(f"--out-dir parent exists but is not a directory: {parent}")
    if not os.access(parent, os.W_OK):
        raise ValueError(f"--out-dir parent is not writable: {parent}")
    return resolved


def safe_prepare_output_dir(path: pathlib.Path, replace_output: bool) -> pathlib.Path:
    resolved = validate_output_dir(path)
    protected_dirs = {
        pathlib.Path(resolved.anchor).resolve(),
        pathlib.Path.home().resolve(),
        pathlib.Path.cwd().resolve(),
        SCRIPT_DIR.resolve(),
        SCRIPT_DIR.parent.resolve(),
    }
    if resolved in protected_dirs:
        raise ValueError(f"--out-dir refuses protected directory: {resolved}")

    if resolved.exists():
        existing = list(resolved.iterdir())
        if existing and not replace_output:
            raise ValueError("--out-dir must be empty or pass --replace-output")
        if replace_output:
            for child in existing:
                if child.is_symlink() or child.is_file():
                    child.unlink()
                elif child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved


def load_module(path: pathlib.Path) -> Any:
    spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_bridge(key: str, argv: list[str]) -> dict[str, Any]:
    completed = subprocess.run(argv, check=False, text=True, capture_output=True)
    if completed.returncode != 0:
        raise ValueError(
            f"{key} bridge failed with exit code {completed.returncode}: "
            + (completed.stderr.strip() or completed.stdout.strip())
        )
    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{key} bridge did not return JSON: {exc}") from exc
    validation = result.get("proofValidation")
    if not isinstance(validation, dict) or validation.get("status") != "verified":
        raise ValueError(f"{key} bridge did not generate a verified proof")
    proof_path = result.get("proofPath")
    if not isinstance(proof_path, str) or not pathlib.Path(proof_path).is_file():
        raise ValueError(f"{key} bridge did not report an existing proofPath")
    return result


def proof_key_from_file(path: pathlib.Path) -> str | None:
    try:
        payload = load_json_object(path)
    except (OSError, json.JSONDecodeError, ValueError):
        return None
    key = payload.get("key")
    if isinstance(key, str) and key in EXPECTED_PROOFS and payload.get("verified") is True:
        return key
    return None


def discover_verified_proofs(root: pathlib.Path) -> dict[str, pathlib.Path]:
    proofs: dict[str, pathlib.Path] = {}
    for path in sorted(root.rglob("*.json")):
        key = proof_key_from_file(path)
        if key is None:
            continue
        if key in proofs:
            raise ValueError(f"duplicate generated proof for {key}: {proofs[key]} and {path}")
        proofs[key] = path
    missing = sorted(set(EXPECTED_PROOFS) - set(proofs))
    if missing:
        raise ValueError("supplemental proof bundle missing generated proofs: " + ", ".join(missing))
    return proofs


def validate_inputs(args: argparse.Namespace) -> tuple[
    pathlib.Path,
    pathlib.Path,
    pathlib.Path,
    dict[str, pathlib.Path],
]:
    out_dir = validate_output_dir(args.out_dir)
    policy_events = require_file(args.policy_events, "--policy-events")
    policy_impact = require_file(args.policy_impact_json, "--policy-impact-json")
    if policy_events.stat().st_size < 1:
        raise ValueError("--policy-events must not be empty")
    load_json_object(policy_impact)
    coverage_paths = {
        "ai_agent_developer_workstation": require_file(
            args.ai_agent_coverage_json,
            "--ai-agent-coverage-json",
        ),
        "endpoint_deception": require_file(
            args.endpoint_deception_coverage_json,
            "--endpoint-deception-coverage-json",
        ),
        "supply_chain_runtime_guard": require_file(
            args.supply_chain_coverage_json,
            "--supply-chain-coverage-json",
        ),
        "privacy_preserving_telemetry": require_file(
            args.privacy_coverage_json,
            "--privacy-coverage-json",
        ),
        "operator_workflows": require_file(
            args.operator_workflows_coverage_json,
            "--operator-workflows-coverage-json",
        ),
        "cross_platform_sensor_breadth": require_file(
            args.sensor_breadth_coverage_json,
            "--sensor-breadth-coverage-json",
        ),
    }
    for key, path in coverage_paths.items():
        try:
            load_json_object(path)
        except ValueError as exc:
            raise ValueError(f"{key} coverage JSON is invalid: {exc}") from exc

    if args.policy_epoch < 1:
        raise ValueError("--policy-epoch must be a positive integer")
    args.policy_current_ref = require_non_empty_text(
        args.policy_current_ref,
        "--policy-current-ref",
    )
    args.policy_proposed_ref = require_non_empty_text(
        args.policy_proposed_ref,
        "--policy-proposed-ref",
    )
    args.policy_proposed_hash = require_sha256(
        args.policy_proposed_hash,
        "--policy-proposed-hash",
    )
    enforce_local_policy_hash(args.policy_proposed_ref, args.policy_proposed_hash)
    return out_dir, policy_events, policy_impact, coverage_paths


def stage_source_artifacts(
    out_dir: pathlib.Path,
    policy_events: pathlib.Path,
    policy_impact: pathlib.Path,
    coverage_paths: dict[str, pathlib.Path],
) -> tuple[pathlib.Path, pathlib.Path, dict[str, pathlib.Path], dict[str, Any]]:
    source_root = out_dir / SOURCE_ARTIFACTS_DIR
    staged_policy_events = source_root / "policy-events.jsonl"
    staged_policy_impact = source_root / "policy-impact.json"
    staged_coverage: dict[str, pathlib.Path] = {}
    coverage_records: dict[str, Any] = {}

    policy_events_record = copy_source_artifact(policy_events, staged_policy_events, out_dir)
    policy_impact_record = copy_source_artifact(policy_impact, staged_policy_impact, out_dir)
    for key, source in sorted(coverage_paths.items()):
        target = source_root / SOURCE_COVERAGE_FILENAMES[key]
        staged_coverage[key] = target
        coverage_records[key] = copy_source_artifact(source, target, out_dir)

    source_records = {
        "policyEvents": policy_events_record,
        "policyImpactJson": policy_impact_record,
        "coverageInputs": coverage_records,
    }
    return staged_policy_events, staged_policy_impact, staged_coverage, source_records


def write_source_manifest(
    out_dir: pathlib.Path,
    source_records: dict[str, Any],
    proof_records: dict[str, Any],
    args: argparse.Namespace,
) -> pathlib.Path:
    payload = {
        "schemaVersion": 1,
        "kind": SOURCE_MANIFEST_KIND,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "evidenceMode": args.evidence_mode,
        "proofRoot": ".",
        "sourceRoot": SOURCE_ARTIFACTS_DIR,
        "expectedProofKeys": sorted(EXPECTED_PROOFS),
        "policy": {
            "currentPolicyRef": args.policy_current_ref,
            "proposedPolicyRef": args.policy_proposed_ref,
            "proposedPolicyHash": args.policy_proposed_hash,
            "policyEpoch": args.policy_epoch,
        },
        "sourceArtifacts": source_records,
        "generatedProofs": proof_records,
        "bridgeScripts": {
            key: file_record(SCRIPT_DIR / script_name)
            for key, script_name in sorted(EXPECTED_PROOFS.items())
        },
    }
    manifest_path = out_dir / SOURCE_MANIFEST_NAME
    write_json(manifest_path, payload)
    return manifest_path


def preflight_bundle(args: argparse.Namespace) -> dict[str, Any]:
    out_dir, policy_events, policy_impact, coverage_paths = validate_inputs(args)
    with tempfile.TemporaryDirectory(prefix="clawdstrike-ede-proof-preflight-") as temp_dir:
        dry_run_args = argparse.Namespace(**vars(args))
        dry_run_args.out_dir = pathlib.Path(temp_dir) / "supplemental-proofs"
        dry_run_args.replace_output = True
        dry_run = build_bundle(dry_run_args)
        proof_keys = sorted(dry_run.get("proofs", {}))
        dry_run_source_manifest = isinstance(dry_run.get("sourceManifestPath"), str)
    return {
        "schemaVersion": 1,
        "preflight": True,
        "proofRoot": str(out_dir),
        "policyEvents": str(policy_events),
        "policyImpactJson": str(policy_impact),
        "coverageInputs": {key: str(path) for key, path in sorted(coverage_paths.items())},
        "dryRunProofKeys": proof_keys,
        "dryRunProofCount": len(proof_keys),
        "dryRunSourceManifest": dry_run_source_manifest,
    }


def build_bundle(args: argparse.Namespace) -> dict[str, Any]:
    out_dir, policy_events, policy_impact, coverage_paths = validate_inputs(args)
    out_dir = safe_prepare_output_dir(
        out_dir,
        bool(getattr(args, "replace_output", False)),
    )
    staged_policy_events, staged_policy_impact, staged_coverage_paths, source_records = (
        stage_source_artifacts(out_dir, policy_events, policy_impact, coverage_paths)
    )

    generated: dict[str, dict[str, Any]] = {}
    policy_dir = out_dir / "policy_simulation_impact"
    policy_argv = [
        sys.executable,
        str(SCRIPT_DIR / EXPECTED_PROOFS["policy_simulation_impact"]),
        "--out-dir",
        str(policy_dir),
        "--events",
        str(staged_policy_events),
        "--impact-json",
        str(staged_policy_impact),
        "--policy-epoch",
        str(args.policy_epoch),
        "--current-policy-ref",
        args.policy_current_ref,
        "--proposed-policy-ref",
        args.policy_proposed_ref,
        "--proposed-policy-hash",
        args.policy_proposed_hash,
    ]
    generated["policy_simulation_impact"] = run_bridge("policy_simulation_impact", policy_argv)

    for key, coverage_path in staged_coverage_paths.items():
        generated[key] = run_bridge(
            key,
            [
                sys.executable,
                str(SCRIPT_DIR / EXPECTED_PROOFS[key]),
                "--out-dir",
                str(out_dir / key),
                "--coverage-json",
                str(coverage_path),
            ],
        )

    proofs = discover_verified_proofs(out_dir)
    proof_records = {
        key: file_record(path, path.relative_to(out_dir))
        for key, path in sorted(proofs.items())
    }
    source_manifest_path = write_source_manifest(out_dir, source_records, proof_records, args)
    summary = {
        "schemaVersion": 1,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "proofRoot": str(out_dir),
        "sourceManifestPath": str(source_manifest_path),
        "sourceManifestSha256": file_sha256(source_manifest_path),
        "proofs": {key: str(path) for key, path in sorted(proofs.items())},
        "bridgeSummaries": {
            key: result.get("summaryPath")
            for key, result in sorted(generated.items())
            if isinstance(result.get("summaryPath"), str)
        },
    }
    summary_path = out_dir / "supplemental-proof-bundle-summary.json"
    write_json(summary_path, summary)
    summary["summaryPath"] = str(summary_path)
    return summary


def fixture_policy_inputs(root: pathlib.Path) -> dict[str, pathlib.Path | str]:
    events = root / "policy-events.jsonl"
    current_policy = root / "current-policy.yaml"
    proposed_policy = root / "proposed-policy.yaml"
    impact_json = root / "policy-impact.json"
    events.write_text(
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
    current_policy.write_text("schemaVersion: 1\nname: current\n", encoding="utf-8")
    proposed_policy.write_text("schemaVersion: 1\nname: proposed\n", encoding="utf-8")
    write_json(
        impact_json,
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
                    "receiptId": "simulation:supplemental-fixture",
                    "metadata": {
                        "endpointDecision": {
                            "receiptFamily": "simulation",
                        },
                    },
                },
                "exit_code": 0,
            },
        )
    return {
        "events": events,
        "currentPolicyRef": str(current_policy),
        "proposedPolicyRef": str(proposed_policy),
        "proposedPolicyHash": file_sha256(proposed_policy),
        "impactJson": impact_json,
    }


def fixture_coverage_file(root: pathlib.Path, script_name: str, filename: str) -> pathlib.Path:
    module = load_module(SCRIPT_DIR / script_name)
    if not hasattr(module, "fixture_coverage"):
        raise ValueError(f"{script_name} does not expose fixture_coverage")
    path = root / filename
    write_json(path, module.fixture_coverage())
    return path


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-ede-proof-bundle-") as temp_dir:
        root = pathlib.Path(temp_dir)
        policy = fixture_policy_inputs(root)
        args = argparse.Namespace(
            out_dir=root / "supplemental-proofs",
            policy_events=policy["events"],
            policy_impact_json=policy["impactJson"],
            policy_current_ref=policy["currentPolicyRef"],
            policy_proposed_ref=policy["proposedPolicyRef"],
            policy_proposed_hash=policy["proposedPolicyHash"],
            policy_epoch=7,
            ai_agent_coverage_json=fixture_coverage_file(
                root,
                EXPECTED_PROOFS["ai_agent_developer_workstation"],
                "ai-agent-coverage.json",
            ),
            endpoint_deception_coverage_json=fixture_coverage_file(
                root,
                EXPECTED_PROOFS["endpoint_deception"],
                "endpoint-deception-coverage.json",
            ),
            supply_chain_coverage_json=fixture_coverage_file(
                root,
                EXPECTED_PROOFS["supply_chain_runtime_guard"],
                "supply-chain-coverage.json",
            ),
            privacy_coverage_json=fixture_coverage_file(
                root,
                EXPECTED_PROOFS["privacy_preserving_telemetry"],
                "privacy-coverage.json",
            ),
            operator_workflows_coverage_json=fixture_coverage_file(
                root,
                EXPECTED_PROOFS["operator_workflows"],
                "operator-workflows-coverage.json",
            ),
            sensor_breadth_coverage_json=fixture_coverage_file(
                root,
                EXPECTED_PROOFS["cross_platform_sensor_breadth"],
                "sensor-breadth-coverage.json",
            ),
            evidence_mode="fixture",
            replace_output=False,
        )
        preflight_args = argparse.Namespace(**vars(args))
        preflight_args.out_dir = root / "preflight-proofs"
        preflight_result = preflight_bundle(preflight_args)
        if preflight_result["preflight"] is not True:
            print("self-test expected preflight result", file=sys.stderr)
            print(json.dumps(preflight_result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if preflight_args.out_dir.exists():
            print("self-test expected preflight not to create output directory", file=sys.stderr)
            return 1

        result = build_bundle(args)
        if sorted(result["proofs"]) != sorted(EXPECTED_PROOFS):
            print("self-test expected one generated proof for every key", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        source_manifest = load_json_object(pathlib.Path(result["sourceManifestPath"]))
        if source_manifest.get("kind") != SOURCE_MANIFEST_KIND:
            print("self-test expected source manifest kind", file=sys.stderr)
            print(json.dumps(source_manifest, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if source_manifest.get("proofRoot") != "." or source_manifest.get("sourceRoot") != SOURCE_ARTIFACTS_DIR:
            print("self-test expected relocatable source manifest roots", file=sys.stderr)
            print(json.dumps(source_manifest, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        staged_policy_events = args.out_dir / SOURCE_ARTIFACTS_DIR / "policy-events.jsonl"
        manifest_policy_events = source_manifest["sourceArtifacts"]["policyEvents"]
        if manifest_policy_events.get("sha256") != file_sha256(staged_policy_events):
            print("self-test expected source manifest hash to match staged policy events", file=sys.stderr)
            return 1
        if manifest_policy_events.get("sourcePath") is not None:
            print("self-test expected source manifest to omit unverified sourcePath", file=sys.stderr)
            print(json.dumps(source_manifest, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if sorted(source_manifest["sourceArtifacts"]["coverageInputs"]) != sorted(
            set(EXPECTED_PROOFS) - {"policy_simulation_impact"}
        ):
            print(
                "self-test expected source manifest to cover every supplemental coverage input",
                file=sys.stderr,
            )
            print(json.dumps(source_manifest, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if sorted(source_manifest.get("generatedProofs", {})) != sorted(EXPECTED_PROOFS):
            print("self-test expected source manifest to bind every generated proof", file=sys.stderr)
            print(json.dumps(source_manifest, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        try:
            build_bundle(args)
        except ValueError:
            pass
        else:
            print("self-test expected non-empty output directory to fail", file=sys.stderr)
            return 1

        replace_args = argparse.Namespace(**vars(args))
        replace_args.replace_output = True
        result = build_bundle(replace_args)
        if sorted(result["proofs"]) != sorted(EXPECTED_PROOFS):
            print("self-test expected replace-output to regenerate every key", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        missing_args = argparse.Namespace(**vars(args))
        missing_args.out_dir = root / "missing-source-proofs"
        missing_args.sensor_breadth_coverage_json = root / "missing-sensor-breadth.json"
        try:
            build_bundle(missing_args)
        except ValueError:
            pass
        else:
            print("self-test expected missing source coverage to fail", file=sys.stderr)
            return 1

        bad_policy_args = argparse.Namespace(**vars(args))
        bad_policy_args.out_dir = root / "bad-policy-proofs"
        bad_policy_args.policy_proposed_hash = "not-a-sha256"
        try:
            build_bundle(bad_policy_args)
        except ValueError:
            pass
        else:
            print("self-test expected invalid source policy hash to fail", file=sys.stderr)
            return 1

        mismatched_policy_args = argparse.Namespace(**vars(args))
        mismatched_policy_args.out_dir = root / "mismatched-policy-proofs"
        mismatched_policy_args.policy_proposed_hash = "sha256:" + ("ab" * 32)
        try:
            build_bundle(mismatched_policy_args)
        except ValueError:
            pass
        else:
            print("self-test expected mismatched local proposed policy hash to fail", file=sys.stderr)
            return 1

        blank_policy_args = argparse.Namespace(**vars(args))
        blank_policy_args.out_dir = root / "blank-policy-proofs"
        blank_policy_args.policy_current_ref = ""
        try:
            build_bundle(blank_policy_args)
        except ValueError:
            pass
        else:
            print("self-test expected blank source policy reference to fail", file=sys.stderr)
            return 1

        duplicate = next((args.out_dir / "policy_simulation_impact").glob("*-proof.json"))
        duplicate_target = args.out_dir / "duplicate-policy-proof.json"
        duplicate_target.write_text(duplicate.read_text(encoding="utf-8"), encoding="utf-8")
        try:
            discover_verified_proofs(args.out_dir)
        except ValueError:
            pass
        else:
            print("self-test expected duplicate generated proof detection to fail", file=sys.stderr)
            return 1

    print("endpoint decision engine supplemental proof bundle self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=pathlib.Path)
    parser.add_argument("--policy-events", type=pathlib.Path)
    parser.add_argument("--policy-impact-json", type=pathlib.Path)
    parser.add_argument("--policy-current-ref", default="captured-current-policy")
    parser.add_argument("--policy-proposed-ref", default="captured-proposed-policy")
    parser.add_argument("--policy-proposed-hash")
    parser.add_argument("--policy-epoch", type=int, default=0)
    parser.add_argument("--ai-agent-coverage-json", type=pathlib.Path)
    parser.add_argument("--endpoint-deception-coverage-json", type=pathlib.Path)
    parser.add_argument("--supply-chain-coverage-json", type=pathlib.Path)
    parser.add_argument("--privacy-coverage-json", type=pathlib.Path)
    parser.add_argument("--operator-workflows-coverage-json", type=pathlib.Path)
    parser.add_argument("--sensor-breadth-coverage-json", type=pathlib.Path)
    parser.add_argument("--evidence-mode", choices=("live", "fixture"), default="live")
    parser.add_argument("--replace-output", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()
    if args.out_dir is None:
        parser.error("--out-dir is required")
    missing_args = [
        name
        for name in (
            "policy_events",
            "policy_impact_json",
            "ai_agent_coverage_json",
            "endpoint_deception_coverage_json",
            "supply_chain_coverage_json",
            "privacy_coverage_json",
            "operator_workflows_coverage_json",
            "sensor_breadth_coverage_json",
        )
        if getattr(args, name) is None
    ]
    if missing_args:
        parser.error(
            "missing required evidence inputs: "
            + ", ".join("--" + item.replace("_", "-") for item in missing_args)
        )
    if args.preflight:
        try:
            result = preflight_bundle(args)
        except ValueError as exc:
            print(f"supplemental proof bundle preflight failed: {exc}", file=sys.stderr)
            return 1
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    try:
        result = build_bundle(args)
    except ValueError as exc:
        print(f"supplemental proof bundle failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
