#!/usr/bin/env python3
"""Generate a strict cross-platform sensor-breadth supplemental proof."""

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
REQUIRED_SENSORS = {
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
REQUIRED_PLATFORMS = {"macos", "linux", "windows"}
REQUIRED_INGESTION_ROUTES = {
    "/api/v1/agent/edr/developer-activity",
    "/api/v1/agent/edr/package-manager/events",
    "/api/v1/agent/edr/endpoint-security/events",
    "/api/v1/agent/edr/network-extension/events",
    "/api/v1/agent/edr/policy-events",
}
REQUIRED_EVENT_KINDS = {
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
REQUIRED_IDENTITY_FIELDS = {
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


def normalize_platform(value: str) -> str:
    normalized = value.strip().lower().replace("darwin", "macos")
    aliases = {
        "osx": "macos",
        "win32": "windows",
        "win": "windows",
    }
    return aliases.get(normalized, normalized)


def require_complete_coverage(
    sensors: set[str],
    platforms: set[str],
    routes: set[str],
    event_kinds: set[str],
    identity_fields: set[str],
) -> None:
    missing = {
        "sensors": sorted(REQUIRED_SENSORS - sensors),
        "sensorPlatforms": sorted(REQUIRED_PLATFORMS - platforms),
        "ingestionRoutes": sorted(REQUIRED_INGESTION_ROUTES - routes),
        "eventKinds": sorted(REQUIRED_EVENT_KINDS - event_kinds),
        "identityFields": sorted(REQUIRED_IDENTITY_FIELDS - identity_fields),
    }
    missing = {key: values for key, values in missing.items() if values}
    if missing:
        raise ValueError("sensor breadth coverage missing required evidence: " + json.dumps(missing))


def require_verified_rows(rows: list[dict[str, Any]], label: str) -> None:
    unverified = [
        str(row.get("sensor") or row.get("eventKind") or row.get("route") or index)
        for index, row in enumerate(rows)
        if row.get("verified") is not True
    ]
    if unverified:
        raise ValueError(f"{label} rows must be verified: " + ", ".join(unverified))


def require_graph_persistence(graph_evidence: dict[str, Any]) -> tuple[set[str], set[str]]:
    node_kinds = values_from_row(graph_evidence, "nodeKind", "nodeKinds")
    edge_kinds = values_from_row(graph_evidence, "edgeKind", "edgeKinds")
    missing = {
        "graphNodeKinds": sorted(REQUIRED_GRAPH_NODE_KINDS - node_kinds),
        "graphEdgeKinds": sorted(REQUIRED_GRAPH_EDGE_KINDS - edge_kinds),
    }
    missing = {key: values for key, values in missing.items() if values}
    if missing:
        raise ValueError("graphPersistence missing required causal coverage: " + json.dumps(missing))
    for field in ("causalQueriesVerified", "processTreeCoverage", "upstreamDownstreamCoverage"):
        if graph_evidence.get(field) is not True:
            raise ValueError(f"graphPersistence.{field} must be true")
    return node_kinds, edge_kinds


def derive_sensor_evidence(coverage: dict[str, Any]) -> dict[str, Any]:
    sensor_inventory = object_list(coverage, "sensorInventory")
    event_coverage = object_list(coverage, "eventCoverage")
    ingestion_routes = object_list(coverage, "ingestionRoutes")
    graph_evidence = object_value(coverage, "graphPersistence")
    redaction_evidence = object_value(coverage, "redactionEvidence")

    require_verified_rows(sensor_inventory, "sensorInventory")
    require_verified_rows(event_coverage, "eventCoverage")
    require_verified_rows(ingestion_routes, "ingestionRoutes")
    if graph_evidence.get("verified") is not True:
        raise ValueError("graphPersistence must be verified")
    if redaction_evidence.get("verified") is not True:
        raise ValueError("redactionEvidence must be verified")
    graph_node_kinds, graph_edge_kinds = require_graph_persistence(graph_evidence)

    sensors: set[str] = set()
    platforms: set[str] = set()
    event_kinds: set[str] = set()
    identity_fields: set[str] = set()
    routes: set[str] = set()
    for row in sensor_inventory:
        sensors.update(values_from_row(row, "sensor", "sensors"))
        platforms.update(
            normalize_platform(value) for value in values_from_row(row, "platform", "platforms")
        )
        event_kinds.update(values_from_row(row, "eventKind", "eventKinds"))
        routes.update(values_from_row(row, "ingestionRoute", "ingestionRoutes", "route", "routes"))
        identity_fields.update(values_from_row(row, "identityField", "identityFields"))
    for row in event_coverage:
        event_kinds.update(values_from_row(row, "eventKind", "eventKinds"))
        sensors.update(values_from_row(row, "sensor", "sensors"))
        identity_fields.update(values_from_row(row, "identityField", "identityFields"))
    for row in ingestion_routes:
        routes.update(values_from_row(row, "route", "routes", "ingestionRoute", "ingestionRoutes"))
        sensors.update(values_from_row(row, "sensor", "sensors"))

    require_complete_coverage(sensors, platforms, routes, event_kinds, identity_fields)

    return {
        "sensors": sorted(sensors),
        "sensorPlatforms": sorted(platforms),
        "ingestionRoutes": sorted(routes),
        "eventKinds": sorted(event_kinds),
        "identityFields": sorted(identity_fields),
        "graphNodeKinds": sorted(graph_node_kinds),
        "graphEdgeKinds": sorted(graph_edge_kinds),
        "localIngestionVerified": True,
        "identityContextCoverage": True,
        "redactionCoverage": True,
        "graphPersistenceCoverage": True,
        "causalQueriesVerified": True,
        "processTreeCoverage": True,
        "upstreamDownstreamCoverage": True,
        "sensorInventorySha256": sha256_json(sensor_inventory),
        "eventCoverageSha256": sha256_json(event_coverage),
        "ingestionRouteCoverageSha256": sha256_json(ingestion_routes),
        "graphSliceSha256": sha256_json(graph_evidence),
        "sensorModuleCount": len(sensors),
        "platformCount": len(platforms),
        "eventKindCount": len(event_kinds),
        "ingestionRouteCount": len(routes),
    }


def write_proof(
    out_dir: pathlib.Path,
    evidence_path: pathlib.Path,
    coverage_path: pathlib.Path,
    command_result_path: pathlib.Path,
) -> dict[str, Any]:
    proof_path = out_dir / "cross-platform-sensor-breadth-proof.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(READINESS_AUDIT),
            "--write-proof",
            "cross_platform_sensor_breadth",
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


def build_sensor_proof(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = args.out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    coverage_path = args.coverage_json.expanduser().resolve()
    if not coverage_path.is_file():
        raise ValueError(f"--coverage-json must reference an existing JSON file: {coverage_path}")
    coverage = load_json_object(coverage_path)
    evidence = derive_sensor_evidence(coverage)
    evidence_path = out_dir / "cross-platform-sensor-breadth-evidence.json"
    command_result_path = out_dir / "cross-platform-sensor-breadth-command-result.json"
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
    summary_path = out_dir / "cross-platform-sensor-breadth-proof-summary.json"
    write_json(summary_path, result)
    result["summaryPath"] = str(summary_path)
    return result


def fixture_coverage() -> dict[str, Any]:
    identity_fields = sorted(REQUIRED_IDENTITY_FIELDS)
    return {
        "schemaVersion": 1,
        "sensorInventory": [
            {
                "sensor": "process",
                "platforms": ["macos", "linux", "windows"],
                "eventKinds": [
                    "process_exec",
                    "shell_command",
                    "tool_call",
                    "policy_decision",
                ],
                "ingestionRoutes": [
                    "/api/v1/agent/edr/endpoint-security/events",
                    "/api/v1/agent/edr/policy-events",
                    "/api/v1/agent/edr/developer-activity",
                ],
                "identityFields": identity_fields,
                "verified": True,
            },
            {
                "sensor": "file",
                "platforms": ["macos", "linux", "windows"],
                "eventKinds": ["file_access", "file_write"],
                "ingestionRoutes": [
                    "/api/v1/agent/edr/endpoint-security/events",
                    "/api/v1/agent/edr/policy-events",
                    "/api/v1/agent/edr/developer-activity",
                ],
                "identityFields": identity_fields,
                "verified": True,
            },
            {
                "sensor": "network",
                "platforms": ["macos", "linux", "windows"],
                "eventKinds": ["network_flow"],
                "ingestionRoutes": [
                    "/api/v1/agent/edr/network-extension/events",
                    "/api/v1/agent/edr/developer-activity",
                ],
                "identityFields": identity_fields,
                "verified": True,
            },
            {
                "sensor": "dns",
                "platforms": ["macos", "linux", "windows"],
                "eventKinds": ["dns_lookup"],
                "ingestionRoutes": [
                    "/api/v1/agent/edr/network-extension/events",
                    "/api/v1/agent/edr/developer-activity",
                ],
                "identityFields": identity_fields,
                "verified": True,
            },
            {
                "sensor": "persistence",
                "platforms": ["macos", "linux", "windows"],
                "eventKinds": ["launch_persistence"],
                "ingestionRoutes": ["/api/v1/agent/edr/developer-activity"],
                "identityFields": identity_fields,
                "verified": True,
            },
            {
                "sensor": "identity",
                "platforms": ["macos", "linux", "windows"],
                "eventKinds": ["identity_context"],
                "ingestionRoutes": ["/api/v1/agent/edr/developer-activity"],
                "identityFields": identity_fields,
                "verified": True,
            },
            {
                "sensor": "browser",
                "platforms": ["macos", "linux", "windows"],
                "eventKinds": ["browser_download"],
                "ingestionRoutes": ["/api/v1/agent/edr/developer-activity"],
                "identityFields": identity_fields,
                "verified": True,
            },
            {
                "sensor": "package_manager",
                "platforms": ["macos", "linux", "windows"],
                "eventKinds": ["package_script"],
                "ingestionRoutes": [
                    "/api/v1/agent/edr/package-manager/events",
                    "/api/v1/agent/edr/developer-activity",
                ],
                "identityFields": identity_fields,
                "verified": True,
            },
            {
                "sensor": "secrets",
                "platforms": ["macos", "linux", "windows"],
                "eventKinds": ["credential_access"],
                "ingestionRoutes": [
                    "/api/v1/agent/edr/developer-activity",
                    "/api/v1/agent/edr/policy-events",
                ],
                "identityFields": identity_fields,
                "verified": True,
            },
        ],
        "eventCoverage": [
            {"eventKind": event_kind, "verified": True}
            for event_kind in sorted(REQUIRED_EVENT_KINDS)
        ],
        "ingestionRoutes": [
            {"route": route, "verified": True}
            for route in sorted(REQUIRED_INGESTION_ROUTES)
        ],
        "graphPersistence": {
            "verified": True,
            "flightRecorder": "jsonl",
            "causalGraph": "endpoint-local",
            "nodeKinds": sorted(REQUIRED_GRAPH_NODE_KINDS),
            "edgeKinds": sorted(REQUIRED_GRAPH_EDGE_KINDS),
            "causalQueriesVerified": True,
            "processTreeCoverage": True,
            "upstreamDownstreamCoverage": True,
        },
        "redactionEvidence": {
            "verified": True,
            "rawCommandLinesRedacted": True,
            "secretBearingMetadataRedacted": True,
        },
    }


def expect_failure(root: pathlib.Path, name: str, coverage: dict[str, Any]) -> bool:
    path = root / f"{name}.json"
    write_json(path, coverage)
    try:
        build_sensor_proof(
            argparse.Namespace(out_dir=root / f"{name}-out", coverage_json=path)
        )
    except ValueError:
        return True
    return False


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-sensor-breadth-proof-") as temp_dir:
        root = pathlib.Path(temp_dir)
        coverage_path = root / "coverage.json"
        write_json(coverage_path, fixture_coverage())
        result = build_sensor_proof(
            argparse.Namespace(out_dir=root / "out", coverage_json=coverage_path)
        )
        if result["proofValidation"]["status"] != "verified":
            print("self-test expected generated proof to validate", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        missing_sensor = fixture_coverage()
        missing_sensor["sensorInventory"] = [
            row for row in missing_sensor["sensorInventory"] if row["sensor"] != "secrets"
        ]
        if not expect_failure(root, "missing-sensor", missing_sensor):
            print("self-test expected missing sensor to fail", file=sys.stderr)
            return 1

        missing_platform = fixture_coverage()
        for row in missing_platform["sensorInventory"]:
            row["platforms"] = [platform for platform in row["platforms"] if platform != "windows"]
        if not expect_failure(root, "missing-platform", missing_platform):
            print("self-test expected missing platform to fail", file=sys.stderr)
            return 1

        unverified_route = fixture_coverage()
        unverified_route["ingestionRoutes"][0]["verified"] = False
        if not expect_failure(root, "unverified-route", unverified_route):
            print("self-test expected unverified ingestion route to fail", file=sys.stderr)
            return 1

        missing_file_write = fixture_coverage()
        for row in missing_file_write["sensorInventory"]:
            row["eventKinds"] = [
                event_kind
                for event_kind in row["eventKinds"]
                if event_kind != "file_write"
            ]
        missing_file_write["eventCoverage"] = [
            row
            for row in missing_file_write["eventCoverage"]
            if row["eventKind"] != "file_write"
        ]
        if not expect_failure(root, "missing-file-write", missing_file_write):
            print("self-test expected missing file_write event coverage to fail", file=sys.stderr)
            return 1

        missing_identity = fixture_coverage()
        for row in missing_identity["sensorInventory"]:
            row["identityFields"] = [
                field for field in row["identityFields"] if field != "approval_id"
            ]
        if not expect_failure(root, "missing-identity", missing_identity):
            print("self-test expected missing identity coverage to fail", file=sys.stderr)
            return 1

        missing_redaction = fixture_coverage()
        missing_redaction["redactionEvidence"]["verified"] = False
        if not expect_failure(root, "missing-redaction", missing_redaction):
            print("self-test expected missing redaction evidence to fail", file=sys.stderr)
            return 1

        missing_graph = fixture_coverage()
        missing_graph["graphPersistence"]["verified"] = False
        if not expect_failure(root, "missing-graph", missing_graph):
            print("self-test expected missing graph persistence evidence to fail", file=sys.stderr)
            return 1

        missing_graph_edge = fixture_coverage()
        missing_graph_edge["graphPersistence"]["edgeKinds"] = [
            edge
            for edge in missing_graph_edge["graphPersistence"]["edgeKinds"]
            if edge != "made_decision"
        ]
        if not expect_failure(root, "missing-graph-edge", missing_graph_edge):
            print("self-test expected missing causal edge coverage to fail", file=sys.stderr)
            return 1

    print("cross-platform sensor breadth proof self-test passed")
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
        result = build_sensor_proof(args)
    except ValueError as exc:
        print(f"cross-platform sensor breadth proof failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
