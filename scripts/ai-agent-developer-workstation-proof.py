#!/usr/bin/env python3
"""Generate a strict AI-agent/developer-workstation supplemental proof."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
from typing import Any


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
READINESS_AUDIT = SCRIPT_DIR / "endpoint-decision-engine-readiness-audit.py"
REQUIRED_RUNTIMES = {
    "mcp",
    "browser_automation",
    "shell_agent",
    "package_manager",
    "cloud_cli",
}
REQUIRED_PROTECTED_SURFACES = {
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
REQUIRED_SECRET_KINDS = {
    "local_api_key",
    "repo_secret",
    "ci_token",
    "browser_cookie",
    "package_registry_token",
    "cloud_credential",
}
REQUIRED_IDENTITY_FIELDS = {
    "host_id",
    "user_id",
    "session_id",
    "agent_id",
    "workload_id",
    "approval_id",
    "tool_call_id",
}
REQUIRED_COLLECTOR_KINDS = {
    "adapter_core_tool_interceptor",
    "browser_runtime",
    "package_manager_lifecycle_hook",
    "repo_scanner",
    "ci_agent",
    "mcp_policy_check",
}
SECRET_LIKE = re.compile(
    r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|"
    r"xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|MY_RAW_SECRET)",
)


def sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def write_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]


def object_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def fail_if_raw_secret_like(payload: dict[str, Any]) -> None:
    canonical = canonical_json(payload)
    if SECRET_LIKE.search(canonical):
        raise ValueError("coverage artifact contains raw secret-like material")


def values_from_rows(rows: list[dict[str, Any]], field: str) -> set[str]:
    values: set[str] = set()
    for row in rows:
        value = row.get(field)
        if isinstance(value, str) and value.strip():
            values.add(value)
        elif isinstance(value, list):
            values.update(string_list(value))
    return values


def row_id(row: dict[str, Any]) -> str:
    value = row.get("id") or row.get("activityId")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("each AI-agent activity row must include id or activityId")
    return value.strip()


def row_receipt_ids(row: dict[str, Any]) -> set[str]:
    return values_from_rows([row], "receiptId") | values_from_rows([row], "receiptIds")


def require_activity_ids(rows: list[dict[str, Any]]) -> set[str]:
    activity_ids: set[str] = set()
    for row in rows:
        activity_id = row_id(row)
        if activity_id in activity_ids:
            raise ValueError("AI-agent activity ids must be unique")
        activity_ids.add(activity_id)
        if not row_receipt_ids(row):
            raise ValueError(f"AI-agent activity {activity_id} must include a receipt id")
    return activity_ids


def require_receipt_bindings(
    rows: list[dict[str, Any]],
    receipt_rows: list[dict[str, Any]],
) -> int:
    receipts_by_id: dict[str, dict[str, Any]] = {}
    for receipt in receipt_rows:
        for receipt_id in row_receipt_ids(receipt):
            receipts_by_id[receipt_id] = receipt
    binding_count = 0
    for row in rows:
        activity_id = row_id(row)
        row_runtime = row.get("runtime")
        row_surface = row.get("protectedSurface")
        for receipt_id in row_receipt_ids(row):
            receipt = receipts_by_id.get(receipt_id)
            if receipt is None:
                raise ValueError(f"receipt {receipt_id} is missing for activity {activity_id}")
            receipt_activity_id = receipt.get("activityId") or receipt.get("activity_id")
            if receipt_activity_id != activity_id:
                raise ValueError(f"receipt {receipt_id} must bind activity {activity_id}")
            if row_runtime and receipt.get("runtime") != row_runtime:
                raise ValueError(f"receipt {receipt_id} must bind activity runtime")
            if row_surface and receipt.get("protectedSurface") != row_surface:
                raise ValueError(f"receipt {receipt_id} must bind activity protected surface")
            if receipt.get("rawSecretsOmitted") is not True and receipt.get("rawPayloadOmitted") is not True:
                raise ValueError(f"receipt {receipt_id} must prove raw secret or payload omission")
            binding_count += 1
    return binding_count


def graph_id(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def require_activity_graph(graph: dict[str, Any], activity_ids: set[str]) -> tuple[int, int]:
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("causalGraph must include non-empty nodes")
    if not isinstance(edges, list) or not edges:
        raise ValueError("causalGraph must include non-empty edges")
    if not all(isinstance(node, dict) for node in nodes):
        raise ValueError("causalGraph nodes must be objects")
    if not all(isinstance(edge, dict) for edge in edges):
        raise ValueError("causalGraph edges must be objects")
    node_ids = {node_id for node in nodes if (node_id := graph_id(node, "id", "nodeId"))}
    missing_nodes = sorted(activity_ids - node_ids)
    if missing_nodes:
        raise ValueError("causalGraph missing activity nodes: " + ", ".join(missing_nodes))
    incident_ids: set[str] = set()
    for edge in edges:
        source = graph_id(edge, "from", "source", "sourceId")
        target = graph_id(edge, "to", "target", "targetId")
        if source in activity_ids or target in activity_ids:
            if not graph_id(edge, "kind", "edgeKind", "type"):
                raise ValueError("causalGraph activity edges must include a kind")
            if source in activity_ids:
                incident_ids.add(source)
            if target in activity_ids:
                incident_ids.add(target)
    isolated = sorted(activity_ids - incident_ids)
    if isolated:
        raise ValueError("causalGraph has isolated activity nodes: " + ", ".join(isolated))
    return len(activity_ids), len(edges)


def row_has_identity(row: dict[str, Any]) -> bool:
    identities = set(string_list(row.get("identityFields")))
    for field in REQUIRED_IDENTITY_FIELDS:
        camel = "".join([field.split("_")[0], *(part.title() for part in field.split("_")[1:])])
        if row.get(field) or row.get(camel) or field in identities:
            return True
    return False


def derive_evidence(coverage: dict[str, Any]) -> dict[str, Any]:
    fail_if_raw_secret_like(coverage)
    rows = object_list(coverage.get("activities"))
    if not rows:
        rows = object_list(coverage.get("coverage"))
    if not rows:
        raise ValueError("coverage artifact must include non-empty activities or coverage rows")
    receipt_rows = object_list(coverage.get("receipts"))
    if not receipt_rows:
        raise ValueError("coverage artifact must include non-empty receipts")
    graph = coverage.get("causalGraph")
    if not isinstance(graph, dict) or not graph:
        raise ValueError("coverage artifact must include non-empty causalGraph")
    activity_ids = require_activity_ids(rows)
    receipt_binding_count = require_receipt_bindings(rows, receipt_rows)
    graph_activity_node_count, graph_edge_count = require_activity_graph(graph, activity_ids)

    if any(row.get("rawSecretsOmitted") is False for row in rows):
        raise ValueError("all coverage rows must omit raw secrets")
    if any(row.get("rawValue") is not None or row.get("rawSecret") is not None for row in rows):
        raise ValueError("coverage rows must not include rawValue/rawSecret fields")

    runtimes = values_from_rows(rows, "runtime") | values_from_rows(rows, "coveredRuntimes")
    surfaces = values_from_rows(rows, "protectedSurface") | values_from_rows(rows, "protectedSurfaces")
    secret_kinds = values_from_rows(rows, "secretKind") | values_from_rows(rows, "secretKinds")
    collector_kinds = values_from_rows(rows, "collectorKind") | values_from_rows(rows, "collectorKinds")
    identity_fields = values_from_rows(rows, "identityFields")
    secret_touch_count = 0
    agent_identity_count = 0
    omission_evidence: list[dict[str, Any]] = []

    for row in rows:
        if row.get("rawSecretsOmitted") is True or row.get("rawPayloadOmitted") is True:
            omission_evidence.append(
                {
                    "runtime": row.get("runtime"),
                    "protectedSurface": row.get("protectedSurface"),
                    "collectorKind": row.get("collectorKind"),
                    "secretKind": row.get("secretKind"),
                }
            )
        if row.get("secretKind") or row.get("secretKinds"):
            secret_touch_count += int(row.get("secretTouchCount") or 1)
        if row_has_identity(row):
            agent_identity_count += int(row.get("agentIdentityCount") or 1)
            for field in REQUIRED_IDENTITY_FIELDS:
                camel = "".join(
                    [field.split("_")[0], *(part.title() for part in field.split("_")[1:])]
                )
                if row.get(field) or row.get(camel):
                    identity_fields.add(field)

    missing = {
        "coveredRuntimes": sorted(REQUIRED_RUNTIMES - runtimes),
        "protectedSurfaces": sorted(REQUIRED_PROTECTED_SURFACES - surfaces),
        "secretKinds": sorted(REQUIRED_SECRET_KINDS - secret_kinds),
        "identityFields": sorted(REQUIRED_IDENTITY_FIELDS - identity_fields),
        "collectorKinds": sorted(REQUIRED_COLLECTOR_KINDS - collector_kinds),
    }
    missing = {key: value for key, value in missing.items() if value}
    if missing:
        raise ValueError("coverage artifact missing required evidence: " + json.dumps(missing))
    if secret_touch_count < 1:
        raise ValueError("coverage artifact must include at least one secret touch")
    if agent_identity_count < 1:
        raise ValueError("coverage artifact must include at least one identity-bound event")

    omission_hash = sha256_bytes(canonical_json(omission_evidence).encode("utf-8"))
    return {
        "rawSecretsOmitted": True,
        "rawValueOmissionSha256": omission_hash,
        "secretTouchCount": secret_touch_count,
        "agentIdentityCount": agent_identity_count,
        "coveredRuntimes": sorted(runtimes),
        "protectedSurfaces": sorted(surfaces),
        "secretKinds": sorted(secret_kinds),
        "identityFields": sorted(identity_fields),
        "collectorKinds": sorted(collector_kinds),
        "activityReceiptsBound": True,
        "causalGraphActivityCoverage": True,
        "activityReceiptCount": receipt_binding_count,
        "activityGraphNodeCount": graph_activity_node_count,
        "activityGraphEdgeCount": graph_edge_count,
        "activityCausalGraphSha256": sha256_bytes(canonical_json(graph).encode("utf-8")),
    }


def write_proof(
    out_dir: pathlib.Path,
    evidence_path: pathlib.Path,
    coverage_path: pathlib.Path,
    command_result_path: pathlib.Path,
) -> dict[str, Any]:
    proof_path = out_dir / "ai-agent-developer-workstation-proof.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(READINESS_AUDIT),
            "--write-proof",
            "ai_agent_developer_workstation",
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


def build_ai_agent_proof(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = args.out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    coverage_path = args.coverage_json.expanduser().resolve()
    if not coverage_path.is_file():
        raise ValueError(f"--coverage-json must reference an existing JSON file: {coverage_path}")
    coverage = load_json_object(coverage_path)
    evidence = derive_evidence(coverage)
    evidence_path = out_dir / "ai-agent-developer-workstation-evidence.json"
    command_result_path = out_dir / "ai-agent-developer-workstation-command-result.json"
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
    summary_path = out_dir / "ai-agent-developer-workstation-proof-summary.json"
    write_json(summary_path, result)
    result["summaryPath"] = str(summary_path)
    return result


def fixture_coverage() -> dict[str, Any]:
    activities = [
        {
            "id": "activity:mcp",
            "runtime": "mcp",
            "protectedSurface": "mcp_server",
            "collectorKind": "mcp_policy_check",
            "identityFields": ["host_id", "user_id", "session_id", "tool_call_id"],
            "rawSecretsOmitted": True,
            "receiptId": "receipt:mcp",
        },
        {
            "id": "activity:browser",
            "runtime": "browser_automation",
            "protectedSurface": "browser_automation",
            "collectorKind": "browser_runtime",
            "identityFields": ["agent_id", "approval_id"],
            "rawPayloadOmitted": True,
            "receiptId": "receipt:browser",
        },
        {
            "id": "activity:shell",
            "runtime": "shell_agent",
            "protectedSurface": "shell_agent",
            "collectorKind": "adapter_core_tool_interceptor",
            "identityFields": ["workload_id"],
            "rawSecretsOmitted": True,
            "receiptId": "receipt:shell",
        },
        {
            "id": "activity:package-manager",
            "runtime": "package_manager",
            "protectedSurface": "package_manager",
            "collectorKind": "package_manager_lifecycle_hook",
            "secretKind": "package_registry_token",
            "rawSecretsOmitted": True,
            "receiptId": "receipt:package-manager",
        },
        {
            "id": "activity:cloud-cli",
            "runtime": "cloud_cli",
            "protectedSurface": "cloud_cli",
            "collectorKind": "adapter_core_tool_interceptor",
            "secretKind": "cloud_credential",
            "rawSecretsOmitted": True,
            "receiptId": "receipt:cloud-cli",
        },
        {
            "id": "activity:repo-secret",
            "runtime": "shell_agent",
            "protectedSurface": "repo_secret",
            "collectorKind": "repo_scanner",
            "secretKind": "repo_secret",
            "rawSecretsOmitted": True,
            "receiptId": "receipt:repo-secret",
        },
        {
            "id": "activity:local-api-key",
            "runtime": "shell_agent",
            "protectedSurface": "local_api_key",
            "collectorKind": "repo_scanner",
            "secretKind": "local_api_key",
            "rawSecretsOmitted": True,
            "receiptId": "receipt:local-api-key",
        },
        {
            "id": "activity:ci-token",
            "runtime": "shell_agent",
            "protectedSurface": "ci_token",
            "collectorKind": "ci_agent",
            "secretKind": "ci_token",
            "rawSecretsOmitted": True,
            "receiptId": "receipt:ci-token",
        },
        {
            "id": "activity:prompt-injection",
            "runtime": "browser_automation",
            "protectedSurface": "prompt_injected_tool_execution",
            "collectorKind": "adapter_core_tool_interceptor",
            "secretKind": "browser_cookie",
            "rawPayloadOmitted": True,
            "receiptId": "receipt:prompt-injection",
        },
    ]
    return {
        "schemaVersion": 1,
        "activities": activities,
        "receipts": [
            {
                "receiptId": activity["receiptId"],
                "activityId": activity["id"],
                "runtime": activity["runtime"],
                "protectedSurface": activity["protectedSurface"],
                "rawSecretsOmitted": True,
            }
            for activity in activities
        ],
        "causalGraph": {
            "graphSliceId": "graph-slice:ai-agent-workstation",
            "nodes": [{"id": "agent-session:fixture", "kind": "agent_session"}]
            + [{"id": activity["id"], "kind": activity["runtime"]} for activity in activities],
            "edges": [
                {
                    "from": "agent-session:fixture",
                    "to": activity["id"],
                    "kind": "observed_activity",
                }
                for activity in activities
            ],
        },
    }


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-ai-agent-proof-") as temp_dir:
        root = pathlib.Path(temp_dir)
        coverage_path = root / "coverage.json"
        write_json(coverage_path, fixture_coverage())
        args = argparse.Namespace(out_dir=root / "out", coverage_json=coverage_path)
        result = build_ai_agent_proof(args)
        if result["proofValidation"]["status"] != "verified":
            print("self-test expected generated proof to validate", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bad_coverage = fixture_coverage()
        bad_coverage["activities"][0]["rawValue"] = "ghp_MY_RAW_SECRET_12345678901234567890"
        bad_path = root / "bad-coverage.json"
        write_json(bad_path, bad_coverage)
        try:
            build_ai_agent_proof(argparse.Namespace(out_dir=root / "bad-out", coverage_json=bad_path))
        except ValueError:
            pass
        else:
            print("self-test expected raw secret-like coverage to fail", file=sys.stderr)
            return 1

        unbound_receipt = fixture_coverage()
        unbound_receipt["receipts"][0]["activityId"] = "activity:other"
        unbound_path = root / "unbound-receipt.json"
        write_json(unbound_path, unbound_receipt)
        try:
            build_ai_agent_proof(
                argparse.Namespace(out_dir=root / "unbound-out", coverage_json=unbound_path)
            )
        except ValueError:
            pass
        else:
            print("self-test expected unbound AI-agent receipt to fail", file=sys.stderr)
            return 1

        isolated_graph = fixture_coverage()
        isolated_graph["causalGraph"]["edges"] = [
            edge
            for edge in isolated_graph["causalGraph"]["edges"]
            if edge["to"] != "activity:cloud-cli"
        ]
        isolated_path = root / "isolated-graph.json"
        write_json(isolated_path, isolated_graph)
        try:
            build_ai_agent_proof(
                argparse.Namespace(out_dir=root / "isolated-out", coverage_json=isolated_path)
            )
        except ValueError:
            pass
        else:
            print("self-test expected isolated AI-agent graph activity to fail", file=sys.stderr)
            return 1

    print("AI-agent developer workstation proof self-test passed")
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
        result = build_ai_agent_proof(args)
    except ValueError as exc:
        print(f"AI-agent developer workstation proof failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
