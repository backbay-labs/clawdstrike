#!/usr/bin/env python3
"""Generate a strict endpoint-deception supplemental proof."""

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
REQUIRED_HONEY_KINDS = {"file", "ssh_key", "browser_cookie", "api_token", "hostname"}
DECEPTION_RULE_ID = "deception.honey_artifact_touched"
HONEY_TOUCH_EDGE_KINDS = {"accessed", "read", "wrote", "opened", "credential_used"}


def sha256_json(payload: Any) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def write_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def string_value(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def string_list_value(payload: dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
        elif isinstance(value, list):
            values.extend(item.strip() for item in value if isinstance(item, str) and item.strip())
    return values


def object_value(payload: dict[str, Any], key: str) -> dict[str, Any]:
    value = payload.get(key)
    if not isinstance(value, dict):
        raise ValueError(f"coverage artifact must include object {key}")
    return value


def object_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key)
    if not isinstance(value, list) or not value:
        raise ValueError(f"coverage artifact must include non-empty list {key}")
    rows = [item for item in value if isinstance(item, dict)]
    if len(rows) != len(value):
        raise ValueError(f"coverage artifact {key} entries must be objects")
    return rows


def honey_kind(row: dict[str, Any]) -> str | None:
    value = string_value(row, "kind", "honeyKind", "artifactKind")
    if value is None:
        return None
    normalized = value.strip().lower()
    aliases = {
        "ssh_private_key": "ssh_key",
        "api_key": "api_token",
        "internal_hostname": "hostname",
        "browser_cookie_jar": "browser_cookie",
    }
    return aliases.get(normalized, normalized)


def graph_nodes(causal_graph: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = causal_graph.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("causalGraph must include non-empty nodes")
    if not all(isinstance(node, dict) for node in nodes):
        raise ValueError("causalGraph nodes must be objects")
    return nodes


def graph_edges(causal_graph: dict[str, Any]) -> list[dict[str, Any]]:
    edges = causal_graph.get("edges")
    if not isinstance(edges, list) or not edges:
        raise ValueError("causalGraph must include non-empty edges")
    if not all(isinstance(edge, dict) for edge in edges):
        raise ValueError("causalGraph edges must be objects")
    return edges


def artifact_ids(rows: list[dict[str, Any]], label: str) -> set[str]:
    ids = {value for row in rows if (value := string_value(row, "id", "artifactId"))}
    if len(ids) != len(rows):
        raise ValueError(f"{label} entries must include unique id/artifactId values")
    return ids


def require_materialization_binding(
    materialization_receipt: dict[str, Any],
    materialized_ids: set[str],
) -> None:
    receipt_ids = set(
        string_list_value(
            materialization_receipt,
            "honeyArtifactIds",
            "honey_artifact_ids",
            "materializedArtifactIds",
            "materialized_artifact_ids",
        )
    )
    if not receipt_ids:
        raise ValueError("materializationReceipt must bind materialized honey artifact ids")
    if not materialized_ids <= receipt_ids:
        raise ValueError("materializationReceipt must bind every materialized honey artifact id")


def require_detection_binding(
    detection_receipt: dict[str, Any],
    materialization_receipt_id: str,
    graph_slice_id: str,
    touched_ids: set[str],
) -> None:
    detection_materialization_id = string_value(
        detection_receipt,
        "materializationReceiptId",
        "materialization_receipt_id",
        "deceptionMaterializationId",
    )
    if detection_materialization_id != materialization_receipt_id:
        raise ValueError("detectionReceipt must bind the materialization receipt id")
    detection_graph_id = string_value(
        detection_receipt,
        "causalGraphSliceId",
        "causal_graph_slice_id",
        "graphSliceId",
    )
    if detection_graph_id != graph_slice_id:
        raise ValueError("detectionReceipt must bind the causal graph slice id")
    detection_touched_ids = set(
        string_list_value(
            detection_receipt,
            "touchedHoneyArtifactIds",
            "touched_honey_artifact_ids",
            "touchedArtifactIds",
            "touched_artifact_ids",
        )
    )
    if not detection_touched_ids:
        raise ValueError("detectionReceipt must bind touched honey artifact ids")
    if not touched_ids <= detection_touched_ids:
        raise ValueError("detectionReceipt must bind every touched honey artifact id")


def require_causal_graph_binding(
    causal_graph: dict[str, Any],
    touched_ids: set[str],
) -> tuple[int, int]:
    nodes = graph_nodes(causal_graph)
    edges = graph_edges(causal_graph)
    node_ids = {node_id for node in nodes if (node_id := string_value(node, "id", "nodeId"))}
    if not touched_ids <= node_ids:
        raise ValueError("causalGraph must include nodes for every touched honey artifact")
    process_ids = {
        node_id
        for node in nodes
        if (node_id := string_value(node, "id", "nodeId"))
        and string_value(node, "kind", "nodeKind", "type") == "process"
    }
    if not process_ids:
        raise ValueError("causalGraph must include at least one process node")
    binding_count = 0
    for edge in edges:
        source = string_value(edge, "from", "source", "sourceId")
        target = string_value(edge, "to", "target", "targetId")
        kind = string_value(edge, "kind", "edgeKind", "type")
        if kind not in HONEY_TOUCH_EDGE_KINDS:
            continue
        if source in process_ids and target in touched_ids:
            binding_count += 1
        elif target in process_ids and source in touched_ids:
            binding_count += 1
    if binding_count < len(touched_ids):
        raise ValueError("causalGraph must bind every touched honey artifact to a process edge")
    return len(process_ids), binding_count


def derive_deception_evidence(coverage: dict[str, Any]) -> dict[str, Any]:
    materialization_receipt = object_value(coverage, "materializationReceipt")
    detection_receipt = object_value(coverage, "detectionReceipt")
    causal_graph = object_value(coverage, "causalGraph")
    honey_artifacts = object_list(coverage, "honeyArtifacts")
    touched_artifacts = object_list(coverage, "touchedHoneyArtifacts")

    materialization_receipt_id = string_value(
        materialization_receipt,
        "receiptId",
        "id",
        "deceptionMaterializationId",
        "materializationReceiptId",
    )
    detection_receipt_id = string_value(detection_receipt, "receiptId", "id", "detectionReceiptId")
    finding_id = string_value(detection_receipt, "findingId")
    detection_rule_id = string_value(detection_receipt, "ruleId", "detectionRuleId")
    graph_slice_id = string_value(causal_graph, "graphSliceId", "sliceId", "id")
    if not materialization_receipt_id:
        raise ValueError("materializationReceipt must include a receipt/materialization id")
    if not detection_receipt_id:
        raise ValueError("detectionReceipt must include a receipt id")
    if not finding_id:
        raise ValueError("detectionReceipt must include findingId")
    if detection_rule_id != DECEPTION_RULE_ID:
        raise ValueError(f"detectionReceipt rule id must be {DECEPTION_RULE_ID}")
    if not graph_slice_id:
        raise ValueError("causalGraph must include graphSliceId, sliceId, or id")

    kinds = {kind for row in honey_artifacts if (kind := honey_kind(row))}
    touched_kinds = {kind for row in touched_artifacts if (kind := honey_kind(row))}
    missing = sorted(REQUIRED_HONEY_KINDS - kinds)
    if missing:
        raise ValueError("honeyArtifacts missing required kinds: " + ", ".join(missing))
    if not touched_kinds:
        raise ValueError("touchedHoneyArtifacts must include at least one honey kind")
    if not touched_kinds <= kinds:
        raise ValueError("touchedHoneyArtifacts must reference materialized honey kinds")
    materialized_ids = artifact_ids(honey_artifacts, "honeyArtifacts")
    touched_ids = artifact_ids(touched_artifacts, "touchedHoneyArtifacts")
    if not touched_ids <= materialized_ids:
        raise ValueError("touchedHoneyArtifacts must reference materialized honey artifact ids")
    require_materialization_binding(materialization_receipt, materialized_ids)
    require_detection_binding(
        detection_receipt,
        materialization_receipt_id,
        graph_slice_id,
        touched_ids,
    )
    process_node_count, graph_binding_count = require_causal_graph_binding(causal_graph, touched_ids)

    return {
        "materializationReceipt": True,
        "detectionReceipt": True,
        "causalProcessTree": True,
        "materializationReceiptId": materialization_receipt_id,
        "detectionReceiptId": detection_receipt_id,
        "findingId": finding_id,
        "detectionRuleId": detection_rule_id,
        "causalGraphSliceId": graph_slice_id,
        "materializationReceiptSha256": sha256_json(materialization_receipt),
        "detectionReceiptSha256": sha256_json(detection_receipt),
        "causalGraphSha256": sha256_json(causal_graph),
        "materializedArtifactCount": len(honey_artifacts),
        "touchedArtifactCount": len(touched_artifacts),
        "materializationReceiptBindsHoneyArtifacts": True,
        "detectionReceiptBindsMaterialization": True,
        "detectionReceiptBindsCausalGraph": True,
        "detectionReceiptBindsTouchedArtifact": True,
        "graphProcessNodeCount": process_node_count,
        "touchedHoneyGraphBindingCount": graph_binding_count,
        "honeyKinds": sorted(kinds),
    }


def write_proof(
    out_dir: pathlib.Path,
    evidence_path: pathlib.Path,
    coverage_path: pathlib.Path,
    command_result_path: pathlib.Path,
) -> dict[str, Any]:
    proof_path = out_dir / "endpoint-deception-proof.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(READINESS_AUDIT),
            "--write-proof",
            "endpoint_deception",
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


def build_endpoint_deception_proof(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = args.out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    coverage_path = args.coverage_json.expanduser().resolve()
    if not coverage_path.is_file():
        raise ValueError(f"--coverage-json must reference an existing JSON file: {coverage_path}")
    coverage = load_json_object(coverage_path)
    evidence = derive_deception_evidence(coverage)
    evidence_path = out_dir / "endpoint-deception-evidence.json"
    command_result_path = out_dir / "endpoint-deception-command-result.json"
    write_json(evidence_path, evidence)
    write_json(
        command_result_path,
        {
            "argv": [str(pathlib.Path(__file__).name), "--coverage-json", str(coverage_path)],
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
    summary_path = out_dir / "endpoint-deception-proof-summary.json"
    write_json(summary_path, result)
    result["summaryPath"] = str(summary_path)
    return result


def fixture_coverage() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "materializationReceipt": {
            "receiptId": "deception_materialization:fixture",
            "family": "deception_materialization",
            "artifactCount": 5,
            "honeyArtifactIds": [
                "honey:file",
                "honey:ssh",
                "honey:cookie",
                "honey:api",
                "honey:host",
            ],
        },
        "detectionReceipt": {
            "receiptId": "detection:fixture",
            "findingId": "finding:honey-touch",
            "ruleId": DECEPTION_RULE_ID,
            "family": "detection",
            "materializationReceiptId": "deception_materialization:fixture",
            "causalGraphSliceId": "graph-slice:honey-touch",
            "touchedHoneyArtifactIds": ["honey:file"],
        },
        "causalGraph": {
            "graphSliceId": "graph-slice:honey-touch",
            "nodes": [
                {"id": "process:agent", "kind": "process"},
                {"id": "honey:file", "kind": "file"},
            ],
            "edges": [{"from": "process:agent", "to": "honey:file", "kind": "accessed"}],
        },
        "honeyArtifacts": [
            {"id": "honey:file", "kind": "file"},
            {"id": "honey:ssh", "kind": "ssh_key"},
            {"id": "honey:cookie", "kind": "browser_cookie"},
            {"id": "honey:api", "kind": "api_token"},
            {"id": "honey:host", "kind": "hostname"},
        ],
        "touchedHoneyArtifacts": [{"id": "honey:file", "kind": "file"}],
    }


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-endpoint-deception-proof-") as temp_dir:
        root = pathlib.Path(temp_dir)
        coverage_path = root / "coverage.json"
        write_json(coverage_path, fixture_coverage())
        result = build_endpoint_deception_proof(
            argparse.Namespace(out_dir=root / "out", coverage_json=coverage_path)
        )
        if result["proofValidation"]["status"] != "verified":
            print("self-test expected generated proof to validate", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bad_coverage = fixture_coverage()
        bad_coverage["detectionReceipt"]["ruleId"] = "other.rule"
        bad_path = root / "bad-coverage.json"
        write_json(bad_path, bad_coverage)
        try:
            build_endpoint_deception_proof(
                argparse.Namespace(out_dir=root / "bad-out", coverage_json=bad_path)
            )
        except ValueError:
            pass
        else:
            print("self-test expected wrong deception rule id to fail", file=sys.stderr)
            return 1

        unbound_coverage = fixture_coverage()
        unbound_coverage["detectionReceipt"].pop("materializationReceiptId")
        unbound_path = root / "unbound-coverage.json"
        write_json(unbound_path, unbound_coverage)
        try:
            build_endpoint_deception_proof(
                argparse.Namespace(out_dir=root / "unbound-out", coverage_json=unbound_path)
            )
        except ValueError:
            pass
        else:
            print("self-test expected unbound deception receipt to fail", file=sys.stderr)
            return 1

        graph_gap_coverage = fixture_coverage()
        graph_gap_coverage["causalGraph"]["edges"] = []
        graph_gap_path = root / "graph-gap-coverage.json"
        write_json(graph_gap_path, graph_gap_coverage)
        try:
            build_endpoint_deception_proof(
                argparse.Namespace(out_dir=root / "graph-gap-out", coverage_json=graph_gap_path)
            )
        except ValueError:
            pass
        else:
            print("self-test expected unbound causal graph to fail", file=sys.stderr)
            return 1

    print("endpoint deception proof self-test passed")
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
        result = build_endpoint_deception_proof(args)
    except ValueError as exc:
        print(f"endpoint deception proof failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
