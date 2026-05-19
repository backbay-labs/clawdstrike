#!/usr/bin/env python3
"""Generate a strict supply-chain runtime-guard supplemental proof."""

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
REQUIRED_PACKAGE_MANAGERS = {"npm", "pip", "cargo"}
REQUIRED_SURFACES = {
    "package_install_script",
    "unsigned_binary",
    "signature_drift",
    "dynamic_library_injection",
    "launch_persistence",
    "browser_extension",
    "developer_tool",
}
REQUIRED_RULE_IDS = {
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
SURFACE_ALIASES = {
    "package_script": "package_install_script",
    "install_script": "package_install_script",
    "unsigned": "unsigned_binary",
    "binary_signature_drift": "signature_drift",
    "dylib_injection": "dynamic_library_injection",
    "package_manager_dylib_injection": "dynamic_library_injection",
    "persistence": "launch_persistence",
    "launch_agent": "launch_persistence",
    "launch_daemon": "launch_persistence",
    "extension": "browser_extension",
    "browser_extension_install": "browser_extension",
    "developer_cli": "developer_tool",
    "cloud_cli": "developer_tool",
    "package_registry_token": "developer_tool",
    "developer_secret": "developer_tool",
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


def non_empty_evidence(payload: dict[str, Any], key: str, fallback: list[dict[str, Any]]) -> Any:
    value = payload.get(key)
    if isinstance(value, dict) and value:
        return value
    if isinstance(value, list) and value:
        if not all(isinstance(item, dict) for item in value):
            raise ValueError(f"coverage artifact {key} list entries must be objects")
        return value
    if fallback:
        return fallback
    raise ValueError(f"coverage artifact must include non-empty {key} evidence")


def normalize_manager(value: str) -> str:
    normalized = value.strip().lower()
    aliases = {
        "node": "npm",
        "python-pip": "pip",
        "rust-cargo": "cargo",
    }
    return aliases.get(normalized, normalized)


def normalize_surface(value: str) -> str:
    normalized = value.strip().lower().replace("-", "_")
    return SURFACE_ALIASES.get(normalized, normalized)


def values_from_row(row: dict[str, Any], *keys: str) -> set[str]:
    values: set[str] = set()
    for key in keys:
        values.update(string_values(row.get(key)))
    return values


def row_surfaces(row: dict[str, Any]) -> set[str]:
    return {normalize_surface(value) for value in values_from_row(row, "surface", "surfaces")}


def row_rule_ids(row: dict[str, Any]) -> set[str]:
    return values_from_row(row, "ruleId", "ruleIds", "findingRuleId", "findingRuleIds")


def row_package_managers(row: dict[str, Any]) -> set[str]:
    return {
        normalize_manager(value)
        for value in values_from_row(row, "packageManager", "packageManagers", "manager")
    }


def row_receipt_ids(row: dict[str, Any]) -> set[str]:
    return values_from_row(
        row,
        "receiptId",
        "receiptIds",
        "evidenceReceiptId",
        "evidenceReceiptIds",
    )


def row_id(row: dict[str, Any]) -> str:
    value = row.get("id")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("every supply-chain observation must include a non-empty id")
    return value.strip()


def require_observation_fields(rows: list[dict[str, Any]]) -> None:
    seen: set[str] = set()
    for row in rows:
        observation_id = row_id(row)
        if observation_id in seen:
            raise ValueError("supply-chain observation ids must be unique")
        seen.add(observation_id)
        if not row_surfaces(row):
            raise ValueError(f"supply-chain observation {observation_id} must include a surface")
        if not row_rule_ids(row):
            raise ValueError(f"supply-chain observation {observation_id} must include a rule id")
        if not row_receipt_ids(row):
            raise ValueError(f"supply-chain observation {observation_id} must include a receipt id")


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
        observation_id = row_id(row)
        row_rules = row_rule_ids(row)
        observation_surfaces = row_surfaces(row)
        for receipt_id in row_receipt_ids(row):
            receipt = receipts_by_id.get(receipt_id)
            if receipt is None:
                raise ValueError(f"receipt {receipt_id} is missing for observation {observation_id}")
            receipt_observation_id = receipt.get("observationId") or receipt.get("observation_id")
            if receipt_observation_id != observation_id:
                raise ValueError(f"receipt {receipt_id} must bind observation {observation_id}")
            if not row_rules <= row_rule_ids(receipt):
                raise ValueError(f"receipt {receipt_id} must bind observation rule ids")
            receipt_surfaces = row_surfaces(receipt)
            if not observation_surfaces <= receipt_surfaces:
                raise ValueError(f"receipt {receipt_id} must bind observation surfaces")
            binding_count += 1
    return binding_count


def graph_nodes(graph: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = graph.get("nodes")
    if not isinstance(nodes, list) or not nodes:
        raise ValueError("supplyChainGraph must include non-empty nodes")
    if not all(isinstance(node, dict) for node in nodes):
        raise ValueError("supplyChainGraph nodes must be objects")
    return nodes


def graph_edges(graph: dict[str, Any]) -> list[dict[str, Any]]:
    edges = graph.get("edges")
    if not isinstance(edges, list) or not edges:
        raise ValueError("supplyChainGraph must include non-empty edges")
    if not all(isinstance(edge, dict) for edge in edges):
        raise ValueError("supplyChainGraph edges must be objects")
    return edges


def graph_id(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def require_graph_bindings(graph: dict[str, Any], rows: list[dict[str, Any]]) -> tuple[int, int]:
    nodes = graph_nodes(graph)
    edges = graph_edges(graph)
    observation_ids = {row_id(row) for row in rows}
    node_ids = {node_id for node in nodes if (node_id := graph_id(node, "id", "nodeId"))}
    missing_nodes = sorted(observation_ids - node_ids)
    if missing_nodes:
        raise ValueError("supplyChainGraph missing observation nodes: " + ", ".join(missing_nodes))
    incident_ids: set[str] = set()
    for edge in edges:
        source = graph_id(edge, "from", "source", "sourceId")
        target = graph_id(edge, "to", "target", "targetId")
        if source in observation_ids or target in observation_ids:
            if not graph_id(edge, "kind", "edgeKind", "type"):
                raise ValueError("supplyChainGraph observation edges must include a kind")
            if source in observation_ids:
                incident_ids.add(source)
            if target in observation_ids:
                incident_ids.add(target)
    isolated = sorted(observation_ids - incident_ids)
    if isolated:
        raise ValueError("supplyChainGraph has isolated observation nodes: " + ", ".join(isolated))
    return len(observation_ids), len(edges)


def rows_matching(
    rows: list[dict[str, Any]],
    surfaces: set[str] | None = None,
    rule_ids: set[str] | None = None,
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for row in rows:
        row_surface_values = row_surfaces(row)
        row_rule_values = row_rule_ids(row)
        surface_match = bool(surfaces and row_surface_values & surfaces)
        rule_match = bool(rule_ids and row_rule_values & rule_ids)
        if surface_match or rule_match:
            matches.append(row)
    return matches


def require_complete_coverage(
    package_managers: set[str],
    surfaces: set[str],
    rule_ids: set[str],
) -> None:
    missing = {
        "packageManagers": sorted(REQUIRED_PACKAGE_MANAGERS - package_managers),
        "coveredSurfaces": sorted(REQUIRED_SURFACES - surfaces),
        "findingRuleIds": sorted(REQUIRED_RULE_IDS - rule_ids),
    }
    missing = {key: values for key, values in missing.items() if values}
    if missing:
        raise ValueError(
            "coverage artifact missing required supply-chain evidence: " + json.dumps(missing)
        )


def require_positive_counts(counts: dict[str, int]) -> None:
    missing = [key for key, value in counts.items() if value < 1]
    if missing:
        raise ValueError(
            "coverage artifact has zero observations for: " + ", ".join(sorted(missing))
        )


def derive_supply_chain_evidence(coverage: dict[str, Any]) -> dict[str, Any]:
    rows = object_list(coverage, "observations")
    receipt_rows = object_list(coverage, "receipts")
    graph = coverage.get("supplyChainGraph")
    if not isinstance(graph, dict) or not graph:
        raise ValueError("coverage artifact must include non-empty object supplyChainGraph")
    require_observation_fields(rows)
    receipt_binding_count = require_receipt_bindings(rows, receipt_rows)
    graph_observation_node_count, graph_edge_count = require_graph_bindings(graph, rows)

    package_managers: set[str] = set()
    surfaces: set[str] = set()
    rule_ids: set[str] = set()
    receipt_ids: set[str] = set()
    for row in rows:
        package_managers.update(row_package_managers(row))
        surfaces.update(row_surfaces(row))
        rule_ids.update(row_rule_ids(row))
        receipt_ids.update(row_receipt_ids(row))
    for receipt in receipt_rows:
        rule_ids.update(row_rule_ids(receipt))
        receipt_ids.update(row_receipt_ids(receipt))

    require_complete_coverage(package_managers, surfaces, rule_ids)

    package_script_rows = rows_matching(
        rows,
        {"package_install_script"},
        {"supply_chain.install_script.risky"},
    )
    binary_drift_rows = rows_matching(
        rows,
        {"unsigned_binary", "signature_drift"},
        {
            "supply_chain.unsigned_binary.dev_path",
            "supply_chain.signature_drift",
        },
    )
    dylib_rows = rows_matching(
        rows,
        {"dynamic_library_injection"},
        {
            "supply_chain.package_manager_dylib_injection",
            "supply_chain.dylib_injection",
        },
    )
    persistence_rows = rows_matching(
        rows,
        {"launch_persistence"},
        {"supply_chain.launch_persistence"},
    )
    browser_rows = rows_matching(
        rows,
        {"browser_extension"},
        {"supply_chain.unmanaged_browser_extension"},
    )
    developer_rows = rows_matching(
        rows,
        {"developer_tool"},
        {
            "supply_chain.developer_secret_access",
            "supply_chain.package_registry_token_operation",
            "supply_chain.cloud_cli_sensitive_operation",
        },
    )
    counts = {
        "observedPackageScriptCount": len(package_script_rows),
        "observedBinaryDriftCount": len(binary_drift_rows),
        "observedDylibInjectionCount": len(dylib_rows),
        "observedPersistenceCount": len(persistence_rows),
        "observedBrowserExtensionCount": len(browser_rows),
        "observedDeveloperToolCount": len(developer_rows),
        "evidenceReceiptCount": len(receipt_ids),
    }
    require_positive_counts(counts)

    package_script_evidence = non_empty_evidence(
        coverage,
        "packageScriptObservation",
        package_script_rows,
    )
    signature_or_drift_evidence = non_empty_evidence(
        coverage,
        "signatureOrDriftEvidence",
        binary_drift_rows + dylib_rows,
    )
    persistence_evidence = non_empty_evidence(
        coverage,
        "persistenceEvidence",
        persistence_rows,
    )
    browser_extension_evidence = non_empty_evidence(
        coverage,
        "browserExtensionEvidence",
        browser_rows,
    )
    developer_tool_evidence = non_empty_evidence(
        coverage,
        "developerToolEvidence",
        developer_rows,
    )

    return {
        "packageScriptObservation": True,
        "unsignedOrSignatureDriftCoverage": True,
        "persistenceCoverage": True,
        "packageScriptObservationSha256": sha256_json(package_script_evidence),
        "signatureOrDriftEvidenceSha256": sha256_json(signature_or_drift_evidence),
        "persistenceEvidenceSha256": sha256_json(persistence_evidence),
        "browserExtensionEvidenceSha256": sha256_json(browser_extension_evidence),
        "developerToolEvidenceSha256": sha256_json(developer_tool_evidence),
        "supplyChainGraphSha256": sha256_json(graph),
        "receiptBindingVerified": True,
        "graphObservationCoverage": True,
        "receiptBindingCount": receipt_binding_count,
        "graphObservationNodeCount": graph_observation_node_count,
        "graphEdgeCount": graph_edge_count,
        "packageManagers": sorted(package_managers),
        "coveredSurfaces": sorted(surfaces),
        "findingRuleIds": sorted(rule_ids),
        **counts,
    }


def write_proof(
    out_dir: pathlib.Path,
    evidence_path: pathlib.Path,
    coverage_path: pathlib.Path,
    command_result_path: pathlib.Path,
) -> dict[str, Any]:
    proof_path = out_dir / "supply-chain-runtime-guard-proof.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(READINESS_AUDIT),
            "--write-proof",
            "supply_chain_runtime_guard",
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


def build_supply_chain_proof(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = args.out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    coverage_path = args.coverage_json.expanduser().resolve()
    if not coverage_path.is_file():
        raise ValueError(f"--coverage-json must reference an existing JSON file: {coverage_path}")
    coverage = load_json_object(coverage_path)
    evidence = derive_supply_chain_evidence(coverage)
    evidence_path = out_dir / "supply-chain-runtime-guard-evidence.json"
    command_result_path = out_dir / "supply-chain-runtime-guard-command-result.json"
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
    summary_path = out_dir / "supply-chain-runtime-guard-proof-summary.json"
    write_json(summary_path, result)
    result["summaryPath"] = str(summary_path)
    return result


def fixture_coverage() -> dict[str, Any]:
    observations = [
        {
            "id": "obs:package-script",
            "surface": "package_install_script",
            "packageManager": "npm",
            "ruleId": "supply_chain.install_script.risky",
            "receiptId": "receipt:package-script",
        },
        {
            "id": "obs:unsigned",
            "surface": "unsigned_binary",
            "packageManager": "pip",
            "ruleId": "supply_chain.unsigned_binary.dev_path",
            "receiptId": "receipt:unsigned",
        },
        {
            "id": "obs:signature-drift",
            "surface": "signature_drift",
            "packageManager": "cargo",
            "ruleId": "supply_chain.signature_drift",
            "receiptId": "receipt:signature-drift",
        },
        {
            "id": "obs:package-manager-dylib",
            "surface": "dynamic_library_injection",
            "packageManager": "npm",
            "ruleId": "supply_chain.package_manager_dylib_injection",
            "receiptId": "receipt:package-manager-dylib",
        },
        {
            "id": "obs:dylib",
            "surface": "dynamic_library_injection",
            "ruleId": "supply_chain.dylib_injection",
            "receiptId": "receipt:dylib",
        },
        {
            "id": "obs:launch-persistence",
            "surface": "launch_persistence",
            "ruleId": "supply_chain.launch_persistence",
            "receiptId": "receipt:launch-persistence",
        },
        {
            "id": "obs:browser-extension",
            "surface": "browser_extension",
            "ruleId": "supply_chain.unmanaged_browser_extension",
            "receiptId": "receipt:browser-extension",
        },
        {
            "id": "obs:developer-secret",
            "surface": "developer_tool",
            "ruleId": "supply_chain.developer_secret_access",
            "receiptId": "receipt:developer-secret",
        },
        {
            "id": "obs:registry-token",
            "surface": "developer_tool",
            "packageManager": "npm",
            "ruleId": "supply_chain.package_registry_token_operation",
            "receiptId": "receipt:registry-token",
        },
        {
            "id": "obs:cloud-cli",
            "surface": "developer_tool",
            "ruleId": "supply_chain.cloud_cli_sensitive_operation",
            "receiptId": "receipt:cloud-cli",
        },
    ]
    return {
        "schemaVersion": 1,
        "observations": observations,
        "receipts": [
            {
                "receiptId": row["receiptId"],
                "observationId": row["id"],
                "surface": row["surface"],
                "ruleId": row["ruleId"],
            }
            for row in observations
        ],
        "packageScriptObservation": {
            "manager": "npm",
            "phase": "postinstall",
            "scriptHash": "sha256:package-script-fixture",
        },
        "signatureOrDriftEvidence": {
            "unsignedBinaryPath": "/Users/alice/Downloads/build-helper",
            "expectedCdhash": "expected-cdhash",
            "observedCdhash": "actual-cdhash",
            "dylibPath": "/Users/alice/Library/Caches/libspy.dylib",
        },
        "persistenceEvidence": {
            "path": "/Users/alice/Library/LaunchAgents/com.example.updater.plist",
            "operation": "create",
        },
        "browserExtensionEvidence": {
            "browser": "chrome",
            "extensionId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "source": "developer_mode",
        },
        "developerToolEvidence": {
            "developerSecretPath": "~/.aws/credentials",
            "packageRegistryOperation": "npm token list",
            "cloudCliOperation": "aws secretsmanager get-secret-value",
        },
        "supplyChainGraph": {
            "graphSliceId": "graph-slice:supply-chain-runtime",
            "nodes": [{"id": "process:installer", "kind": "process"}]
            + [{"id": row["id"], "kind": row["surface"]} for row in observations],
            "edges": [
                {
                    "from": "process:installer",
                    "to": row["id"],
                    "kind": "observed_supply_chain_event",
                }
                for row in observations
            ],
        },
    }


def expect_failure(root: pathlib.Path, name: str, coverage: dict[str, Any]) -> bool:
    path = root / f"{name}.json"
    write_json(path, coverage)
    try:
        build_supply_chain_proof(
            argparse.Namespace(out_dir=root / f"{name}-out", coverage_json=path)
        )
    except ValueError:
        return True
    return False


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-supply-chain-proof-") as temp_dir:
        root = pathlib.Path(temp_dir)
        coverage_path = root / "coverage.json"
        write_json(coverage_path, fixture_coverage())
        result = build_supply_chain_proof(
            argparse.Namespace(out_dir=root / "out", coverage_json=coverage_path)
        )
        if result["proofValidation"]["status"] != "verified":
            print("self-test expected generated proof to validate", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        missing_manager = fixture_coverage()
        for row in missing_manager["observations"]:
            if row.get("packageManager") == "cargo":
                row["packageManager"] = "npm"
        if not expect_failure(root, "missing-manager", missing_manager):
            print("self-test expected missing cargo coverage to fail", file=sys.stderr)
            return 1

        missing_surface = fixture_coverage()
        missing_surface["observations"] = [
            row for row in missing_surface["observations"] if row["surface"] != "browser_extension"
        ]
        if not expect_failure(root, "missing-surface", missing_surface):
            print("self-test expected missing browser-extension coverage to fail", file=sys.stderr)
            return 1

        missing_rule = fixture_coverage()
        missing_rule["observations"] = [
            row
            for row in missing_rule["observations"]
            if row["ruleId"] != "supply_chain.cloud_cli_sensitive_operation"
        ]
        missing_rule["receipts"] = [
            receipt
            for receipt in missing_rule["receipts"]
            if receipt["ruleId"] != "supply_chain.cloud_cli_sensitive_operation"
        ]
        if not expect_failure(root, "missing-rule", missing_rule):
            print("self-test expected missing cloud-CLI rule coverage to fail", file=sys.stderr)
            return 1

        missing_graph = fixture_coverage()
        missing_graph.pop("supplyChainGraph")
        if not expect_failure(root, "missing-graph", missing_graph):
            print("self-test expected missing graph evidence to fail", file=sys.stderr)
            return 1

        unbound_receipt = fixture_coverage()
        unbound_receipt["receipts"][0]["observationId"] = "obs:other"
        if not expect_failure(root, "unbound-receipt", unbound_receipt):
            print("self-test expected unbound receipt evidence to fail", file=sys.stderr)
            return 1

        isolated_graph = fixture_coverage()
        isolated_graph["supplyChainGraph"]["edges"] = [
            edge
            for edge in isolated_graph["supplyChainGraph"]["edges"]
            if edge["to"] != "obs:cloud-cli"
        ]
        if not expect_failure(root, "isolated-graph", isolated_graph):
            print("self-test expected isolated graph observation to fail", file=sys.stderr)
            return 1

    print("supply chain runtime guard proof self-test passed")
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
        result = build_supply_chain_proof(args)
    except ValueError as exc:
        print(f"supply chain runtime guard proof failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
