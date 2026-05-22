#!/usr/bin/env python3
"""Generate a strict policy-simulation supplemental proof from policy impact output."""

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
SUMMARY_FIELDS = (
    "total",
    "changed",
    "allow_to_warn",
    "allow_to_block",
    "warn_to_allow",
    "warn_to_block",
    "block_to_allow",
    "block_to_warn",
)
ALLOWED_HISTORY_SOURCES = {
    "policy_event_stream",
    "flight_recorder_history",
    "causal_graph_slice",
    "endpoint_history_replay",
}
MAX_HISTORY_WINDOW_SECONDS = 604800


def sha256_bytes(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_json(payload: Any) -> str:
    return sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return payload


def write_json(path: pathlib.Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_non_negative_int(summary: dict[str, Any], field: str) -> int:
    value = summary.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"impact summary.{field} must be a non-negative integer")
    return value


def require_positive_int(payload: dict[str, Any], *fields: str) -> int:
    for field in fields:
        value = payload.get(field)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    raise ValueError(f"impact JSON must include one of {', '.join(fields)} as a positive integer")


def require_bool_true(payload: dict[str, Any], *fields: str) -> bool:
    for field in fields:
        if field in payload:
            if payload[field] is not True:
                raise ValueError(f"impact JSON {field} must be true")
            return True
    raise ValueError(f"impact JSON must include one of {', '.join(fields)}")


def require_non_empty_string(payload: dict[str, Any], *fields: str) -> str:
    for field in fields:
        value = payload.get(field)
        if isinstance(value, str) and value.strip():
            return value
    raise ValueError(f"impact JSON must include one of {', '.join(fields)} as a non-empty string")


def optional_value(payload: dict[str, Any], *fields: str) -> Any:
    for field in fields:
        if field in payload:
            return payload[field]
    return None


def receipt_family(receipt: dict[str, Any]) -> str | None:
    direct = optional_value(receipt, "family", "receiptFamily", "receipt_family")
    if isinstance(direct, str) and direct.strip():
        return direct
    metadata = receipt.get("metadata")
    if isinstance(metadata, dict):
        endpoint_decision = metadata.get("endpointDecision")
        if isinstance(endpoint_decision, dict):
            nested = optional_value(endpoint_decision, "receiptFamily", "receipt_family", "family")
            if isinstance(nested, str) and nested.strip():
                return nested
    return None


def require_simulation_receipt(impact: dict[str, Any]) -> dict[str, Any]:
    receipt = optional_value(impact, "receipt", "simulationReceipt", "simulation_receipt")
    if not isinstance(receipt, dict) or not receipt:
        raise ValueError("impact JSON must include a non-empty simulation receipt object")
    if receipt_family(receipt) != "simulation":
        raise ValueError("impact JSON simulation receipt must declare receipt family simulation")
    require_non_empty_string(receipt, "receiptId", "receipt_id", "id")
    return receipt


def require_breakage_drivers(impact: dict[str, Any]) -> list[dict[str, Any]]:
    value = optional_value(impact, "breakageDrivers", "breakage_drivers")
    if not isinstance(value, list) or not value:
        raise ValueError("impact JSON must include non-empty breakageDrivers")
    if not all(isinstance(item, dict) and item for item in value):
        raise ValueError("impact JSON breakageDrivers must be non-empty objects")
    return value


def count_jsonl_records(path: pathlib.Path) -> int:
    count = 0
    with path.open("r", encoding="utf-8") as handle:
        for index, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path} line {index} must be valid JSON") from exc
            count += 1
    if count < 1:
        raise ValueError("--events must include at least one replay event")
    return count


def normalize_impact_result(path: pathlib.Path) -> dict[str, Any]:
    impact = load_json_object(path)
    if impact.get("command") != "policy_impact":
        raise ValueError("impact JSON command must be policy_impact")
    summary = impact.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("impact JSON must include summary object")
    normalized_summary = {
        field: require_non_negative_int(summary, field)
        for field in SUMMARY_FIELDS
    }
    if normalized_summary["changed"] > normalized_summary["total"]:
        raise ValueError("impact summary.changed cannot exceed summary.total")
    if normalized_summary["total"] < 1:
        raise ValueError("impact summary.total must be positive")
    blocking_change_count = (
        normalized_summary["allow_to_block"]
        + normalized_summary["warn_to_block"]
    )
    if blocking_change_count > normalized_summary["changed"]:
        raise ValueError("blocking transitions cannot exceed changed verdict count")
    require_non_empty_string(impact, "historySource", "history_source")
    history_window_seconds = require_positive_int(
        impact,
        "historyWindowSeconds",
        "history_window_seconds",
    )
    if history_window_seconds > MAX_HISTORY_WINDOW_SECONDS:
        raise ValueError("impact JSON historyWindowSeconds must be no more than 604800")
    require_bool_true(impact, "auditModeSupported", "audit_mode_supported")
    require_bool_true(impact, "stagedEnforcementSupported", "staged_enforcement_supported")
    require_breakage_drivers(impact)
    require_simulation_receipt(impact)
    impact["summary"] = normalized_summary
    return impact


def validate_sha256(value: str) -> str:
    if not value.startswith("sha256:") or len(value) != 71:
        raise ValueError("--proposed-policy-hash must use sha256:<64-hex>")
    try:
        int(value.removeprefix("sha256:"), 16)
    except ValueError as exc:
        raise ValueError("--proposed-policy-hash must use sha256:<64-hex>") from exc
    return value


def policy_hash_for_ref(policy_ref: str, override: str | None) -> str:
    if override is not None:
        return validate_sha256(override)
    path = pathlib.Path(policy_ref).expanduser()
    if not path.is_file():
        raise ValueError(
            "proposed policy ref is not a local file; provide --proposed-policy-hash"
        )
    return sha256_file(path.resolve())


def developer_breakage_score(summary: dict[str, int]) -> int:
    total = summary["total"]
    if total == 0:
        return 0
    weighted = (
        summary["allow_to_block"] * 100
        + summary["warn_to_block"] * 75
        + summary["allow_to_warn"] * 25
    )
    return min(100, round(weighted / total))


def impact_level(summary: dict[str, int], score: int) -> str:
    if summary["changed"] == 0:
        return "none"
    if score >= 50 or summary["allow_to_block"] > 0:
        return "high"
    if summary["warn_to_block"] > 0:
        return "medium"
    return "low"


def recommended_stage(summary: dict[str, int], score: int) -> str:
    if summary["total"] == 0:
        return "observe"
    if summary["allow_to_block"] > 0 or summary["warn_to_block"] > 0 or score >= 50:
        return "audit"
    if summary["changed"] > 0:
        return "warn"
    return "limited_block"


def run_policy_impact(
    clawdstrike_bin: str,
    old_policy: str,
    new_policy: str,
    events: pathlib.Path,
    out_dir: pathlib.Path,
    resolve: bool,
) -> tuple[pathlib.Path, dict[str, Any]]:
    argv = [
        clawdstrike_bin,
        "policy",
        "impact",
        old_policy,
        new_policy,
        str(events),
        "--json",
    ]
    if resolve:
        argv.append("--resolve")
    completed = subprocess.run(
        argv,
        check=False,
        text=True,
        capture_output=True,
    )
    stdout_path = out_dir / "policy-impact.stdout.json"
    stderr_path = out_dir / "policy-impact.stderr.txt"
    stdout_path.write_text(completed.stdout, encoding="utf-8")
    stderr_path.write_text(completed.stderr, encoding="utf-8")
    command_result = {
        "argv": argv,
        "exitCode": completed.returncode,
        "stdoutPath": str(stdout_path),
        "stderrPath": str(stderr_path),
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if completed.returncode != 0:
        command_result_path = out_dir / "policy-impact-command-result.json"
        write_json(command_result_path, command_result)
        raise ValueError(
            f"policy impact command failed with exit code {completed.returncode}; "
            f"see {command_result_path}"
        )
    impact_result = normalize_impact_result(stdout_path)
    impact_path = out_dir / "policy-impact-result.json"
    write_json(impact_path, impact_result)
    command_result["impactResultPath"] = str(impact_path)
    return impact_path, command_result


def import_policy_impact(
    impact_json: pathlib.Path,
    out_dir: pathlib.Path,
) -> tuple[pathlib.Path, dict[str, Any]]:
    impact_result = normalize_impact_result(impact_json)
    impact_path = out_dir / "policy-impact-result.json"
    write_json(impact_path, impact_result)
    command_result = {
        "argv": [
            str(pathlib.Path(__file__).name),
            "--impact-json",
            str(impact_json),
        ],
        "exitCode": 0,
        "impactResultPath": str(impact_path),
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    return impact_path, command_result


def build_evidence(
    impact: dict[str, Any],
    impact_path: pathlib.Path,
    events: pathlib.Path,
    current_policy_ref: str,
    proposed_policy_ref: str,
    policy_hash: str,
    policy_epoch: int,
) -> dict[str, Any]:
    summary = impact["summary"]
    replayed_event_count = count_jsonl_records(events)
    if summary["total"] != replayed_event_count:
        raise ValueError(
            "impact summary.total must match the replay event stream record count"
        )
    history_source = require_non_empty_string(impact, "historySource", "history_source")
    if history_source not in ALLOWED_HISTORY_SOURCES:
        raise ValueError("impact JSON historySource must be a supported replay source")
    history_window_seconds = require_positive_int(
        impact,
        "historyWindowSeconds",
        "history_window_seconds",
    )
    if history_window_seconds > MAX_HISTORY_WINDOW_SECONDS:
        raise ValueError("impact JSON historyWindowSeconds must be no more than 604800")
    require_bool_true(impact, "auditModeSupported", "audit_mode_supported")
    require_bool_true(impact, "stagedEnforcementSupported", "staged_enforcement_supported")
    breakage_drivers = require_breakage_drivers(impact)
    receipt = require_simulation_receipt(impact)
    receipt_id = require_non_empty_string(receipt, "receiptId", "receipt_id", "id")
    score = developer_breakage_score(summary)
    event_hash = sha256_file(events)
    result_hash = sha256_file(impact_path)
    blocking_change_count = summary["allow_to_block"] + summary["warn_to_block"]
    return {
        "policyHash": policy_hash,
        "policyEpoch": policy_epoch,
        "graphSliceId": "policy_event_stream:" + event_hash.removeprefix("sha256:")[:16],
        "eventStreamSha256": event_hash,
        "resultSha256": result_hash,
        "currentPolicyRef": current_policy_ref,
        "proposedPolicyRef": proposed_policy_ref,
        "impactEngine": "cli_policy_impact",
        "impactLevel": impact_level(summary, score),
        "recommendedStage": recommended_stage(summary, score),
        "developerBreakageScore": score,
        "changedVerdictCount": summary["changed"],
        "blockingChangeCount": blocking_change_count,
        "replayedEventCount": replayed_event_count,
        "historySource": history_source,
        "historyWindowSeconds": history_window_seconds,
        "auditModeSupported": True,
        "stagedEnforcementSupported": True,
        "simulationReceiptId": receipt_id,
        "simulationReceiptSha256": sha256_json(receipt),
        "breakageDriversSha256": sha256_json(breakage_drivers),
        "breakageDriverCount": len(breakage_drivers),
        "simulationReceiptFamily": "simulation",
    }


def write_proof(
    out_dir: pathlib.Path,
    evidence_path: pathlib.Path,
    impact_path: pathlib.Path,
    events: pathlib.Path,
    command_result_path: pathlib.Path,
) -> dict[str, Any]:
    proof_path = out_dir / "policy-simulation-impact-proof.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(READINESS_AUDIT),
            "--write-proof",
            "policy_simulation_impact",
            "--proof-output",
            str(proof_path),
            "--proof-evidence",
            str(evidence_path),
            "--proof-artifact",
            str(impact_path),
            "--proof-artifact",
            str(events),
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
    return {
        "proofPath": str(proof_path),
        "proofValidation": result,
    }


def build_policy_simulation_impact_proof(args: argparse.Namespace) -> dict[str, Any]:
    out_dir = args.out_dir.expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    events = args.events.expanduser().resolve()
    if not events.is_file():
        raise ValueError(f"--events must reference an existing JSONL file: {args.events}")
    if args.policy_epoch < 1:
        raise ValueError("--policy-epoch must be a positive integer")

    if args.impact_json is not None:
        impact_path, command_result = import_policy_impact(args.impact_json.expanduser(), out_dir)
        current_policy_ref = args.current_policy_ref or args.old_policy or "imported-current-policy"
        proposed_policy_ref = args.proposed_policy_ref or args.new_policy or "imported-proposed-policy"
    else:
        if not args.old_policy or not args.new_policy:
            raise ValueError("run mode requires --old-policy and --new-policy")
        impact_path, command_result = run_policy_impact(
            args.clawdstrike_bin,
            args.old_policy,
            args.new_policy,
            events,
            out_dir,
            args.resolve,
        )
        current_policy_ref = args.current_policy_ref or args.old_policy
        proposed_policy_ref = args.proposed_policy_ref or args.new_policy

    policy_ref_for_hash = args.new_policy or proposed_policy_ref
    policy_hash = policy_hash_for_ref(policy_ref_for_hash, args.proposed_policy_hash)
    impact = load_json_object(impact_path)
    evidence = build_evidence(
        impact,
        impact_path,
        events,
        current_policy_ref,
        proposed_policy_ref,
        policy_hash,
        args.policy_epoch,
    )
    evidence_path = out_dir / "policy-simulation-impact-evidence.json"
    command_result_path = out_dir / "policy-impact-command-result.json"
    write_json(evidence_path, evidence)
    command_result["exitCode"] = 0
    write_json(command_result_path, command_result)
    proof = write_proof(out_dir, evidence_path, impact_path, events, command_result_path)
    result = {
        "schemaVersion": 1,
        "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
        "evidencePath": str(evidence_path),
        "impactResultPath": str(impact_path),
        "commandResultPath": str(command_result_path),
        "eventsPath": str(events),
        "evidence": evidence,
        **proof,
    }
    summary_path = out_dir / "policy-simulation-impact-proof-summary.json"
    write_json(summary_path, result)
    result["summaryPath"] = str(summary_path)
    return result


def run_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="clawdstrike-policy-impact-proof-") as temp_dir:
        root = pathlib.Path(temp_dir)
        events = root / "events.jsonl"
        current_policy = root / "current-policy.yaml"
        proposed_policy = root / "proposed-policy.yaml"
        impact_json = root / "impact.json"
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
                    "receiptId": "simulation:fixture",
                    "metadata": {
                        "endpointDecision": {
                            "receiptFamily": "simulation",
                        },
                    },
                },
                "exit_code": 0,
            },
        )
        args = argparse.Namespace(
            out_dir=root / "out",
            events=events,
            impact_json=impact_json,
            old_policy=str(current_policy),
            new_policy=str(proposed_policy),
            current_policy_ref=None,
            proposed_policy_ref=None,
            proposed_policy_hash=None,
            policy_epoch=7,
            clawdstrike_bin="clawdstrike",
            resolve=False,
        )
        result = build_policy_simulation_impact_proof(args)
        evidence = result["evidence"]
        if evidence["changedVerdictCount"] != 2 or evidence["blockingChangeCount"] != 1:
            print("self-test expected derived changed/blocking counts", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1
        if result["proofValidation"]["status"] != "verified":
            print("self-test expected generated proof to validate", file=sys.stderr)
            print(json.dumps(result, indent=2, sort_keys=True), file=sys.stderr)
            return 1

        bad_impact = root / "bad-impact.json"
        write_json(bad_impact, {"command": "policy_impact", "summary": {"total": 1}})
        args.impact_json = bad_impact
        args.out_dir = root / "bad-out"
        try:
            build_policy_simulation_impact_proof(args)
        except ValueError:
            pass
        else:
            print("self-test expected malformed impact JSON to fail", file=sys.stderr)
            return 1

        zero_replay = load_json_object(impact_json)
        zero_replay["summary"]["total"] = 0
        zero_replay["summary"]["changed"] = 0
        zero_replay["summary"]["allow_to_warn"] = 0
        zero_replay["summary"]["allow_to_block"] = 0
        zero_replay_path = root / "zero-replay-impact.json"
        write_json(zero_replay_path, zero_replay)
        args.impact_json = zero_replay_path
        args.out_dir = root / "zero-replay-out"
        try:
            build_policy_simulation_impact_proof(args)
        except ValueError:
            pass
        else:
            print("self-test expected zero replay impact JSON to fail", file=sys.stderr)
            return 1

        missing_receipt = load_json_object(impact_json)
        missing_receipt.pop("receipt", None)
        missing_receipt_path = root / "missing-receipt-impact.json"
        write_json(missing_receipt_path, missing_receipt)
        args.impact_json = missing_receipt_path
        args.out_dir = root / "missing-receipt-out"
        try:
            build_policy_simulation_impact_proof(args)
        except ValueError:
            pass
        else:
            print("self-test expected receiptless impact JSON to fail", file=sys.stderr)
            return 1

    print("policy simulation impact proof self-test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=pathlib.Path, required=False)
    parser.add_argument("--events", type=pathlib.Path)
    parser.add_argument("--old-policy")
    parser.add_argument("--new-policy")
    parser.add_argument("--current-policy-ref")
    parser.add_argument("--proposed-policy-ref")
    parser.add_argument("--proposed-policy-hash")
    parser.add_argument("--policy-epoch", type=int, default=0)
    parser.add_argument("--impact-json", type=pathlib.Path)
    parser.add_argument("--clawdstrike-bin", default="clawdstrike")
    parser.add_argument("--resolve", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return run_self_test()

    if args.out_dir is None:
        parser.error("--out-dir is required")
    if args.events is None:
        parser.error("--events is required")
    try:
        result = build_policy_simulation_impact_proof(args)
    except ValueError as exc:
        print(f"policy simulation impact proof failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
