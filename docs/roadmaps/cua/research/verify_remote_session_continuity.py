#!/usr/bin/env python3
"""Pass #10 C2 validator for remote session continuity fixtures."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #10 C2 remote session continuity validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/session-continuity/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass10-session-continuity-report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def fail_code(suite: Dict[str, Any], key: str, default: str) -> str:
    fail_closed = suite.get("fail_closed_codes", {})
    if isinstance(fail_closed, dict):
        code = fail_closed.get(key)
        if isinstance(code, str) and code:
            return code
    return default


def validate_suite_structure(suite: Dict[str, Any], mapping: Dict[str, Any]) -> Optional[str]:
    invalid = fail_code(suite, "suite_invalid", "CONT_SUITE_INVALID")

    required_top = {
        "suite_id",
        "suite_version",
        "mapping_ref",
        "required_transitions",
        "allowed_events",
        "event_contracts",
        "scenarios",
        "fail_closed_codes",
    }
    if not required_top.issubset(suite.keys()):
        return invalid

    required_transitions = suite.get("required_transitions")
    allowed_events = suite.get("allowed_events")
    contracts = suite.get("event_contracts")
    scenarios = suite.get("scenarios")
    fail_closed = suite.get("fail_closed_codes")

    if not isinstance(required_transitions, list) or not required_transitions:
        return invalid
    if not isinstance(allowed_events, list) or not allowed_events:
        return invalid
    if not isinstance(contracts, dict) or not isinstance(scenarios, dict):
        return invalid
    if not isinstance(fail_closed, dict):
        return invalid

    for key in (
        "suite_invalid",
        "scenario_unknown",
        "chain_break",
        "orphan_action_detected",
        "audit_incomplete",
    ):
        if not isinstance(fail_closed.get(key), str) or not fail_closed.get(key):
            return invalid

    allowed_set = set(allowed_events)
    if not set(required_transitions).issubset(allowed_set):
        return invalid

    for event_name in allowed_events:
        contract = contracts.get(event_name)
        if not isinstance(contract, dict):
            return invalid
        if not isinstance(contract.get("policy_event"), str) or not contract.get("policy_event"):
            return invalid
        if not isinstance(contract.get("audit_event"), str) or not contract.get("audit_event"):
            return invalid

    for scenario_name, scenario in scenarios.items():
        if not isinstance(scenario_name, str) or not isinstance(scenario, dict):
            return invalid
        transition = scenario.get("required_transition")
        expected_result = scenario.get("expected_result")
        if transition not in allowed_set:
            return invalid
        if expected_result not in {"pass", "fail"}:
            return invalid
        expected_error = scenario.get("expected_error_code")
        if expected_result == "fail" and not isinstance(expected_error, str):
            return invalid

    flow_mappings = mapping.get("flow_mappings")
    if not isinstance(flow_mappings, dict):
        return invalid

    def flow_events(flow: str) -> Optional[Tuple[str, str]]:
        entry = flow_mappings.get(flow)
        if not isinstance(entry, dict):
            return None
        preflight = entry.get("preflight")
        post_action = entry.get("post_action")
        if not isinstance(preflight, dict) or not isinstance(post_action, dict):
            return None
        policy_event = preflight.get("policy_event")
        audit_event = post_action.get("audit_event")
        if not isinstance(policy_event, str) or not isinstance(audit_event, str):
            return None
        return policy_event, audit_event

    for event_name, flow_name in {
        "connect": "connect",
        "input": "input",
        "reconnect": "reconnect",
        "disconnect": "disconnect",
    }.items():
        mapped = flow_events(flow_name)
        if mapped is None:
            return invalid
        policy_event, audit_event = mapped
        contract = contracts[event_name]
        if contract["policy_event"] != policy_event:
            return invalid
        if contract["audit_event"] != audit_event:
            return invalid

    return None


def validate_event_common(event: Dict[str, Any]) -> bool:
    session_id = event.get("session_id")
    chain_hash = event.get("chain_hash")

    if not isinstance(session_id, str) or not session_id:
        return False
    if not isinstance(chain_hash, str) or not DIGEST_RE.match(chain_hash):
        return False

    prev_chain = event.get("prev_chain_hash")
    if prev_chain is not None and prev_chain != "GENESIS":
        if not isinstance(prev_chain, str) or not DIGEST_RE.match(prev_chain):
            return False

    return True


def evaluate_transcript(
    suite: Dict[str, Any],
    query: Dict[str, Any],
) -> Tuple[str, Optional[str], Dict[str, Any]]:
    scenario_unknown = fail_code(suite, "scenario_unknown", "CONT_SCENARIO_UNKNOWN")
    chain_break = fail_code(suite, "chain_break", "CONT_CHAIN_BREAK")
    orphan = fail_code(suite, "orphan_action_detected", "CONT_ORPHAN_ACTION_DETECTED")
    audit_incomplete = fail_code(suite, "audit_incomplete", "CONT_AUDIT_INCOMPLETE")
    invalid = fail_code(suite, "suite_invalid", "CONT_SUITE_INVALID")

    scenarios = suite["scenarios"]
    scenario_name = query.get("scenario")
    if scenario_name not in scenarios:
        return "fail", scenario_unknown, {}

    scenario = scenarios[scenario_name]
    required_transition = scenario["required_transition"]
    transcript = query.get("transcript")
    if not isinstance(transcript, list) or len(transcript) == 0:
        return "fail", chain_break, {"scenario": scenario_name}

    contracts = suite["event_contracts"]
    allowed_events = set(suite["allowed_events"])

    previous_hash: Optional[str] = None
    seen_transition = False
    active_sessions: List[str] = []
    final_hash: Optional[str] = None

    for idx, event in enumerate(transcript):
        if not isinstance(event, dict):
            return "fail", invalid, {"scenario": scenario_name}

        event_name = event.get("event")
        if event_name not in allowed_events:
            return "fail", invalid, {"scenario": scenario_name}

        if not validate_event_common(event):
            return "fail", invalid, {"scenario": scenario_name}

        chain_hash = event["chain_hash"]
        prev_chain_hash = event.get("prev_chain_hash")

        if idx == 0:
            if prev_chain_hash not in (None, "GENESIS"):
                return "fail", chain_break, {"scenario": scenario_name, "index": idx}
        else:
            if prev_chain_hash != previous_hash:
                return "fail", chain_break, {"scenario": scenario_name, "index": idx}

        contract = contracts[event_name]
        if event.get("policy_event") != contract["policy_event"]:
            return "fail", audit_incomplete, {"scenario": scenario_name, "index": idx}
        if event.get("audit_event") != contract["audit_event"]:
            return "fail", audit_incomplete, {"scenario": scenario_name, "index": idx}

        session_id = event["session_id"]

        if event_name == "connect":
            active_sessions = [session_id]

        elif event_name == "input":
            action_id = event.get("action_id")
            if not isinstance(action_id, str) or not action_id:
                return "fail", invalid, {"scenario": scenario_name, "index": idx}
            if session_id not in active_sessions:
                return "fail", orphan, {"scenario": scenario_name, "index": idx}

        elif event_name in {"reconnect", "gateway_restart_recover"}:
            if event_name == required_transition:
                seen_transition = True

            if contract.get("requires_continuity_hashes"):
                continuity_prev = event.get("continuity_prev_session_hash")
                continuity_new = event.get("continuity_new_session_hash")
                if continuity_prev != previous_hash:
                    return "fail", chain_break, {"scenario": scenario_name, "index": idx}
                if continuity_new != chain_hash:
                    return "fail", chain_break, {"scenario": scenario_name, "index": idx}

            active_sessions = [session_id]

        elif event_name == "packet_loss_recover":
            if event_name == required_transition:
                seen_transition = True
            loss_packets = event.get("loss_packets")
            if not isinstance(loss_packets, int) or loss_packets <= 0:
                return "fail", invalid, {"scenario": scenario_name, "index": idx}
            if session_id not in active_sessions:
                return "fail", orphan, {"scenario": scenario_name, "index": idx}

        elif event_name == "disconnect":
            if session_id not in active_sessions:
                return "fail", orphan, {"scenario": scenario_name, "index": idx}
            active_sessions = []

        previous_hash = chain_hash
        final_hash = chain_hash

    if not seen_transition:
        return "fail", chain_break, {"scenario": scenario_name}

    return "pass", None, {
        "scenario": scenario_name,
        "required_transition": required_transition,
        "final_chain_hash": final_hash,
    }


def expected_matches(expected: Dict[str, Any], result: str, error_code: Optional[str]) -> bool:
    if expected.get("result") != result:
        return False
    if expected.get("error_code") != error_code:
        return False
    return True


def main() -> int:
    args = parse_args()

    cases_path = (REPO_ROOT / args.cases).resolve()
    cases_doc = json.loads(cases_path.read_text(encoding="utf-8"))

    suite_path = (REPO_ROOT / cases_doc["suite"]).resolve()
    suite = yaml.safe_load(suite_path.read_text(encoding="utf-8"))

    mapping_path = (REPO_ROOT / suite["mapping_ref"]).resolve()
    mapping = yaml.safe_load(mapping_path.read_text(encoding="utf-8"))

    report: Dict[str, Any] = {
        "suite": str(suite_path.relative_to(REPO_ROOT)),
        "mapping": str(mapping_path.relative_to(REPO_ROOT)),
        "results": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }

    structure_error = validate_suite_structure(suite, mapping)
    if structure_error is not None:
        report["summary"] = {"total": 1, "passed": 0, "failed": 1}
        report["results"].append(
            {
                "id": "suite_structure",
                "ok": False,
                "expected": {"result": "pass"},
                "actual": {"result": "fail", "error_code": structure_error},
            }
        )
        report_path = (REPO_ROOT / args.report).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[FAIL] suite_structure -> {{'result': 'fail', 'error_code': '{structure_error}'}}")
        print(f"\nSummary: 0/1 checks passed. Report: {report_path.relative_to(REPO_ROOT)}")
        return 1

    all_ok = True
    for case in cases_doc["cases"]:
        case_id = case["id"]
        query = case["query"]
        expected = case["expected"]

        result, error_code, details = evaluate_transcript(suite, query)

        ok = expected_matches(expected, result, error_code)
        all_ok = all_ok and ok

        report["summary"]["total"] += 1
        if ok:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

        actual: Dict[str, Any] = {"result": result}
        if error_code is not None:
            actual["error_code"] = error_code
        if details:
            actual["details"] = details

        report["results"].append(
            {
                "id": case_id,
                "ok": ok,
                "expected": expected,
                "actual": actual,
            }
        )

        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {case_id} -> {actual}")

    report_path = (REPO_ROOT / args.report).resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        f"\nSummary: {report['summary']['passed']}/{report['summary']['total']} checks passed. "
        f"Report: {report_path.relative_to(REPO_ROOT)}"
    )

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
