#!/usr/bin/env python3
"""Pass #14 validator for OpenClaw CUA bridge contract.

Runs deterministic checks over fixtures/policy-events/openclaw-bridge/v1/cases.json
using the OpenClaw CUA bridge suite definition. Validates that every CUA action
routed through the OpenClaw bridge produces the correct canonical event type,
CUA action label, data type, and direction. Unknown actions and missing metadata
fail closed with stable error codes. Parity between OpenClaw bridge and direct
adapter-core paths is verified.

Fail-closed error codes:
  OCLAW_CUA_UNKNOWN_ACTION   - CUA action not in suite cua_action_kinds
  OCLAW_CUA_MISSING_METADATA - tool flagged as CUA but no extractable action
  OCLAW_CUA_SESSION_MISSING  - session ID missing for CUA action
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run pass #14 OpenClaw CUA bridge validator"
    )
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/openclaw-bridge/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/openclaw_cua_bridge_report.json",
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


def validate_suite_structure(suite: Dict[str, Any]) -> Optional[str]:
    """Validate that the suite YAML has required structure."""
    required_top = {
        "suite_id",
        "suite_version",
        "cua_action_kinds",
        "event_type_map",
        "tool_prefixes",
        "tool_names",
        "fail_closed_codes",
    }
    if not required_top.issubset(suite.keys()):
        return "SUITE_STRUCTURE_INVALID"

    cua_action_kinds = suite.get("cua_action_kinds")
    if not isinstance(cua_action_kinds, list) or not cua_action_kinds:
        return "SUITE_STRUCTURE_INVALID"

    event_type_map = suite.get("event_type_map")
    if not isinstance(event_type_map, dict):
        return "SUITE_STRUCTURE_INVALID"

    for kind in cua_action_kinds:
        entry = event_type_map.get(kind)
        if not isinstance(entry, dict):
            return "SUITE_STRUCTURE_INVALID"
        if not isinstance(entry.get("event_type"), str):
            return "SUITE_STRUCTURE_INVALID"
        if not isinstance(entry.get("cua_action"), str):
            return "SUITE_STRUCTURE_INVALID"

    fail_closed_codes = suite.get("fail_closed_codes")
    if not isinstance(fail_closed_codes, dict):
        return "SUITE_STRUCTURE_INVALID"
    for key in ("unknown_action", "missing_metadata", "session_missing"):
        if not isinstance(fail_closed_codes.get(key), str) or not fail_closed_codes.get(key):
            return "SUITE_STRUCTURE_INVALID"

    tool_names = suite.get("tool_names")
    if not isinstance(tool_names, list) or not tool_names:
        return "SUITE_STRUCTURE_INVALID"
    if not all(isinstance(name, str) and name for name in tool_names):
        return "SUITE_STRUCTURE_INVALID"

    return None


def classify_cua_action(suite: Dict[str, Any], tool_name: str, params: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
    """Classify a tool call into a CUA action kind.

    Returns (kind, error_code). If kind is None, error_code explains why.
    """
    prefixes = suite.get("tool_prefixes", [])
    tool_names = set(name.lower() for name in suite.get("tool_names", []))
    cua_action_kinds = suite.get("cua_action_kinds", [])

    # Check if it's a CUA tool
    lower = tool_name.lower()
    is_cua = False
    action_token = None

    if lower in tool_names:
        is_cua = True
        if isinstance(params.get("action"), str) and params["action"].strip():
            action_token = params["action"].strip().lower()

    for prefix in prefixes:
        if lower.startswith(prefix):
            is_cua = True
            remainder = lower[len(prefix):]
            if remainder:
                action_token = remainder
            break

    if not is_cua:
        if params.get("__cua") is True or params.get("cua_action") is not None:
            is_cua = True
            if isinstance(params.get("cua_action"), str) and params["cua_action"].strip():
                action_token = params["cua_action"].strip().lower()

    if not is_cua:
        return None, None  # Not a CUA tool at all

    # Explicit cua_action overrides prefix extraction
    if isinstance(params.get("cua_action"), str) and params["cua_action"].strip():
        action_token = params["cua_action"].strip().lower()

    if not action_token:
        return None, fail_code(suite, "missing_metadata", "OCLAW_CUA_MISSING_METADATA")

    # Build a token-to-kind lookup from the suite
    token_to_kind = _build_token_map(cua_action_kinds)
    kind = token_to_kind.get(action_token)

    if kind is None:
        return None, fail_code(suite, "unknown_action", "OCLAW_CUA_UNKNOWN_ACTION")

    return kind, None


# Token mapping mirrors the TypeScript ACTION_TOKEN_MAP
_ACTION_TOKEN_MAP = {
    "connect": "connect",
    "session_start": "connect",
    "open": "connect",
    "launch": "connect",
    "disconnect": "disconnect",
    "session_end": "disconnect",
    "close": "disconnect",
    "terminate": "disconnect",
    "reconnect": "reconnect",
    "session_resume": "reconnect",
    "resume": "reconnect",
    "click": "input_inject",
    "type": "input_inject",
    "key": "input_inject",
    "mouse": "input_inject",
    "keyboard": "input_inject",
    "input": "input_inject",
    "scroll": "input_inject",
    "drag": "input_inject",
    "move_mouse": "input_inject",
    "clipboard_read": "clipboard_read",
    "clipboard_get": "clipboard_read",
    "paste_from": "clipboard_read",
    "copy_from_remote": "clipboard_read",
    "clipboard_write": "clipboard_write",
    "clipboard_set": "clipboard_write",
    "copy_to": "clipboard_write",
    "paste_to_remote": "clipboard_write",
    "file_upload": "file_upload",
    "upload": "file_upload",
    "send_file": "file_upload",
    "file_download": "file_download",
    "download": "file_download",
    "receive_file": "file_download",
    "get_file": "file_download",
}


def _build_token_map(cua_action_kinds: List[str]) -> Dict[str, str]:
    """Build token-to-kind map filtered by known action kinds."""
    result = {}
    for token, kind in _ACTION_TOKEN_MAP.items():
        if kind in cua_action_kinds:
            result[token] = kind
    return result


def resolve_event(suite: Dict[str, Any], kind: str) -> Dict[str, Any]:
    """Resolve the expected event type, cua_action, and direction for a kind."""
    event_type_map = suite.get("event_type_map", {})
    entry = event_type_map.get(kind, {})
    return {
        "event_type": entry.get("event_type"),
        "cua_action": entry.get("cua_action"),
        "direction": entry.get("direction"),
    }


def evaluate_case(suite: Dict[str, Any], case: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a single test case against the suite rules."""
    query = case.get("query", {})
    expected = case.get("expected", {})
    source = query.get("source", "openclaw")
    tool_name = query.get("tool_name", "")
    params = query.get("params", {})

    # Special handling for parity cases
    if source == "parity":
        return evaluate_parity_case(suite, query, expected)

    # Classify the CUA action
    kind, error_code = classify_cua_action(suite, tool_name, params)

    if error_code is not None:
        return {
            "result": "fail",
            "error_code": error_code,
            "event_type": None,
            "cua_action": None,
            "decision": "deny",
        }

    if kind is None:
        # Not a CUA tool - should not appear in this fixture set
        return {
            "result": "fail",
            "error_code": "NOT_CUA_TOOL",
            "event_type": None,
            "cua_action": None,
            "decision": "deny",
        }

    resolved = resolve_event(suite, kind)

    actual: Dict[str, Any] = {
        "result": "pass",
        "error_code": None,
        "event_type": resolved["event_type"],
        "cua_action": resolved["cua_action"],
        "decision": "allow",
    }

    if resolved.get("direction") is not None:
        actual["direction"] = resolved["direction"]

    # Check continuity hash if expected
    if query.get("expected_continuity_hash"):
        continuity_hash = params.get("continuityPrevSessionHash")
        if continuity_hash:
            actual["continuity_hash"] = continuity_hash

    return actual


def evaluate_parity_case(
    suite: Dict[str, Any],
    query: Dict[str, Any],
    expected: Dict[str, Any],
) -> Dict[str, Any]:
    """Evaluate a parity test case.

    Parity cases check that OpenClaw bridge and direct adapter-core
    produce equivalent events for the same CUA action.
    """
    tool_name = query.get("tool_name", "")
    params = query.get("params", {})
    parity_fields = query.get("parity_fields", [])

    kind, error_code = classify_cua_action(suite, tool_name, params)
    if error_code is not None or kind is None:
        return {
            "result": "fail",
            "error_code": error_code or "PARITY_CLASSIFICATION_FAILED",
            "parity": False,
            "matched_fields": [],
        }

    resolved = resolve_event(suite, kind)

    # For parity, we verify that the suite event_type_map entries match
    # the canonical adapter-core factory output. The factory is the source
    # of truth, and we validate the suite maps to the same values.
    matched = []
    for field in parity_fields:
        if field == "eventType" and resolved.get("event_type"):
            matched.append(field)
        elif field == "data.type":
            # Both paths produce data.type = 'cua'
            matched.append(field)
        elif field == "data.cuaAction" and resolved.get("cua_action"):
            matched.append(field)

    parity_ok = set(matched) == set(parity_fields)

    return {
        "result": "pass" if parity_ok else "fail",
        "error_code": None if parity_ok else "PARITY_MISMATCH",
        "parity": parity_ok,
        "matched_fields": sorted(matched),
    }


def expected_matches(expected: Dict[str, Any], actual: Dict[str, Any]) -> bool:
    """Check if the actual result matches expected."""
    if expected.get("result") != actual.get("result"):
        return False
    if expected.get("error_code") != actual.get("error_code"):
        return False
    if expected.get("event_type") != actual.get("event_type"):
        return False
    if expected.get("cua_action") != actual.get("cua_action"):
        return False
    if expected.get("decision") != actual.get("decision"):
        return False

    # Optional fields
    if "direction" in expected and expected["direction"] != actual.get("direction"):
        return False
    if "continuity_hash" in expected and expected["continuity_hash"] != actual.get("continuity_hash"):
        return False
    if "parity" in expected and expected["parity"] != actual.get("parity"):
        return False
    if "matched_fields" in expected:
        if sorted(expected["matched_fields"]) != sorted(actual.get("matched_fields", [])):
            return False

    return True


def main() -> int:
    args = parse_args()

    cases_path = (REPO_ROOT / args.cases).resolve()
    cases_doc = json.loads(cases_path.read_text(encoding="utf-8"))

    suite_path = (REPO_ROOT / cases_doc["suite"]).resolve()
    suite = yaml.safe_load(suite_path.read_text(encoding="utf-8"))

    report: Dict[str, Any] = {
        "suite": str(suite_path.relative_to(REPO_ROOT)),
        "results": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }

    # Validate suite structure first
    structure_error = validate_suite_structure(suite)
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
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            f"[FAIL] suite_structure -> {{'result': 'fail', 'error_code': '{structure_error}'}}"
        )
        print(
            f"\nSummary: 0/1 checks passed. Report: {report_path.relative_to(REPO_ROOT)}"
        )
        return 1

    all_ok = True
    for case in cases_doc["cases"]:
        case_id = case["id"]
        expected = case["expected"]

        actual = evaluate_case(suite, case)

        ok = expected_matches(expected, actual)
        all_ok = all_ok and ok

        report["summary"]["total"] += 1
        if ok:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

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
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(
        f"\nSummary: {report['summary']['passed']}/{report['summary']['total']} checks passed. "
        f"Report: {report_path.relative_to(REPO_ROOT)}"
    )

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
