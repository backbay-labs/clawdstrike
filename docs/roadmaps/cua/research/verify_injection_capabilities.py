#!/usr/bin/env python3
"""Pass #9 B2 validator for injection outcome schema and backend capabilities."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple

import jsonschema
import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #9 B2 injection capability validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/input-injection/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass9-injection-capabilities-report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def make_digest(ch: str) -> str:
    return f"sha256:{ch * 64}"


def validate_manifest_structure(manifest: Dict[str, Any]) -> Optional[str]:
    required_keys = {
        "manifest_id",
        "manifest_version",
        "schema_ref",
        "states",
        "actions",
        "target_modes",
        "fail_closed_codes",
        "success_reason_by_state",
        "permissions_catalog",
        "backends",
    }
    if not required_keys.issubset(manifest.keys()):
        return "INJCAP_MANIFEST_INVALID"

    if not isinstance(manifest.get("actions"), list):
        return "INJCAP_MANIFEST_INVALID"
    if not isinstance(manifest.get("target_modes"), list):
        return "INJCAP_MANIFEST_INVALID"
    if not isinstance(manifest.get("backends"), dict):
        return "INJCAP_MANIFEST_INVALID"
    if not isinstance(manifest.get("permissions_catalog"), dict):
        return "INJCAP_MANIFEST_INVALID"
    if not isinstance(manifest.get("success_reason_by_state"), dict):
        return "INJCAP_MANIFEST_INVALID"

    permissions_catalog = manifest["permissions_catalog"]
    for perm_id, perm_cfg in permissions_catalog.items():
        if not isinstance(perm_id, str) or not isinstance(perm_cfg, dict):
            return "INJCAP_MANIFEST_INVALID"
        if not isinstance(perm_cfg.get("missing_reason_code"), str):
            return "INJCAP_MANIFEST_INVALID"

    for backend_id, backend in manifest["backends"].items():
        if not isinstance(backend_id, str) or not isinstance(backend, dict):
            return "INJCAP_MANIFEST_INVALID"
        for req in ("platform", "requires_permissions", "supports"):
            if req not in backend:
                return "INJCAP_MANIFEST_INVALID"

        if not isinstance(backend.get("requires_permissions"), list):
            return "INJCAP_MANIFEST_INVALID"
        for permission in backend["requires_permissions"]:
            if permission not in permissions_catalog:
                return "INJCAP_MANIFEST_INVALID"

        supports = backend.get("supports")
        if not isinstance(supports, dict):
            return "INJCAP_MANIFEST_INVALID"
        for req in ("actions", "target_modes", "default_success_state"):
            if req not in supports:
                return "INJCAP_MANIFEST_INVALID"

        if not isinstance(supports.get("actions"), list):
            return "INJCAP_MANIFEST_INVALID"
        if not isinstance(supports.get("target_modes"), list):
            return "INJCAP_MANIFEST_INVALID"

        state = supports.get("default_success_state")
        if state not in manifest.get("states", []):
            return "INJCAP_MANIFEST_INVALID"

    return None


def build_outcome(
    *,
    schema: Dict[str, Any],
    manifest: Dict[str, Any],
    query: Dict[str, Any],
    timestamp: str,
) -> Tuple[str, Optional[str], Optional[Dict[str, Any]]]:
    fail_closed = manifest["fail_closed_codes"]
    backend_id = query.get("backend_id")
    action_kind = query.get("action_kind")
    target_mode = query.get("target_mode")
    permissions = query.get("permissions", [])

    if backend_id not in manifest["backends"]:
        return "fail", fail_closed["unknown_backend"], None

    if action_kind not in manifest["actions"]:
        return "fail", fail_closed["unknown_action"], None

    if target_mode not in manifest["target_modes"]:
        return "fail", fail_closed["unknown_target_mode"], None

    backend = manifest["backends"][backend_id]
    supports = backend["supports"]
    unsupported_reason = (
        backend.get("limits", {}).get("unsupported_reason_code", "RC_UNSUPPORTED_CAPABILITY_COMBINATION")
    )

    if action_kind not in supports["actions"] or target_mode not in supports["target_modes"]:
        outcome = {
            "outcome_version": "1.0.0",
            "backend_id": backend_id,
            "platform": backend["platform"],
            "action_kind": action_kind,
            "target_mode": target_mode,
            "state": "denied",
            "reason_code": unsupported_reason,
            "timestamp": timestamp,
            "evidence": {
                "pre_action_hash": make_digest("a")
            },
            "details": {
                "message": "backend/action/target_mode combination is unsupported"
            }
        }
        try:
            jsonschema.validate(outcome, schema)
        except jsonschema.ValidationError:
            return "fail", fail_closed["invalid_outcome"], None
        return "fail", fail_closed["unsupported_combination"], outcome

    required_permissions: Set[str] = set(backend.get("requires_permissions", []))
    granted_permissions: Set[str] = set(permissions if isinstance(permissions, list) else [])
    missing = sorted(required_permissions - granted_permissions)
    if missing:
        first_missing = missing[0]
        reason_code = manifest["permissions_catalog"][first_missing]["missing_reason_code"]
        outcome = {
            "outcome_version": "1.0.0",
            "backend_id": backend_id,
            "platform": backend["platform"],
            "action_kind": action_kind,
            "target_mode": target_mode,
            "state": "denied",
            "reason_code": reason_code,
            "timestamp": timestamp,
            "evidence": {
                "pre_action_hash": make_digest("b")
            },
            "details": {
                "message": f"missing required permission: {first_missing}"
            }
        }
        try:
            jsonschema.validate(outcome, schema)
        except jsonschema.ValidationError:
            return "fail", fail_closed["invalid_outcome"], None
        return "fail", fail_closed["missing_required_permission"], outcome

    success_state = supports["default_success_state"]
    success_reason = manifest["success_reason_by_state"][success_state]

    outcome: Dict[str, Any] = {
        "outcome_version": "1.0.0",
        "backend_id": backend_id,
        "platform": backend["platform"],
        "action_kind": action_kind,
        "target_mode": target_mode,
        "state": success_state,
        "reason_code": success_reason,
        "timestamp": timestamp,
        "evidence": {
            "pre_action_hash": make_digest("c")
        },
        "timing_ms": {
            "accepted": 1.2,
            "applied": 3.4
        },
        "policy": {
            "event": "input.inject",
            "decision": "allow"
        }
    }

    if success_state in {"applied", "verified"}:
        outcome["evidence"]["post_action_hash"] = make_digest("d")
    if success_state == "verified":
        outcome["probe"] = {
            "name": "postcondition_probe",
            "status": "pass"
        }
        outcome["timing_ms"]["verified"] = 7.8

    try:
        jsonschema.validate(outcome, schema)
    except jsonschema.ValidationError:
        return "fail", fail_closed["invalid_outcome"], None

    return "pass", None, outcome


def expected_matches(expected: Dict[str, Any], result: str, error_code: Optional[str], outcome: Optional[Dict[str, Any]]) -> bool:
    if expected.get("result") != result:
        return False

    exp_error = expected.get("error_code")
    if exp_error != error_code:
        return False

    exp_outcome = expected.get("outcome")
    if isinstance(exp_outcome, dict):
        if not isinstance(outcome, dict):
            return False
        for key, value in exp_outcome.items():
            if outcome.get(key) != value:
                return False

    return True


def main() -> int:
    args = parse_args()

    cases_path = (REPO_ROOT / args.cases).resolve()
    cases_doc = json.loads(cases_path.read_text(encoding="utf-8"))

    schema_path = (REPO_ROOT / cases_doc["schema"]).resolve()
    manifest_path = (REPO_ROOT / cases_doc["manifest"]).resolve()

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))

    report: Dict[str, Any] = {
        "schema": str(schema_path.relative_to(REPO_ROOT)),
        "manifest": str(manifest_path.relative_to(REPO_ROOT)),
        "results": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }

    manifest_error = validate_manifest_structure(manifest)
    if manifest_error is not None:
        report["summary"] = {"total": 1, "passed": 0, "failed": 1}
        report["results"].append(
            {
                "id": "manifest_structure",
                "ok": False,
                "expected": {"result": "pass"},
                "actual": {"result": "fail", "error_code": manifest_error},
            }
        )
        report_path = (REPO_ROOT / args.report).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[FAIL] manifest_structure -> {{'result': 'fail', 'error_code': '{manifest_error}'}}")
        print(f"\nSummary: 0/1 checks passed. Report: {report_path.relative_to(REPO_ROOT)}")
        return 1

    timestamp = cases_doc.get("evaluation_context", {}).get("timestamp", "2026-02-18T00:00:00Z")

    all_ok = True
    for case in cases_doc["cases"]:
        case_id = case["id"]
        expected = case["expected"]
        query = case["query"]

        result, error_code, outcome = build_outcome(
            schema=schema,
            manifest=manifest,
            query=query,
            timestamp=timestamp,
        )

        ok = expected_matches(expected, result, error_code, outcome)
        all_ok = all_ok and ok

        report["summary"]["total"] += 1
        if ok:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

        actual: Dict[str, Any] = {"result": result}
        if error_code is not None:
            actual["error_code"] = error_code
        if outcome is not None:
            actual["outcome"] = {
                "state": outcome.get("state"),
                "reason_code": outcome.get("reason_code"),
            }

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
