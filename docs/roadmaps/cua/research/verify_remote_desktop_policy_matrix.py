#!/usr/bin/env python3
"""Pass #9 validator for remote desktop policy matrix fixtures."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


@dataclass
class ResolveOutcome:
    result: str
    error_code: Optional[str] = None
    decision: Optional[str] = None
    policy_event: Optional[str] = None
    guard: Optional[str] = None
    guard_decision: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"result": self.result}
        if self.error_code is not None:
            out["error_code"] = self.error_code
        if self.decision is not None:
            out["decision"] = self.decision
        if self.policy_event is not None:
            out["policy_event"] = self.policy_event
        if self.guard is not None:
            out["guard"] = self.guard
        if self.guard_decision is not None:
            out["guard_decision"] = self.guard_decision
        return out


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #9 remote desktop matrix validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/remote-desktop/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass9-remote-desktop-matrix-report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def validate_matrix_structure(matrix: Dict[str, Any]) -> Optional[str]:
    required_top = {
        "required_features",
        "required_modes",
        "required_threat_tiers",
        "feature_definitions",
        "decision_to_guard",
        "threat_tiers",
    }
    if not required_top.issubset(matrix.keys()):
        return "RDPM_MATRIX_INVALID"

    required_features = matrix.get("required_features")
    required_modes = matrix.get("required_modes")
    required_tiers = matrix.get("required_threat_tiers")
    definitions = matrix.get("feature_definitions")
    decision_to_guard = matrix.get("decision_to_guard")
    threat_tiers = matrix.get("threat_tiers")

    if not all(isinstance(x, list) for x in [required_features, required_modes, required_tiers]):
        return "RDPM_MATRIX_INVALID"
    if not all(isinstance(x, dict) for x in [definitions, decision_to_guard, threat_tiers]):
        return "RDPM_MATRIX_INVALID"

    allowed_decisions = set(decision_to_guard.keys())
    if not {"allow", "deny", "require_approval"}.issubset(allowed_decisions):
        return "RDPM_MATRIX_INVALID"

    # Feature definitions complete.
    for feature in required_features:
        if feature not in definitions:
            return "RDPM_MATRIX_INCOMPLETE"
        fdef = definitions.get(feature)
        if not isinstance(fdef, dict):
            return "RDPM_MATRIX_INVALID"
        for key in ("policy_event", "guard", "audit_event"):
            if not isinstance(fdef.get(key), str):
                return "RDPM_MATRIX_INVALID"

    # Tier/mode/feature coverage complete.
    for tier in required_tiers:
        tier_cfg = threat_tiers.get(tier)
        if not isinstance(tier_cfg, dict):
            return "RDPM_MATRIX_INCOMPLETE"
        modes = tier_cfg.get("modes")
        if not isinstance(modes, dict):
            return "RDPM_MATRIX_INVALID"

        for mode in required_modes:
            mode_cfg = modes.get(mode)
            if not isinstance(mode_cfg, dict):
                return "RDPM_MATRIX_INCOMPLETE"
            for feature in required_features:
                if feature not in mode_cfg:
                    return "RDPM_MATRIX_INCOMPLETE"
                decision = mode_cfg.get(feature)
                if decision not in allowed_decisions:
                    return "RDPM_MATRIX_INVALID"

    return None


def resolve_query(matrix: Dict[str, Any], query: Dict[str, Any]) -> ResolveOutcome:
    tier = query.get("threat_tier")
    mode = query.get("mode")
    feature = query.get("feature")

    required_tiers = set(matrix["required_threat_tiers"])
    required_modes = set(matrix["required_modes"])
    required_features = set(matrix["required_features"])

    if tier not in required_tiers:
        return ResolveOutcome(result="fail", error_code="RDPM_THREAT_TIER_UNKNOWN")
    if mode not in required_modes:
        return ResolveOutcome(result="fail", error_code="RDPM_MODE_UNKNOWN")
    if feature not in required_features:
        return ResolveOutcome(result="fail", error_code="RDPM_FEATURE_UNKNOWN")

    feature_def = matrix["feature_definitions"][feature]
    decision = matrix["threat_tiers"][tier]["modes"][mode][feature]
    guard_decision = matrix["decision_to_guard"][decision]

    return ResolveOutcome(
        result="pass",
        decision=decision,
        policy_event=feature_def["policy_event"],
        guard=feature_def["guard"],
        guard_decision=guard_decision,
    )


def evaluate_expected(expected: Dict[str, Any], actual: ResolveOutcome) -> bool:
    actual_dict = actual.to_dict()
    for key, value in expected.items():
        if actual_dict.get(key) != value:
            return False
    return True


def main() -> int:
    args = parse_args()

    cases_path = (REPO_ROOT / args.cases).resolve()
    cases_doc = json.loads(cases_path.read_text(encoding="utf-8"))

    matrix_path = (REPO_ROOT / cases_doc["matrix"]).resolve()
    matrix = yaml.safe_load(matrix_path.read_text(encoding="utf-8"))

    report: Dict[str, Any] = {
        "matrix": str(matrix_path.relative_to(REPO_ROOT)),
        "results": [],
        "summary": {"total": 0, "passed": 0, "failed": 0},
    }

    structure_error = validate_matrix_structure(matrix)
    if structure_error is not None:
        report["summary"]["total"] = 1
        report["summary"]["failed"] = 1
        report["results"].append(
            {
                "id": "matrix_structure",
                "ok": False,
                "expected": {"result": "pass"},
                "actual": {"result": "fail", "error_code": structure_error},
            }
        )
        report_path = (REPO_ROOT / args.report).resolve()
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[FAIL] matrix_structure -> {{'result': 'fail', 'error_code': '{structure_error}'}}")
        print(f"\nSummary: 0/1 checks passed. Report: {report_path.relative_to(REPO_ROOT)}")
        return 1

    all_ok = True
    for case in cases_doc["cases"]:
        cid = case["id"]
        expected = case["expected"]
        query = case["query"]

        actual = resolve_query(matrix, query)
        ok = evaluate_expected(expected, actual)
        all_ok = all_ok and ok

        report["summary"]["total"] += 1
        if ok:
            report["summary"]["passed"] += 1
        else:
            report["summary"]["failed"] += 1

        report["results"].append(
            {
                "id": cid,
                "ok": ok,
                "expected": expected,
                "actual": actual.to_dict(),
            }
        )

        status = "PASS" if ok else "FAIL"
        print(f"[{status}] {cid} -> {actual.to_dict()}")

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
