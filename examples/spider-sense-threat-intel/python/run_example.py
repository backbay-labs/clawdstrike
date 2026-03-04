#!/usr/bin/env python3
"""Spider-Sense threat-intel + behavior-profile example (Python)."""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from pathlib import Path
from typing import Any

THRESHOLD = 0.86
AMBIGUITY_BAND = 0.06


def _bootstrap_sdk(example_root: Path) -> None:
    repo_root = example_root.parents[1]
    sdk_src = repo_root / "packages" / "sdk" / "hush-py" / "src"
    if str(sdk_src) not in sys.path:
        sys.path.insert(0, str(sdk_src))


def _cosine(a: list[float], b: list[float]) -> float:
    if len(a) != len(b) or not a:
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    denom = na * nb
    if denom == 0:
        return 0.0
    return dot / denom


def _classify_drift(profile: dict[str, Any], drift: float) -> str:
    if drift >= float(profile["drift_deny_threshold"]):
        return "anomalous"
    if drift >= float(profile["drift_warn_threshold"]):
        return "elevated"
    return "normal"


def _screen_embedding(
    embedding: list[float],
    patterns: list[dict[str, Any]],
) -> tuple[float, dict[str, Any]]:
    if not patterns:
        return 0.0, {}
    best_score = -math.inf
    best: dict[str, Any] | None = None
    for pattern in patterns:
        score = _cosine(embedding, pattern.get("embedding", []))
        if score > best_score:
            best_score = score
            best = pattern
    top_match = {}
    if isinstance(best, dict):
        top_match = {
            "id": best.get("id"),
            "category": best.get("category"),
            "stage": best.get("stage"),
            "label": best.get("label"),
        }
    return best_score if math.isfinite(best_score) else 0.0, top_match


def _combined_recommendation(decision_status: str, drift_state: str) -> str:
    if decision_status == "deny":
        return "block"
    if decision_status == "warn" and drift_state == "anomalous":
        return "block"
    if decision_status == "warn":
        return "review"
    if drift_state == "anomalous":
        return "review_high"
    if drift_state == "elevated":
        return "review"
    return "allow"


def _verdict_from_top_score(score: float) -> str:
    if score >= THRESHOLD + AMBIGUITY_BAND:
        return "deny"
    if score <= THRESHOLD - AMBIGUITY_BAND:
        return "allow"
    return "ambiguous"


def _status_from_verdict(verdict: str) -> str:
    if verdict == "deny":
        return "deny"
    if verdict == "ambiguous":
        return "warn"
    return "allow"


def _severity_from_verdict(verdict: str) -> str:
    if verdict == "deny":
        return "error"
    if verdict == "ambiguous":
        return "warning"
    return "info"


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _clamp(value: float, minimum: float, maximum: float) -> float:
    if value < minimum:
        return minimum
    if value > maximum:
        return maximum
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--policy",
        choices=("baseline", "hardened"),
        default="baseline",
        help="Policy tier to run.",
    )
    parser.add_argument(
        "--scenario",
        default="all",
        help="Scenario ID to run, or 'all'.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    example_root = Path(__file__).resolve().parents[1]
    os.chdir(example_root)
    _bootstrap_sdk(example_root)

    from clawdstrike import Clawdstrike  # pylint: disable=import-outside-toplevel
    from clawdstrike.guards.base import CustomAction  # pylint: disable=import-outside-toplevel

    policy_path = example_root / (
        "policy.baseline.yaml" if args.policy == "baseline" else "policy.hardened.yaml"
    )
    profiles_doc = json.loads((example_root / "data" / "behavior_profiles.json").read_text(encoding="utf-8"))
    scenarios_doc = json.loads((example_root / "data" / "scenarios.json").read_text(encoding="utf-8"))
    pattern_db = json.loads((example_root / "data" / "pattern_db.s2intel-v1.json").read_text(encoding="utf-8"))

    profiles = profiles_doc["profiles"]
    profile_by_id = {profile["profile_id"]: profile for profile in profiles}
    scenarios = scenarios_doc["scenarios"]
    if args.scenario != "all":
        scenarios = [scenario for scenario in scenarios if scenario["scenario_id"] == args.scenario]
    if not scenarios:
        raise SystemExit(f"scenario not found: {args.scenario}")

    cs = Clawdstrike.from_policy(str(policy_path))
    rows: list[dict[str, Any]] = []

    for scenario in scenarios:
        profile = profile_by_id.get(scenario["profile_id"])
        if profile is None:
            raise RuntimeError(
                f"missing profile {scenario['profile_id']} for scenario {scenario['scenario_id']}",
            )

        decision = cs.check(
            CustomAction(
                custom_type="spider_sense",
                custom_data={"embedding": scenario["embedding"]},
            ),
        )

        details = _as_dict(decision.details)
        top_score, screened_top_match = _screen_embedding(scenario["embedding"], pattern_db)
        top_match = screened_top_match or _as_dict(details.get("top_match"))
        spider_verdict = _verdict_from_top_score(top_score)
        decision_status = _status_from_verdict(spider_verdict)
        profile_similarity = _clamp(_cosine(profile["embedding"], scenario["embedding"]), -1.0, 1.0)
        profile_drift = _clamp(1.0 - profile_similarity, 0.0, 2.0)
        drift_state = _classify_drift(profile, profile_drift)
        recommendation = _combined_recommendation(decision_status, drift_state)

        rows.append(
            {
                "scenario_id": scenario["scenario_id"],
                "profile_id": scenario["profile_id"],
                "spider_verdict": spider_verdict,
                "decision_status": decision_status,
                "severity": _severity_from_verdict(spider_verdict),
                "top_score": top_score,
                "top_match": {
                    "id": top_match.get("id"),
                    "category": top_match.get("category"),
                    "stage": top_match.get("stage"),
                    "label": top_match.get("label"),
                },
                "profile_similarity": profile_similarity,
                "profile_drift_score": profile_drift,
                "profile_drift_state": drift_state,
                "combined_recommendation": recommendation,
            },
        )

    if args.json:
        print(json.dumps({"policy": args.policy, "rows": rows}, indent=2))
        return

    print(f"=== Spider-Sense Threat Intel Example (Python, {args.policy}) ===\n")
    header = (
        f"{'scenario':32} {'status':6} {'verdict':10} {'top':7} "
        f"{'drift':7} {'drift_state':10} recommendation"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            f"{row['scenario_id']:32} "
            f"{row['decision_status']:6} "
            f"{str(row['spider_verdict']):10} "
            f"{row['top_score']:.3f}   "
            f"{row['profile_drift_score']:.3f}   "
            f"{row['profile_drift_state']:10} "
            f"{row['combined_recommendation']}",
        )
        top_match = row["top_match"]
        if top_match.get("id"):
            print(
                f"  top_match: {top_match.get('id')} "
                f"({top_match.get('category')}/{top_match.get('stage')})",
            )


if __name__ == "__main__":
    main()
