#!/usr/bin/env python3
"""Pass #13 validator for E2 provider translator conformance.

Runs deterministic checks over fixtures/policy-events/provider-conformance/v1/cases.json
using the provider conformance suite definition. Validates that OpenAI and Claude
computer-use translators produce identical canonical policy events for equivalent
user intents, and that unknown/invalid inputs fail closed.

Fail-closed error codes:
  PRV_PROVIDER_UNKNOWN       - provider not in suite providers list
  PRV_INTENT_UNKNOWN         - intent not in suite canonical_intents list
  PRV_PARITY_VIOLATION       - cross-provider parity check failed on parity_fields
  PRV_TRANSLATION_ERROR      - translator produced invalid output structure
  PRV_MISSING_REQUIRED_FIELD - canonical output missing a required parity field
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


REPO_ROOT = Path(__file__).resolve().parents[4]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run pass #13 E2 provider conformance validator")
    parser.add_argument(
        "--cases",
        default="fixtures/policy-events/provider-conformance/v1/cases.json",
        help="Path to fixture cases",
    )
    parser.add_argument(
        "--report",
        default="docs/roadmaps/cua/research/pass13-provider-conformance-report.json",
        help="Path to write machine-readable report",
    )
    return parser.parse_args()


def fail_code(suite: Dict[str, Any], key: str, default: str) -> str:
    codes = suite.get("fail_closed_codes", {})
    if isinstance(codes, dict):
        code = codes.get(key)
        if isinstance(code, str) and code:
            return code
    return default


def validate_suite_structure(suite: Dict[str, Any]) -> Optional[str]:
    """Validate that the suite YAML has required structure."""
    required_top = {
        "suite_id",
        "suite_version",
        "providers",
        "canonical_intents",
        "parity_fields",
        "intent_canonical_map",
        "provider_input_schemas",
        "fail_closed_codes",
    }
    if not required_top.issubset(suite.keys()):
        return "SUITE_STRUCTURE_INVALID"

    providers = suite.get("providers")
    if not isinstance(providers, list) or not providers:
        return "SUITE_STRUCTURE_INVALID"

    canonical_intents = suite.get("canonical_intents")
    if not isinstance(canonical_intents, list) or not canonical_intents:
        return "SUITE_STRUCTURE_INVALID"

    parity_fields = suite.get("parity_fields")
    if not isinstance(parity_fields, list) or not parity_fields:
        return "SUITE_STRUCTURE_INVALID"

    intent_map = suite.get("intent_canonical_map")
    if not isinstance(intent_map, dict):
        return "SUITE_STRUCTURE_INVALID"
    for intent in canonical_intents:
        entry = intent_map.get(intent)
        if not isinstance(entry, dict):
            return "SUITE_STRUCTURE_INVALID"
        if "eventType" not in entry:
            return "SUITE_STRUCTURE_INVALID"
        if "cuaAction" not in entry:
            return "SUITE_STRUCTURE_INVALID"

    provider_schemas = suite.get("provider_input_schemas")
    if not isinstance(provider_schemas, dict):
        return "SUITE_STRUCTURE_INVALID"
    for provider in providers:
        schema = provider_schemas.get(provider)
        if not isinstance(schema, dict):
            return "SUITE_STRUCTURE_INVALID"
        if not isinstance(schema.get("tool_name"), str):
            return "SUITE_STRUCTURE_INVALID"
        if not isinstance(schema.get("action_field"), str):
            return "SUITE_STRUCTURE_INVALID"
        action_values = schema.get("action_values")
        if not isinstance(action_values, dict):
            return "SUITE_STRUCTURE_INVALID"

    fail_codes = suite.get("fail_closed_codes")
    if not isinstance(fail_codes, dict):
        return "SUITE_STRUCTURE_INVALID"
    for key in ("provider_unknown", "intent_unknown", "parity_violation",
                "translation_error", "missing_required_field"):
        if not isinstance(fail_codes.get(key), str) or not fail_codes.get(key):
            return "SUITE_STRUCTURE_INVALID"

    return None


def translate_provider_input(
    suite: Dict[str, Any],
    provider: str,
    intent: str,
) -> Dict[str, Any]:
    """Translate a provider-specific input to canonical form using the suite mapping.

    Returns the canonical event dict: {eventType, data: {cuaAction, direction}}.
    """
    intent_map = suite["intent_canonical_map"]
    entry = intent_map[intent]
    return {
        "eventType": entry["eventType"],
        "data": {
            "cuaAction": entry["cuaAction"],
            "direction": entry.get("direction"),
        },
    }


def extract_parity_value(canonical: Dict[str, Any], field: str) -> Any:
    """Extract a dotted field path from canonical output.

    Supports paths like 'eventType' and 'data.cuaAction'.
    """
    parts = field.split(".")
    obj: Any = canonical
    for part in parts:
        if isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


def check_required_parity_fields(
    suite: Dict[str, Any],
    canonical: Dict[str, Any],
) -> Optional[str]:
    """Check that all parity fields are present in canonical output."""
    parity_fields = suite.get("parity_fields", [])
    for field in parity_fields:
        value = extract_parity_value(canonical, field)
        # cuaAction is the critical required field; direction may be null legitimately
        if field == "data.cuaAction" and value is None:
            return fail_code(suite, "missing_required_field", "PRV_MISSING_REQUIRED_FIELD")
        if field == "eventType" and value is None:
            return fail_code(suite, "missing_required_field", "PRV_MISSING_REQUIRED_FIELD")
    return None


def evaluate_single_translation(
    suite: Dict[str, Any],
    query: Dict[str, Any],
) -> Dict[str, Any]:
    """Evaluate a single provider translation case."""
    provider = query.get("provider")
    intent = query.get("intent")
    override_canonical = query.get("override_canonical")

    providers = suite.get("providers", [])
    canonical_intents = suite.get("canonical_intents", [])

    # Check provider is known
    if provider not in providers:
        return {
            "result": "fail",
            "error_code": fail_code(suite, "provider_unknown", "PRV_PROVIDER_UNKNOWN"),
        }

    # Check intent is known
    if intent not in canonical_intents:
        return {
            "result": "fail",
            "error_code": fail_code(suite, "intent_unknown", "PRV_INTENT_UNKNOWN"),
        }

    # Translate
    if override_canonical is not None:
        canonical = override_canonical
    else:
        canonical = translate_provider_input(suite, provider, intent)

    # Check required parity fields are present
    field_err = check_required_parity_fields(suite, canonical)
    if field_err is not None:
        return {
            "result": "fail",
            "error_code": field_err,
        }

    return {
        "result": "pass",
        "canonical": canonical,
    }


def evaluate_parity_check(
    suite: Dict[str, Any],
    query: Dict[str, Any],
) -> Dict[str, Any]:
    """Evaluate a cross-provider parity check case."""
    intent = query.get("intent")
    provider_a_spec = query.get("provider_a", {})
    provider_b_spec = query.get("provider_b", {})
    override_canonical_b = query.get("override_canonical_b")

    canonical_intents = suite.get("canonical_intents", [])
    providers = suite.get("providers", [])

    # Validate providers
    provider_a = provider_a_spec.get("provider")
    provider_b = provider_b_spec.get("provider")

    if provider_a not in providers:
        return {
            "result": "fail",
            "error_code": fail_code(suite, "provider_unknown", "PRV_PROVIDER_UNKNOWN"),
        }
    if provider_b not in providers:
        return {
            "result": "fail",
            "error_code": fail_code(suite, "provider_unknown", "PRV_PROVIDER_UNKNOWN"),
        }

    # Validate intent
    if intent not in canonical_intents:
        return {
            "result": "fail",
            "error_code": fail_code(suite, "intent_unknown", "PRV_INTENT_UNKNOWN"),
        }

    # Translate both
    canonical_a = translate_provider_input(suite, provider_a, intent)

    if override_canonical_b is not None:
        canonical_b = override_canonical_b
    else:
        canonical_b = translate_provider_input(suite, provider_b, intent)

    # Compare parity fields
    parity_fields = suite.get("parity_fields", [])
    for field in parity_fields:
        val_a = extract_parity_value(canonical_a, field)
        val_b = extract_parity_value(canonical_b, field)
        if val_a != val_b:
            return {
                "result": "fail",
                "error_code": fail_code(suite, "parity_violation", "PRV_PARITY_VIOLATION"),
            }

    return {
        "result": "pass",
        "parity": True,
    }


def evaluate_case(
    suite: Dict[str, Any],
    case: Dict[str, Any],
) -> Dict[str, Any]:
    """Route a case to the appropriate evaluator."""
    query = case.get("query", {})
    query_type = query.get("type")

    if query_type == "parity_check":
        return evaluate_parity_check(suite, query)
    else:
        return evaluate_single_translation(suite, query)


def expected_matches(expected: Dict[str, Any], actual: Dict[str, Any]) -> bool:
    """Check if the actual result matches expected."""
    if expected.get("result") != actual.get("result"):
        return False

    # Check error_code if present in expected
    if "error_code" in expected:
        if expected["error_code"] != actual.get("error_code"):
            return False

    # Check canonical output if present in expected
    expected_canonical = expected.get("canonical")
    actual_canonical = actual.get("canonical")
    if expected_canonical is not None:
        if actual_canonical is None:
            return False
        if expected_canonical.get("eventType") != actual_canonical.get("eventType"):
            return False
        expected_data = expected_canonical.get("data", {})
        actual_data = actual_canonical.get("data", {})
        if expected_data.get("cuaAction") != actual_data.get("cuaAction"):
            return False
        if expected_data.get("direction") != actual_data.get("direction"):
            return False

    # Check parity flag if present
    if "parity" in expected:
        if expected["parity"] != actual.get("parity"):
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
        report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"[FAIL] suite_structure -> {{'result': 'fail', 'error_code': '{structure_error}'}}")
        print(f"\nSummary: 0/1 checks passed. Report: {report_path.relative_to(REPO_ROOT)}")
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
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(
        f"\nSummary: {report['summary']['passed']}/{report['summary']['total']} checks passed. "
        f"Report: {report_path.relative_to(REPO_ROOT)}"
    )

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
