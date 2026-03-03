"""Cross-SDK policy schema conformance vectors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from clawdstrike.guards.base import GuardAction, GuardContext
from clawdstrike.policy import Policy, PolicyEngine


def _run_check(engine: PolicyEngine, check: dict[str, Any]) -> tuple[str, list[str]]:
    kind = check["kind"]
    if kind == "file_access":
        action = GuardAction.file_access(check["path"])
    elif kind == "network_egress":
        action = GuardAction.network_egress(check["host"], int(check["port"]))
    elif kind == "mcp_tool":
        action = GuardAction.mcp_tool(check["tool"], check.get("args") or {})
    elif kind == "patch":
        action = GuardAction.patch(check["path"], check["diff"])
    else:
        raise ValueError(f"unsupported check kind: {kind}")

    results = engine.check(action, GuardContext())
    denied_guards = [r.guard for r in results if not r.allowed]
    status = "deny" if denied_guards else "allow"
    return status, denied_guards


def test_policy_conformance_vectors(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[4]
    vectors_path = repo_root / "fixtures" / "policy" / "conformance_vectors.json"
    vectors = json.loads(vectors_path.read_text(encoding="utf-8"))

    for vector in vectors:
        case_dir = tmp_path / vector["name"]
        case_dir.mkdir()
        for filename, content in vector["files"].items():
            (case_dir / filename).write_text(content, encoding="utf-8")

        policy = Policy.from_yaml_file(str(case_dir / vector["entry"]))
        engine = PolicyEngine(policy)

        for check in vector["checks"]:
            status, denied_guards = _run_check(engine, check)
            assert status == check["expected_status"], f'{vector["name"]}:{check["kind"]}'
            expected_guard = check.get("expected_guard")
            if expected_guard:
                assert expected_guard in denied_guards, (
                    f'{vector["name"]}:{check["kind"]}: '
                    f"expected guard {expected_guard!r}, got {denied_guards!r}"
                )
