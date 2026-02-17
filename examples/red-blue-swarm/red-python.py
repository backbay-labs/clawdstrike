#!/usr/bin/env python3
"""Red team agent using the clawdstrike Python SDK.

Performs three attack attempts (file access, network egress, MCP tool call)
using the local PolicyEngine and also reports each to hushd for SSE attribution.

Environment variables (set by the TS orchestrator):
  HUSHD_URL    - hushd base URL (e.g. http://127.0.0.1:9876)
  SESSION_ID   - shared session ID for attribution
  POLICY_PATH  - path to policy.yaml
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error

AGENT_ID = "red-python"
HUSHD_URL = os.environ.get("HUSHD_URL", "http://127.0.0.1:9876")
SESSION_ID = os.environ.get("SESSION_ID", "")
POLICY_PATH = os.environ.get("POLICY_PATH", "./policy.yaml")

# ---------------------------------------------------------------------------
# hushd remote check (always attempted for SSE attribution)
# ---------------------------------------------------------------------------

def hushd_check(
    action_type: str,
    target: str,
    content: str | None = None,
    args: dict | None = None,
) -> dict | None:
    """POST to hushd /api/v1/check. Returns parsed JSON or None on error."""
    body: dict = {
        "action_type": action_type,
        "target": target,
        "session_id": SESSION_ID,
        "agent_id": AGENT_ID,
    }
    if content is not None:
        body["content"] = content
    if args is not None:
        body["args"] = args

    try:
        req = urllib.request.Request(
            f"{HUSHD_URL}/api/v1/check",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        print(f"[red-python] hushd check failed: {exc}", file=sys.stderr)
        return None

# ---------------------------------------------------------------------------
# Local SDK check
# ---------------------------------------------------------------------------

_sdk_available = False
_engine = None
_ctx = None

try:
    from clawdstrike import Policy, PolicyEngine, GuardAction, GuardContext

    _sdk_available = True
except ImportError:
    print("[red-python] clawdstrike SDK not importable; using hushd only", file=sys.stderr)

if _sdk_available:
    try:
        policy = Policy.from_yaml_file_with_extends(POLICY_PATH)
        _engine = PolicyEngine(policy)
        _ctx = GuardContext(cwd="/app", session_id=SESSION_ID, agent_id=AGENT_ID)
    except Exception as exc:
        print(f"[red-python] failed to load policy: {exc}", file=sys.stderr)
        _engine = None


def sdk_check(action: "GuardAction") -> tuple[bool, str | None]:
    """Run the local PolicyEngine. Returns (allowed, blocking_guard_name)."""
    if _engine is None or _ctx is None:
        return True, None
    try:
        results = _engine.check(action, _ctx)
        for r in results:
            if not r.allowed:
                return False, r.guard
        return True, None
    except Exception as exc:
        print(f"[red-python] SDK check error: {exc}", file=sys.stderr)
        # Fail-closed: treat errors as denied
        return False, "error"

# ---------------------------------------------------------------------------
# Attack definitions
# ---------------------------------------------------------------------------

ATTACKS: list[dict] = [
    {
        "action": "Read SSH key",
        "action_type": "file_access",
        "hushd_action_type": "file_access",
        "target": "~/.ssh/id_rsa",
        "make_guard_action": lambda: GuardAction.file_access("~/.ssh/id_rsa") if _sdk_available else None,
    },
    {
        "action": "Egress to transfer.sh",
        "action_type": "network_egress",
        "hushd_action_type": "egress",
        "target": "transfer.sh",
        "make_guard_action": lambda: GuardAction.network_egress("transfer.sh", 443) if _sdk_available else None,
    },
    {
        "action": "MCP run_command rm -rf",
        "action_type": "mcp_tool",
        "hushd_action_type": "mcp_tool",
        "target": "run_command",
        "hushd_args": {"command": "rm -rf /"},
        "make_guard_action": lambda: GuardAction.mcp_tool("run_command", {"command": "rm -rf /"}) if _sdk_available else None,
    },
]

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    for attack in ATTACKS:
        action_label = attack["action"]
        action_type = attack["action_type"]
        target = attack["target"]

        # 1) Local SDK check
        guard_action = attack["make_guard_action"]()
        sdk_allowed, sdk_guard = sdk_check(guard_action) if guard_action else (True, None)

        # 2) hushd remote check (for SSE attribution)
        # hushd uses different action type names than the SDK
        hushd_at = attack.get("hushd_action_type", action_type)
        hushd_result = hushd_check(
            hushd_at,
            target,
            args=attack.get("hushd_args"),
        )

        # Prefer SDK result; fall back to hushd
        if guard_action and _engine is not None:
            allowed = sdk_allowed
            guard = sdk_guard
        elif hushd_result is not None:
            allowed = hushd_result.get("allowed", True)
            guard = hushd_result.get("guard")
        else:
            # Both unavailable -- fail closed
            allowed = False
            guard = "unavailable"

        line = {
            "action": action_label,
            "action_type": action_type,
            "target": target,
            "allowed": allowed,
            "guard": guard,
        }
        print(json.dumps(line, separators=(",", ":")), flush=True)


if __name__ == "__main__":
    main()
