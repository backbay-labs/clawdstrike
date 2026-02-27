"""Backend dispatch layer for Clawdstrike policy evaluation.

Provides an EngineBackend protocol with two implementations:
- NativeEngineBackend: Delegates to Rust HushEngine via hush_native
- PurePythonBackend: Uses pure Python policy engine and guards (fallback)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger("clawdstrike")


@runtime_checkable
class EngineBackend(Protocol):
    """Backend protocol for policy evaluation."""

    name: str

    def check_file_access(self, path: str, ctx: dict[str, Any]) -> dict: pass
    def check_file_write(self, path: str, content: bytes, ctx: dict[str, Any]) -> dict: pass
    def check_shell(self, command: str, ctx: dict[str, Any]) -> dict: pass
    def check_network(self, host: str, port: int, ctx: dict[str, Any]) -> dict: pass
    def check_mcp_tool(self, tool: str, args: dict[str, Any], ctx: dict[str, Any]) -> dict: pass
    def check_patch(self, path: str, diff: str, ctx: dict[str, Any]) -> dict: pass
    def check_untrusted_text(
        self, source: str | None, text: str, ctx: dict[str, Any],
    ) -> dict: pass
    def check_custom(
        self, custom_type: str, custom_data: dict[str, Any], ctx: dict[str, Any],
    ) -> dict: pass
    def policy_yaml(self) -> str: pass


class NativeEngineBackend:
    """Backend that delegates to the Rust HushEngine via hush_native."""

    name = "native"

    def __init__(self, engine: Any) -> None:
        self._engine = engine  # hush_native.NativeEngine instance

    def check_file_access(self, path: str, ctx: dict[str, Any]) -> dict:
        return self._engine.check_file_access(path, ctx)

    def check_file_write(self, path: str, content: bytes, ctx: dict[str, Any]) -> dict:
        return self._engine.check_file_write(path, content, ctx)

    def check_shell(self, command: str, ctx: dict[str, Any]) -> dict:
        return self._engine.check_shell(command, ctx)

    def check_network(self, host: str, port: int, ctx: dict[str, Any]) -> dict:
        return self._engine.check_network(host, port, ctx)

    def check_mcp_tool(self, tool: str, args: dict[str, Any], ctx: dict[str, Any]) -> dict:
        args_json = json.dumps(args)
        return self._engine.check_mcp_tool(tool, args_json, ctx)

    def check_patch(self, path: str, diff: str, ctx: dict[str, Any]) -> dict:
        return self._engine.check_patch(path, diff, ctx)

    def check_untrusted_text(
        self, source: str | None, text: str, ctx: dict[str, Any],
    ) -> dict:
        return self._engine.check_untrusted_text(source, text, ctx)

    def check_custom(
        self, custom_type: str, custom_data: dict[str, Any], ctx: dict[str, Any],
    ) -> dict:
        data_json = json.dumps(custom_data)
        return self._engine.check_custom(custom_type, data_json, ctx)

    def policy_yaml(self) -> str:
        return self._engine.policy_yaml()

    @classmethod
    def from_yaml(
        cls, yaml_str: str, *, base_path: str | None = None,
    ) -> NativeEngineBackend:
        from clawdstrike.native import get_native_module

        mod = get_native_module()
        engine = mod.NativeEngine.from_yaml(yaml_str, base_path)
        return cls(engine)

    @classmethod
    def from_ruleset(cls, name: str) -> NativeEngineBackend:
        from clawdstrike.native import get_native_module

        mod = get_native_module()
        engine = mod.NativeEngine.from_ruleset(name)
        return cls(engine)


def _results_to_report_dict(results: list) -> dict:
    """Convert a list of GuardResult objects to a GuardReport-like dict.

    This produces the same shape as the native GuardReport serialization so that
    Decision.from_report_dict() can consume either backend's output uniformly.
    """
    from clawdstrike.guards.base import Severity

    per_guard = []
    for r in results:
        per_guard.append({
            "allowed": r.allowed,
            "guard": r.guard,
            "severity": r.severity.value if isinstance(r.severity, Severity) else str(r.severity),
            "message": r.message,
            "details": r.details,
        })

    # Determine overall result (same aggregation logic as Decision.from_guard_results)
    severity_order = {
        Severity.CRITICAL: 4,
        Severity.ERROR: 3,
        Severity.WARNING: 2,
        Severity.INFO: 1,
    }
    denies = [r for r in results if not r.allowed]
    warns = [r for r in results if r.allowed and r.severity == Severity.WARNING]

    def _sev_value(sev: Any) -> str:
        return sev.value if isinstance(sev, Severity) else str(sev)

    if denies:
        worst = max(denies, key=lambda r: severity_order.get(r.severity, 0))
        overall = {
            "allowed": False,
            "guard": worst.guard,
            "severity": _sev_value(worst.severity),
            "message": worst.message,
            "details": worst.details,
        }
    elif warns:
        worst = max(warns, key=lambda r: severity_order.get(r.severity, 0))
        overall = {
            "allowed": True,
            "guard": worst.guard,
            "severity": "warning",
            "message": worst.message,
            "details": worst.details,
        }
    elif results:
        overall = {
            "allowed": True,
            "guard": results[0].guard,
            "severity": "info",
            "message": "Action allowed",
            "details": None,
        }
    else:
        overall = {
            "allowed": True,
            "guard": None,
            "severity": "info",
            "message": "No guards evaluated",
            "details": None,
        }

    return {"overall": overall, "per_guard": per_guard}


class PurePythonBackend:
    """Fallback backend using pure Python policy engine and guards."""

    name = "pure_python"

    def __init__(self, engine: Any) -> None:
        # engine is a PolicyEngine instance
        self._engine = engine

    def check_file_access(self, path: str, ctx: dict[str, Any]) -> dict:
        from clawdstrike.guards.base import FileAccessAction, GuardContext

        action = FileAccessAction(path=path)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_file_write(self, path: str, content: bytes, ctx: dict[str, Any]) -> dict:
        from clawdstrike.guards.base import FileWriteAction, GuardContext

        action = FileWriteAction(path=path, content=content)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_shell(self, command: str, ctx: dict[str, Any]) -> dict:
        from clawdstrike.guards.base import GuardContext, ShellCommandAction

        action = ShellCommandAction(command=command)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_network(self, host: str, port: int, ctx: dict[str, Any]) -> dict:
        from clawdstrike.guards.base import GuardContext, NetworkEgressAction

        action = NetworkEgressAction(host=host, port=port)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_mcp_tool(self, tool: str, args: dict[str, Any], ctx: dict[str, Any]) -> dict:
        from clawdstrike.guards.base import GuardContext, McpToolAction

        action = McpToolAction(tool=tool, args=args)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_patch(self, path: str, diff: str, ctx: dict[str, Any]) -> dict:
        from clawdstrike.guards.base import GuardContext, PatchAction

        action = PatchAction(path=path, diff=diff)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_untrusted_text(
        self, source: str | None, text: str, ctx: dict[str, Any],
    ) -> dict:
        from clawdstrike.guards.base import CustomAction, GuardContext

        action = CustomAction(
            custom_type="untrusted_text",
            custom_data={"source": source, "text": text},
        )
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def check_custom(
        self, custom_type: str, custom_data: dict[str, Any], ctx: dict[str, Any],
    ) -> dict:
        from clawdstrike.guards.base import CustomAction, GuardContext

        action = CustomAction(custom_type=custom_type, custom_data=custom_data)
        context = GuardContext(**ctx)
        results = self._engine.check(action, context)
        return _results_to_report_dict(results)

    def policy_yaml(self) -> str:
        return self._engine.policy.to_yaml()
