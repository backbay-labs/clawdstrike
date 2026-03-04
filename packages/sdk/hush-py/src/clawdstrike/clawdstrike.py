"""Clawdstrike facade -- the primary entry point for the SDK."""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path
from typing import Any

from clawdstrike.backend import EngineBackend, NativeEngineBackend, PurePythonBackend
from clawdstrike.exceptions import ConfigurationError
from clawdstrike.guards.base import (
    Action,
    CustomAction,
    FileAccessAction,
    FileWriteAction,
    GuardContext,
    GuardResult,
    McpToolAction,
    NetworkEgressAction,
    PatchAction,
    ShellCommandAction,
)
from clawdstrike.policy import Policy, PolicyEngine
from clawdstrike.types import Decision, DecisionStatus, SessionOptions, SessionSummary

logger = logging.getLogger("clawdstrike")


class Clawdstrike:
    """Main facade for Clawdstrike security enforcement.

    Usage:
        cs = Clawdstrike.with_defaults("strict")
        decision = cs.check_file("/etc/shadow")
        if decision.denied:
            print(f"Blocked: {decision.message}")
    """

    def __init__(
        self,
        engine_or_backend: PolicyEngine | EngineBackend,
        *,
        cwd: str | None = None,
    ) -> None:
        if isinstance(engine_or_backend, PolicyEngine):
            # Legacy path: wrap in PurePythonBackend for backward compat
            self._backend: EngineBackend = PurePythonBackend(engine_or_backend)
        else:
            self._backend = engine_or_backend
        self._cwd = cwd or os.getcwd()

    @classmethod
    def from_policy(
        cls,
        yaml_or_path: str | os.PathLike[str],
        *,
        cwd: str | None = None,
    ) -> Clawdstrike:
        """Create from a YAML string or file path.

        If the argument is a path to an existing file, loads from file
        with extends resolution. Otherwise, treats it as a YAML string.
        """
        is_path = not isinstance(yaml_or_path, str) or os.path.exists(yaml_or_path)
        path = Path(yaml_or_path) if is_path else None

        # Read YAML content
        if path is not None and path.is_file():
            yaml_str = path.read_text(encoding="utf-8")
        else:
            yaml_str = str(yaml_or_path)

        # Try native backend first
        try:
            base_path_str = str(path) if path is not None else None
            backend = NativeEngineBackend.from_yaml(yaml_str, base_path=base_path_str)
            return cls(backend, cwd=cwd)
        except Exception:
            pass

        # Fallback to pure Python
        if path is not None and path.is_file():
            policy = Policy.from_yaml_file_with_extends(str(path))
        else:
            policy = Policy.from_yaml_with_extends(yaml_str)
        return cls(PurePythonBackend(PolicyEngine(policy)), cwd=cwd)

    @classmethod
    def with_defaults(cls, ruleset: str = "default", *, cwd: str | None = None) -> Clawdstrike:
        """Create with a built-in ruleset.

        Args:
            ruleset: One of "permissive", "default", "strict", "ai-agent", "cicd", "spider-sense"
            cwd: Working directory for context
        """
        # Try native backend first
        try:
            backend = NativeEngineBackend.from_ruleset(ruleset)
            return cls(backend, cwd=cwd)
        except Exception:
            pass

        # Fallback to pure Python
        yaml_str = f'version: "1.1.0"\nname: {ruleset}\nextends: {ruleset}\n'
        try:
            policy = Policy.from_yaml_with_extends(yaml_str)
        except Exception as e:
            raise ConfigurationError(f"Failed to load built-in ruleset {ruleset!r}: {e}") from e
        return cls(PurePythonBackend(PolicyEngine(policy)), cwd=cwd)

    @classmethod
    def configure(
        cls,
        *,
        policy: Policy | None = None,
        guards: list | None = None,
        fail_fast: bool = False,
        cwd: str | None = None,
    ) -> Clawdstrike:
        """Create with explicit configuration.

        Args:
            policy: Pre-loaded Policy object
            guards: Optional list of guard instances (not yet supported)
            fail_fast: Stop on first deny
            cwd: Working directory
        """
        if policy is None:
            policy = Policy()
        else:
            import copy
            policy = copy.deepcopy(policy)
        policy.settings.fail_fast = fail_fast
        return cls(PurePythonBackend(PolicyEngine(policy)), cwd=cwd)

    def _ctx_dict(self, **kwargs: Any) -> dict[str, Any]:
        """Build context dict for backend calls."""
        ctx: dict[str, Any] = {"cwd": kwargs.pop("cwd", self._cwd)}
        for k in ("session_id", "agent_id", "metadata"):
            if k in kwargs and kwargs[k] is not None:
                ctx[k] = kwargs[k]
        return ctx

    def _decide_from_report(self, report: dict) -> Decision:
        """Convert a backend report dict to a Decision."""
        return Decision.from_report_dict(report)

    def _context(self, **kwargs: Any) -> GuardContext:
        """Build a GuardContext with defaults (legacy path)."""
        filtered = {k: v for k, v in kwargs.items() if k != "cwd"}
        return GuardContext(cwd=kwargs.get("cwd", self._cwd), **filtered)

    def _decide(self, results: list[GuardResult]) -> Decision:
        """Convert guard results to a Decision (legacy path)."""
        return Decision.from_guard_results(results)

    def check(self, action: Action, **context_kwargs: Any) -> Decision:
        """Check an action against all guards.

        Args:
            action: The action to check (any typed Action variant)
            **context_kwargs: Additional context (session_id, agent_id, metadata)
        """
        ctx = self._ctx_dict(**context_kwargs)
        if isinstance(action, FileAccessAction):
            report = self._backend.check_file_access(action.path, ctx)
        elif isinstance(action, FileWriteAction):
            report = self._backend.check_file_write(action.path, action.content, ctx)
        elif isinstance(action, ShellCommandAction):
            report = self._backend.check_shell(action.command, ctx)
        elif isinstance(action, NetworkEgressAction):
            report = self._backend.check_network(action.host, action.port, ctx)
        elif isinstance(action, McpToolAction):
            report = self._backend.check_mcp_tool(action.tool, action.args, ctx)
        elif isinstance(action, PatchAction):
            report = self._backend.check_patch(action.path, action.diff, ctx)
        elif isinstance(action, CustomAction):
            report = self._backend.check_custom(
                action.custom_type, action.custom_data, ctx,
            )
        else:
            # Unknown action type — fall through to engine directly if possible
            gc = self._context(**context_kwargs)
            if isinstance(self._backend, PurePythonBackend):
                results = self._backend._engine.check(action, gc)
                return self._decide(results)
            return Decision(status=DecisionStatus.ALLOW)
        return self._decide_from_report(report)

    def check_file(
        self,
        path: str | os.PathLike[str],
        operation: str = "read",
        *,
        content: bytes | None = None,
    ) -> Decision:
        """Check file access.

        Args:
            path: File path to check
            operation: "read" or "write"
            content: File content for write operations (used by content-aware guards)
        """
        str_path = str(path)
        ctx = self._ctx_dict()
        if operation == "write":
            report = self._backend.check_file_write(str_path, content or b"", ctx)
        else:
            report = self._backend.check_file_access(str_path, ctx)
        return self._decide_from_report(report)

    def check_command(self, command: str) -> Decision:
        """Check a shell command."""
        ctx = self._ctx_dict()
        report = self._backend.check_shell(command, ctx)
        return self._decide_from_report(report)

    def check_network(self, host: str, port: int = 443) -> Decision:
        """Check network egress."""
        ctx = self._ctx_dict()
        report = self._backend.check_network(host, port, ctx)
        return self._decide_from_report(report)

    def check_patch(self, path: str | os.PathLike[str], diff: str) -> Decision:
        """Check a code patch."""
        ctx = self._ctx_dict()
        report = self._backend.check_patch(str(path), diff, ctx)
        return self._decide_from_report(report)

    def check_mcp_tool(self, tool: str, args: dict[str, Any] | None = None) -> Decision:
        """Check an MCP tool invocation."""
        ctx = self._ctx_dict()
        report = self._backend.check_mcp_tool(tool, args or {}, ctx)
        return self._decide_from_report(report)

    def session(self, **options: Any) -> ClawdstrikeSession:
        """Create a stateful session for tracking checks.

        Args:
            **options: Session options (agent_id, session_id, metadata)
        """
        opts = SessionOptions(
            agent_id=options.get("agent_id"),
            session_id=options.get("session_id", str(uuid.uuid4())),
            metadata=options.get("metadata"),
        )
        return ClawdstrikeSession(self, opts)


class ClawdstrikeSession:
    """Stateful session that tracks check results."""

    def __init__(self, cs: Clawdstrike, options: SessionOptions) -> None:
        self._cs = cs
        self._options = options
        self._check_count = 0
        self._allow_count = 0
        self._warn_count = 0
        self._deny_count = 0
        self._blocked_actions: list[str] = []

    def _context_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {}
        if self._options.session_id:
            kwargs["session_id"] = self._options.session_id
        if self._options.agent_id:
            kwargs["agent_id"] = self._options.agent_id
        if self._options.metadata:
            kwargs["metadata"] = self._options.metadata
        return kwargs

    def _track(self, decision: Decision, action_desc: str) -> Decision:
        self._check_count += 1
        if decision.status == DecisionStatus.DENY:
            self._deny_count += 1
            self._blocked_actions.append(action_desc)
        elif decision.status == DecisionStatus.WARN:
            self._warn_count += 1
        else:
            self._allow_count += 1
        return decision

    def check(self, action: Action, **context_kwargs: Any) -> Decision:
        merged = {**self._context_kwargs(), **context_kwargs}
        decision = self._cs.check(action, **merged)
        return self._track(decision, f"{action.action_type}")

    def check_file(
        self,
        path: str | os.PathLike[str],
        operation: str = "read",
        *,
        content: bytes | None = None,
    ) -> Decision:
        str_path = str(path)
        ctx = self._context_kwargs()
        if operation == "write":
            action: Action = FileWriteAction(path=str_path, content=content or b"")
        else:
            action = FileAccessAction(path=str_path)
        decision = self._cs.check(action, **ctx)
        return self._track(decision, f"file:{path}")

    def check_command(self, command: str) -> Decision:
        ctx = self._context_kwargs()
        decision = self._cs.check(ShellCommandAction(command=command), **ctx)
        return self._track(decision, f"command:{command[:50]}")

    def check_network(self, host: str, port: int = 443) -> Decision:
        ctx = self._context_kwargs()
        decision = self._cs.check(NetworkEgressAction(host=host, port=port), **ctx)
        return self._track(decision, f"network:{host}:{port}")

    def check_patch(self, path: str | os.PathLike[str], diff: str) -> Decision:
        ctx = self._context_kwargs()
        decision = self._cs.check(PatchAction(path=str(path), diff=diff), **ctx)
        return self._track(decision, f"patch:{path}")

    def check_mcp_tool(self, tool: str, args: dict[str, Any] | None = None) -> Decision:
        ctx = self._context_kwargs()
        decision = self._cs.check(McpToolAction(tool=tool, args=args or {}), **ctx)
        return self._track(decision, f"mcp:{tool}")

    def get_summary(self) -> SessionSummary:
        return SessionSummary(
            check_count=self._check_count,
            allow_count=self._allow_count,
            warn_count=self._warn_count,
            deny_count=self._deny_count,
            blocked_actions=list(self._blocked_actions),
        )
