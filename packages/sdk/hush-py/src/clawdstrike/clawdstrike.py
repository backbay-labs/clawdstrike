"""Clawdstrike facade -- the primary entry point for the SDK."""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Any

from clawdstrike.exceptions import ConfigurationError
from clawdstrike.guards.base import (
    Action,
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


class Clawdstrike:
    """Main facade for Clawdstrike security enforcement.

    Usage:
        cs = Clawdstrike.with_defaults("strict")
        decision = cs.check_file("/etc/shadow")
        if decision.denied:
            print(f"Blocked: {decision.message}")
    """

    def __init__(self, engine: PolicyEngine, *, cwd: str | None = None) -> None:
        self._engine = engine
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
        if path is not None and path.is_file():
            policy = Policy.from_yaml_file_with_extends(str(path))
        else:
            policy = Policy.from_yaml_with_extends(str(yaml_or_path))
        return cls(PolicyEngine(policy), cwd=cwd)

    @classmethod
    def with_defaults(cls, ruleset: str = "default", *, cwd: str | None = None) -> Clawdstrike:
        """Create with a built-in ruleset.

        Args:
            ruleset: One of "permissive", "default", "strict", "ai-agent", "cicd"
            cwd: Working directory for context
        """
        yaml_str = f'version: "1.1.0"\nname: {ruleset}\nextends: {ruleset}\n'
        try:
            policy = Policy.from_yaml_with_extends(yaml_str)
        except Exception as e:
            raise ConfigurationError(f"Failed to load built-in ruleset {ruleset!r}: {e}") from e
        return cls(PolicyEngine(policy), cwd=cwd)

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
            policy = copy.copy(policy)
        policy.settings.fail_fast = fail_fast
        return cls(PolicyEngine(policy), cwd=cwd)

    def _context(self, **kwargs: Any) -> GuardContext:
        """Build a GuardContext with defaults."""
        filtered = {k: v for k, v in kwargs.items() if k != "cwd"}
        return GuardContext(cwd=kwargs.get("cwd", self._cwd), **filtered)

    def _decide(self, results: list[GuardResult]) -> Decision:
        """Convert guard results to a Decision."""
        return Decision.from_guard_results(results)

    def check(self, action: Action, **context_kwargs: Any) -> Decision:
        """Check an action against all guards.

        Args:
            action: The action to check (any typed Action variant)
            **context_kwargs: Additional context (session_id, agent_id, metadata)
        """
        ctx = self._context(**context_kwargs)
        results = self._engine.check(action, ctx)
        return self._decide(results)

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
        if operation == "write":
            action: Action = FileWriteAction(path=str_path, content=content or b"")
        else:
            action = FileAccessAction(path=str_path)
        return self.check(action)

    def check_command(self, command: str) -> Decision:
        """Check a shell command."""
        return self.check(ShellCommandAction(command=command))

    def check_network(self, host: str, port: int = 443) -> Decision:
        """Check network egress."""
        return self.check(NetworkEgressAction(host=host, port=port))

    def check_patch(self, path: str | os.PathLike[str], diff: str) -> Decision:
        """Check a code patch."""
        return self.check(PatchAction(path=str(path), diff=diff))

    def check_mcp_tool(self, tool: str, args: dict[str, Any] | None = None) -> Decision:
        """Check an MCP tool invocation."""
        return self.check(McpToolAction(tool=tool, args=args or {}))

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
