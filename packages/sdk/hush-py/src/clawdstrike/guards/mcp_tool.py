"""MCP tool guard - controls which MCP tools can be invoked."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from clawdstrike.guards.base import (
    Action,
    Guard,
    GuardContext,
    GuardResult,
    Severity,
)


@dataclass
class McpToolConfig:
    """Configuration for McpToolGuard."""

    allow: list[str] = field(default_factory=list)
    block: list[str] = field(default_factory=list)
    require_confirmation: list[str] = field(default_factory=list)
    default_action: str = "block"  # "block" or "allow"
    max_args_size: int | None = None
    additional_allow: list[str] = field(default_factory=list)
    remove_allow: list[str] = field(default_factory=list)
    additional_block: list[str] = field(default_factory=list)
    remove_block: list[str] = field(default_factory=list)
    enabled: bool = True


class McpToolGuard(Guard):
    """Guard that controls MCP tool invocation."""

    def __init__(self, config: McpToolConfig | None = None) -> None:
        self._config = config or McpToolConfig()

    @property
    def name(self) -> str:
        return "mcp_tool"

    def handles(self, action: Action) -> bool:
        return action.action_type == "mcp_tool"

    def _matches_any(self, tool: str, patterns: list[str]) -> bool:
        """Check if tool name matches any pattern."""
        return any(fnmatch.fnmatch(tool, pattern) for pattern in patterns)

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        """Check if MCP tool invocation is allowed.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
        if not self.handles(action):
            return GuardResult.allow(self.name)

        tool: str | None = getattr(action, "tool", None)
        if tool is None:
            return GuardResult.allow(self.name)

        # Check block list first (takes precedence)
        if self._matches_any(tool, self._config.block):
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"MCP tool explicitly blocked: {tool}",
            ).with_details({
                "tool": tool,
                "reason": "explicitly_blocked",
            })

        # Check allow list
        if self._matches_any(tool, self._config.allow):
            return GuardResult.allow(self.name)

        # Apply default action
        if self._config.default_action == "allow":
            return GuardResult.allow(self.name)

        return GuardResult.block(
            self.name,
            Severity.ERROR,
            f"MCP tool not in allowlist: {tool}",
        ).with_details({
            "tool": tool,
            "reason": "not_in_allowlist",
        })


__all__ = ["McpToolGuard", "McpToolConfig"]
