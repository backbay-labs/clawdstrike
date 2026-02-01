"""MCP tool guard - controls which MCP tools can be invoked."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import List, Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class McpToolConfig:
    """Configuration for McpToolGuard."""

    allow: List[str] = field(default_factory=list)
    block: List[str] = field(default_factory=list)
    default_action: str = "block"  # "block" or "allow"


class McpToolGuard(Guard):
    """Guard that controls MCP tool invocation."""

    def __init__(self, config: Optional[McpToolConfig] = None) -> None:
        self._config = config or McpToolConfig()

    @property
    def name(self) -> str:
        return "mcp_tool"

    def handles(self, action: GuardAction) -> bool:
        return action.action_type == "mcp_tool"

    def _matches_any(self, tool: str, patterns: List[str]) -> bool:
        """Check if tool name matches any pattern."""
        return any(fnmatch.fnmatch(tool, pattern) for pattern in patterns)

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Check if MCP tool invocation is allowed.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
        if not self.handles(action):
            return GuardResult.allow(self.name)

        tool = action.tool
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
