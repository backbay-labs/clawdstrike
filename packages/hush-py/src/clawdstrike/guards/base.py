"""Base guard types and interfaces.

Provides the Guard abstract base class and supporting types.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    """Severity level for guard violations."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class GuardResult:
    """Result of a guard check."""

    allowed: bool
    guard: str
    severity: Severity
    message: str
    details: Optional[Dict[str, Any]] = None

    @classmethod
    def allow(cls, guard: str) -> GuardResult:
        """Create an allow result."""
        return cls(
            allowed=True,
            guard=guard,
            severity=Severity.INFO,
            message="Allowed",
        )

    @classmethod
    def block(cls, guard: str, severity: Severity, message: str) -> GuardResult:
        """Create a block result."""
        return cls(
            allowed=False,
            guard=guard,
            severity=severity,
            message=message,
        )

    @classmethod
    def warn(cls, guard: str, message: str) -> GuardResult:
        """Create a warning result (allowed but logged)."""
        return cls(
            allowed=True,
            guard=guard,
            severity=Severity.WARNING,
            message=message,
        )

    def with_details(self, details: Dict[str, Any]) -> GuardResult:
        """Add details to the result."""
        self.details = details
        return self


@dataclass
class GuardContext:
    """Context passed to guards for evaluation."""

    cwd: Optional[str] = None
    session_id: Optional[str] = None
    agent_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class GuardAction:
    """Action to be checked by guards."""

    action_type: str
    path: Optional[str] = None
    content: Optional[bytes] = None
    host: Optional[str] = None
    port: Optional[int] = None
    tool: Optional[str] = None
    args: Optional[Dict[str, Any]] = None
    command: Optional[str] = None
    diff: Optional[str] = None
    custom_type: Optional[str] = None
    custom_data: Optional[Dict[str, Any]] = None

    @classmethod
    def file_access(cls, path: str) -> GuardAction:
        """Create a file access action."""
        return cls(action_type="file_access", path=path)

    @classmethod
    def file_write(cls, path: str, content: bytes) -> GuardAction:
        """Create a file write action."""
        return cls(action_type="file_write", path=path, content=content)

    @classmethod
    def network_egress(cls, host: str, port: int) -> GuardAction:
        """Create a network egress action."""
        return cls(action_type="network_egress", host=host, port=port)

    @classmethod
    def shell_command(cls, command: str) -> GuardAction:
        """Create a shell command action."""
        return cls(action_type="shell_command", command=command)

    @classmethod
    def mcp_tool(cls, tool: str, args: Dict[str, Any]) -> GuardAction:
        """Create an MCP tool action."""
        return cls(action_type="mcp_tool", tool=tool, args=args)

    @classmethod
    def patch(cls, path: str, diff: str) -> GuardAction:
        """Create a patch action."""
        return cls(action_type="patch", path=path, diff=diff)

    @classmethod
    def custom(cls, custom_type: str, data: Dict[str, Any]) -> GuardAction:
        """Create a custom action."""
        return cls(action_type="custom", custom_type=custom_type, custom_data=data)


class Guard(ABC):
    """Abstract base class for security guards."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the guard."""
        ...

    @abstractmethod
    def handles(self, action: GuardAction) -> bool:
        """Check if this guard handles the given action type."""
        ...

    @abstractmethod
    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Evaluate the action.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult indicating whether action is allowed
        """
        ...


__all__ = [
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
]
