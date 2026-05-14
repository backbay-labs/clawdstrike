"""Base guard types and interfaces.

Provides the Guard abstract base class, typed action variants, and supporting types.
"""

from __future__ import annotations

import dataclasses
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from collections.abc import Mapping
from typing import Any

from clawdstrike.origin import OriginContext, normalize_origin_input


class Severity(str, Enum):
    """Severity level for guard violations."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass(frozen=True)
class GuardResult:
    """Result of a guard check."""

    allowed: bool
    guard: str
    severity: Severity
    message: str
    details: dict[str, Any] | None = None

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

    def with_details(self, details: dict[str, Any]) -> GuardResult:
        """Return a new GuardResult with the given details."""
        return dataclasses.replace(self, details=details)


@dataclass
class GuardContext:
    """Context passed to guards for evaluation."""

    cwd: str | None = None
    session_id: str | None = None
    agent_id: str | None = None
    metadata: dict[str, Any] | None = None
    origin: OriginContext | Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        self.origin = normalize_origin_input(self.origin)


# ---------------------------------------------------------------------------
# Typed action variants (frozen dataclasses)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FileAccessAction:
    """Action representing a file access (read)."""

    path: str
    action_type: str = "file_access"


@dataclass(frozen=True)
class FileWriteAction:
    """Action representing a file write."""

    path: str
    content: bytes
    action_type: str = "file_write"


@dataclass(frozen=True)
class NetworkEgressAction:
    """Action representing outbound network access."""

    host: str
    port: int
    action_type: str = "network_egress"


@dataclass(frozen=True)
class ShellCommandAction:
    """Action representing a shell command execution."""

    command: str
    action_type: str = "shell_command"


@dataclass(frozen=True)
class McpToolAction:
    """Action representing an MCP tool invocation."""

    tool: str
    args: dict[str, Any]
    action_type: str = "mcp_tool"


@dataclass(frozen=True)
class PatchAction:
    """Action representing a code patch."""

    path: str
    diff: str
    action_type: str = "patch"


@dataclass(frozen=True)
class CustomAction:
    """Action representing a custom/extension action."""

    custom_type: str
    custom_data: dict[str, Any]
    action_type: str = "custom"


Action = (
    FileAccessAction
    | FileWriteAction
    | NetworkEgressAction
    | ShellCommandAction
    | McpToolAction
    | PatchAction
    | CustomAction
)

class GuardAction:
    """Backward-compatible factory for creating typed Action variants.

    Existing code that calls GuardAction.file_access(...) etc. will get
    the appropriate typed action dataclass. New code should use the typed
    action constructors directly.
    """

    @classmethod
    def file_access(cls, path: str) -> FileAccessAction:
        """Create a file access action."""
        return FileAccessAction(path=path)

    @classmethod
    def file_write(cls, path: str, content: bytes) -> FileWriteAction:
        """Create a file write action."""
        return FileWriteAction(path=path, content=content)

    @classmethod
    def network_egress(cls, host: str, port: int) -> NetworkEgressAction:
        """Create a network egress action."""
        return NetworkEgressAction(host=host, port=port)

    @classmethod
    def shell_command(cls, command: str) -> ShellCommandAction:
        """Create a shell command action."""
        return ShellCommandAction(command=command)

    @classmethod
    def mcp_tool(cls, tool: str, args: dict[str, Any]) -> McpToolAction:
        """Create an MCP tool action."""
        return McpToolAction(tool=tool, args=args)

    @classmethod
    def patch(cls, path: str, diff: str) -> PatchAction:
        """Create a patch action."""
        return PatchAction(path=path, diff=diff)

    @classmethod
    def custom(cls, custom_type: str, data: dict[str, Any]) -> CustomAction:
        """Create a custom action."""
        return CustomAction(custom_type=custom_type, custom_data=data)


class Guard(ABC):
    """Abstract base class for security guards."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the guard."""

    @abstractmethod
    def handles(self, action: Action) -> bool:
        """Check if this guard handles the given action type."""

    @abstractmethod
    def check(self, action: Action, context: GuardContext) -> GuardResult:
        """Evaluate the action.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult indicating whether action is allowed
        """


class AsyncGuard(ABC):
    """Abstract base class for asynchronous security guards."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the guard."""

    @abstractmethod
    def handles(self, action: Action) -> bool:
        """Check if this guard handles the given action type."""

    @abstractmethod
    async def check(self, action: Action, context: GuardContext) -> GuardResult:
        """Evaluate the action asynchronously.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult indicating whether action is allowed
        """


__all__ = [
    "Severity",
    "GuardResult",
    "GuardContext",
    # Typed action variants
    "FileAccessAction",
    "FileWriteAction",
    "NetworkEgressAction",
    "ShellCommandAction",
    "McpToolAction",
    "PatchAction",
    "CustomAction",
    "Action",
    # Backward-compatible alias
    "GuardAction",
    # Guard ABCs
    "Guard",
    "AsyncGuard",
]
