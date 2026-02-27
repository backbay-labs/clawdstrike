"""Core types for the Clawdstrike public API."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from clawdstrike.guards.base import GuardResult, Severity


class DecisionStatus(str, Enum):
    """Overall decision status."""
    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    """Aggregated decision from guard evaluation.

    This is the primary return type from Clawdstrike.check_*() methods.
    """
    status: DecisionStatus
    guard: str | None = None
    severity: Severity | None = None
    message: str | None = None
    details: Any | None = None
    per_guard: list[GuardResult] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        """True if the action is allowed (status is ALLOW or WARN)."""
        return self.status != DecisionStatus.DENY

    @property
    def denied(self) -> bool:
        """True if the action is denied."""
        return self.status == DecisionStatus.DENY

    @classmethod
    def from_guard_results(cls, results: list[GuardResult]) -> Decision:
        """Aggregate guard results into a single Decision.

        Rules:
        - Any deny (not allowed) -> overall DENY
        - Any warn (allowed + WARNING severity) -> overall WARN
        - All allow -> overall ALLOW
        - Highest severity wins among denies, then warns
        - Guard name and message come from the highest-severity result
        """
        if not results:
            return cls(status=DecisionStatus.ALLOW, per_guard=list(results))

        # Separate denies and warns
        denies = [r for r in results if not r.allowed]
        warns = [r for r in results if r.allowed and r.severity == Severity.WARNING]

        if denies:
            # Sort by severity (CRITICAL > ERROR > WARNING > INFO)
            severity_order = {
                Severity.CRITICAL: 4,
                Severity.ERROR: 3,
                Severity.WARNING: 2,
                Severity.INFO: 1,
            }
            worst = max(denies, key=lambda r: severity_order.get(r.severity, 0))
            return cls(
                status=DecisionStatus.DENY,
                guard=worst.guard,
                severity=worst.severity,
                message=worst.message,
                details=worst.details,
                per_guard=list(results),
            )

        if warns:
            severity_order = {
                Severity.CRITICAL: 4,
                Severity.ERROR: 3,
                Severity.WARNING: 2,
                Severity.INFO: 1,
            }
            worst = max(warns, key=lambda r: severity_order.get(r.severity, 0))
            return cls(
                status=DecisionStatus.WARN,
                guard=worst.guard,
                severity=Severity.WARNING,
                message=worst.message,
                details=worst.details,
                per_guard=list(results),
            )

        return cls(status=DecisionStatus.ALLOW, per_guard=list(results))


@dataclass
class SessionOptions:
    """Options for creating a ClawdstrikeSession."""
    agent_id: str | None = None
    session_id: str | None = None
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class SessionSummary:
    """Summary statistics for a ClawdstrikeSession."""
    check_count: int = 0
    allow_count: int = 0
    warn_count: int = 0
    deny_count: int = 0
    blocked_actions: list[str] = field(default_factory=list)
