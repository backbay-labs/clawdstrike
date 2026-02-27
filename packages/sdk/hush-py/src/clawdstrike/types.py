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

        severity_order = {
            Severity.CRITICAL: 4,
            Severity.ERROR: 3,
            Severity.WARNING: 2,
            Severity.INFO: 1,
        }

        if denies:
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

    @classmethod
    def from_report_dict(cls, report: dict) -> Decision:
        """Create a Decision from a GuardReport dict (as returned by native or pure-python backend).

        Expected shape::

            {
                "overall": {"allowed": bool, "guard": str, ...},
                "per_guard": [{"allowed": bool, "guard": str, ...}, ...]
            }
        """
        severity_map = {
            "info": Severity.INFO,
            "warning": Severity.WARNING,
            "error": Severity.ERROR,
            "critical": Severity.CRITICAL,
        }

        per_guard = [
            GuardResult(
                allowed=r["allowed"],
                guard=r["guard"],
                severity=severity_map.get(str(r.get("severity", "info")).lower(), Severity.INFO),
                message=r.get("message", ""),
                details=r.get("details"),
            )
            for r in report.get("per_guard", [])
        ]

        # Use the backend's overall verdict directly instead of re-aggregating,
        # since the native engine may have tie-break behavior (e.g. preferring
        # sanitize warnings) that from_guard_results cannot replicate.
        overall = report.get("overall", {})
        if not overall.get("allowed", True):
            status = DecisionStatus.DENY
        elif severity_map.get(str(overall.get("severity", "info")).lower(), Severity.INFO) == Severity.WARNING:
            status = DecisionStatus.WARN
        else:
            status = DecisionStatus.ALLOW

        return cls(
            status=status,
            guard=overall.get("guard"),
            severity=severity_map.get(str(overall.get("severity", "info")).lower(), Severity.INFO),
            message=overall.get("message"),
            details=overall.get("details"),
            per_guard=per_guard,
        )


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
