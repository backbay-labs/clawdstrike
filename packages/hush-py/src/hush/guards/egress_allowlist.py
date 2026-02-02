"""Egress allowlist guard - controls outbound network access."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import List, Optional

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class EgressAllowlistConfig:
    """Configuration for EgressAllowlistGuard."""

    allow: List[str] = field(default_factory=list)
    block: List[str] = field(default_factory=list)
    default_action: str = "block"  # "block" or "allow"


class EgressAllowlistGuard(Guard):
    """Guard that controls outbound network access."""

    def __init__(self, config: Optional[EgressAllowlistConfig] = None) -> None:
        self._config = config or EgressAllowlistConfig()

    @property
    def name(self) -> str:
        return "egress_allowlist"

    def handles(self, action: GuardAction) -> bool:
        return action.action_type == "network_egress"

    def _matches_pattern(self, host: str, pattern: str) -> bool:
        """Check if host matches a pattern.

        Semantics match the Rust `globset` contract:
        - Full-string glob match (no implicit subdomain matching)
        - Case-insensitive
        - Supports `*`, `?`, and `[]` character classes
        """
        if not pattern:
            return False
        return fnmatch.fnmatchcase(host.lower(), pattern.lower())

    def _matches_any(self, host: str, patterns: List[str]) -> bool:
        """Check if host matches any pattern in the list."""
        return any(self._matches_pattern(host, p) for p in patterns)

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Check if network egress is allowed.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
        if not self.handles(action):
            return GuardResult.allow(self.name)

        host = action.host
        if host is None:
            return GuardResult.allow(self.name)

        # Check block list first (takes precedence)
        if self._matches_any(host, self._config.block):
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Egress to blocked destination: {host}",
            ).with_details({
                "host": host,
                "port": action.port,
                "reason": "explicitly_blocked",
            })

        # Check allow list
        if self._matches_any(host, self._config.allow):
            return GuardResult.allow(self.name)

        # Apply default action
        if self._config.default_action == "allow":
            return GuardResult.allow(self.name)

        return GuardResult.block(
            self.name,
            Severity.ERROR,
            f"Egress to unlisted destination: {host}",
        ).with_details({
            "host": host,
            "port": action.port,
            "reason": "not_in_allowlist",
        })


__all__ = ["EgressAllowlistGuard", "EgressAllowlistConfig"]
