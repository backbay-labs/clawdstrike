"""Patch integrity guard - validates code patches."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from clawdstrike.guards.base import (
    Action,
    Guard,
    GuardContext,
    GuardResult,
    Severity,
)


@dataclass
class PatchIntegrityConfig:
    """Configuration for PatchIntegrityGuard."""

    max_additions: int = 1000
    max_deletions: int = 500
    require_balance: bool = False
    max_imbalance_ratio: float = 5.0
    forbidden_patterns: list[str] = field(default_factory=list)


class PatchIntegrityGuard(Guard):
    """Guard that validates patch size, balance, and forbidden patterns."""

    def __init__(self, config: PatchIntegrityConfig | None = None) -> None:
        self._config = config or PatchIntegrityConfig()
        self._compiled_forbidden: list[tuple[str, re.Pattern[str]]] = []
        for pattern_str in self._config.forbidden_patterns:
            try:
                compiled = re.compile(pattern_str)
            except re.error as e:
                raise ValueError(
                    f"Invalid regex in forbidden_patterns: {pattern_str!r}: {e}"
                ) from e
            self._compiled_forbidden.append((pattern_str, compiled))

    @property
    def name(self) -> str:
        return "patch_integrity"

    def handles(self, action: Action) -> bool:
        return action.action_type == "patch"

    def _count_changes(self, diff: str) -> tuple[int, int]:
        """Count additions and deletions in a diff."""
        additions = 0
        deletions = 0

        for line in diff.split("\n"):
            if line.startswith("@@") or line.startswith("---") or line.startswith("+++"):
                continue
            if line.startswith("+") and not line.startswith("+++"):
                additions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

        return additions, deletions

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        if not self.handles(action):
            return GuardResult.allow(self.name)

        diff: str | None = getattr(action, "diff", None)
        if diff is None:
            return GuardResult.allow(self.name)

        additions, deletions = self._count_changes(diff)

        # Check additions limit
        if additions > self._config.max_additions:
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Patch exceeds max additions: {additions} > {self._config.max_additions}",
            ).with_details({
                "additions": additions,
                "deletions": deletions,
                "max_additions": self._config.max_additions,
            })

        # Check deletions limit
        if deletions > self._config.max_deletions:
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Patch exceeds max deletions: {deletions} > {self._config.max_deletions}",
            ).with_details({
                "additions": additions,
                "deletions": deletions,
                "max_deletions": self._config.max_deletions,
            })

        # Check balance if required
        if self._config.require_balance and deletions > 0:
            ratio = additions / deletions
            if ratio > self._config.max_imbalance_ratio:
                msg = (
                    f"Patch imbalance ratio too high:"
                    f" {ratio:.1f} > {self._config.max_imbalance_ratio}"
                )
                return GuardResult.block(
                    self.name, Severity.WARNING, msg,
                ).with_details({
                    "additions": additions,
                    "deletions": deletions,
                    "ratio": ratio,
                    "max_ratio": self._config.max_imbalance_ratio,
                })

        # Check forbidden patterns in the diff
        for pattern_str, compiled in self._compiled_forbidden:
            match = compiled.search(diff)
            if match:
                return GuardResult.block(
                    self.name,
                    Severity.CRITICAL,
                    f"Patch contains forbidden pattern: {pattern_str}",
                ).with_details({
                    "forbidden_pattern": pattern_str,
                    "additions": additions,
                    "deletions": deletions,
                })

        return GuardResult.allow(self.name).with_details({
            "additions": additions,
            "deletions": deletions,
        })


__all__ = ["PatchIntegrityGuard", "PatchIntegrityConfig"]
