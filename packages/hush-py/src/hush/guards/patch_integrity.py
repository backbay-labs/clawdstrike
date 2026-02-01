"""Patch integrity guard - validates code patches."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple

from hush.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class PatchIntegrityConfig:
    """Configuration for PatchIntegrityGuard."""

    max_additions: int = 1000
    max_deletions: int = 500
    require_balance: bool = False
    max_imbalance_ratio: float = 5.0


class PatchIntegrityGuard(Guard):
    """Guard that validates patch size and balance."""

    def __init__(self, config: Optional[PatchIntegrityConfig] = None) -> None:
        self._config = config or PatchIntegrityConfig()

    @property
    def name(self) -> str:
        return "patch_integrity"

    def handles(self, action: GuardAction) -> bool:
        return action.action_type == "patch"

    def _count_changes(self, diff: str) -> Tuple[int, int]:
        """Count additions and deletions in a diff.

        Returns:
            Tuple of (additions, deletions)
        """
        additions = 0
        deletions = 0

        for line in diff.split("\n"):
            # Skip diff headers
            if line.startswith("@@") or line.startswith("---") or line.startswith("+++"):
                continue
            if line.startswith("+") and not line.startswith("+++"):
                additions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

        return additions, deletions

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Check if patch is within allowed limits.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
        if not self.handles(action):
            return GuardResult.allow(self.name)

        diff = action.diff
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
                return GuardResult.block(
                    self.name,
                    Severity.WARNING,
                    f"Patch imbalance ratio too high: {ratio:.1f} > {self._config.max_imbalance_ratio}",
                ).with_details({
                    "additions": additions,
                    "deletions": deletions,
                    "ratio": ratio,
                    "max_ratio": self._config.max_imbalance_ratio,
                })

        return GuardResult.allow(self.name).with_details({
            "additions": additions,
            "deletions": deletions,
        })


__all__ = ["PatchIntegrityGuard", "PatchIntegrityConfig"]
