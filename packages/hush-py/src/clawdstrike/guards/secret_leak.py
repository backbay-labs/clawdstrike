"""Secret leak guard - detects secrets in output."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from clawdstrike.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class SecretLeakConfig:
    """Configuration for SecretLeakGuard."""

    secrets: List[str] = field(default_factory=list)
    enabled: bool = True


class SecretLeakGuard(Guard):
    """Guard that detects secret values in output."""

    # Action types that may contain output
    OUTPUT_ACTIONS = {"output", "bash_output", "tool_result", "response"}

    def __init__(self, config: Optional[SecretLeakConfig] = None) -> None:
        self._config = config or SecretLeakConfig()
        # Filter out empty/whitespace-only secrets
        self._secrets = [s for s in self._config.secrets if s and s.strip()]

    @property
    def name(self) -> str:
        return "secret_leak"

    def handles(self, action: GuardAction) -> bool:
        if action.action_type == "custom" and action.custom_type:
            return action.custom_type in self.OUTPUT_ACTIONS
        return False

    def _extract_text(self, data: Optional[Dict[str, Any]]) -> str:
        """Extract text content from action data."""
        if data is None:
            return ""

        # Check common content field names
        for key in ("content", "output", "result", "error", "text"):
            value = data.get(key)
            if isinstance(value, str) and value:
                return value

        return ""

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        """Check if output contains secrets.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
        # Skip if disabled or no secrets configured
        if not self._config.enabled or not self._secrets:
            return GuardResult.allow(self.name)

        if not self.handles(action):
            return GuardResult.allow(self.name)

        text = self._extract_text(action.custom_data)
        if not text:
            return GuardResult.allow(self.name)

        # Check for any secret in the output
        for secret in self._secrets:
            if secret in text:
                # Create hint (first 4 chars + "...")
                hint = secret[:4] + "..." if len(secret) > 4 else secret[:2] + "..."

                return GuardResult.block(
                    self.name,
                    Severity.CRITICAL,
                    "Secret value exposed in output",
                ).with_details({
                    "secret_hint": hint,
                    "action_type": action.custom_type,
                })

        return GuardResult.allow(self.name)


__all__ = ["SecretLeakGuard", "SecretLeakConfig"]
