"""Secret leak guard - detects secrets in output using regex patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from clawdstrike.guards.base import Guard, GuardAction, GuardContext, GuardResult, Severity


@dataclass
class SecretPattern:
    """A named regex pattern for secret detection."""

    name: str
    pattern: str
    severity: str = "critical"


DEFAULT_SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern(
        name="aws_access_key",
        pattern=r"AKIA[0-9A-Z]{16}",
        severity="critical",
    ),
    SecretPattern(
        name="github_token",
        pattern=r"gh[ps]_[A-Za-z0-9]{36}",
        severity="critical",
    ),
    SecretPattern(
        name="openai_key",
        pattern=r"\bsk-proj-[A-Za-z0-9_-]{40,}",
        severity="critical",
    ),
    SecretPattern(
        name="generic_api_key",
        pattern=r"\b(?:sk_live|sk_test)_[A-Za-z0-9]{24,}",
        severity="critical",
    ),
    SecretPattern(
        name="private_key",
        pattern=r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
        severity="critical",
    ),
]


def _severity_from_str(s: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "error": Severity.ERROR,
        "warning": Severity.WARNING,
        "info": Severity.INFO,
    }
    return mapping.get(s.lower(), Severity.CRITICAL)


@dataclass
class SecretLeakConfig:
    """Configuration for SecretLeakGuard."""

    patterns: List[SecretPattern] = field(default_factory=lambda: list(DEFAULT_SECRET_PATTERNS))
    skip_paths: List[str] = field(default_factory=list)
    enabled: bool = True
    # Legacy field for backwards compatibility
    secrets: List[str] = field(default_factory=list)


class SecretLeakGuard(Guard):
    """Guard that detects secret values in file writes and output using regex patterns."""

    OUTPUT_ACTIONS = {"output", "bash_output", "tool_result", "response"}

    def __init__(self, config: Optional[SecretLeakConfig] = None) -> None:
        self._config = config or SecretLeakConfig()
        self._compiled_patterns: List[tuple[SecretPattern, re.Pattern[str]]] = []
        for sp in self._config.patterns:
            try:
                compiled = re.compile(sp.pattern)
            except re.error as e:
                raise ValueError(
                    f"Invalid regex in secret pattern {sp.name!r}: {e}"
                ) from e
            self._compiled_patterns.append((sp, compiled))
        # Legacy literal secrets support
        self._secrets = [s for s in self._config.secrets if s and s.strip()]

    @property
    def name(self) -> str:
        return "secret_leak"

    def handles(self, action: GuardAction) -> bool:
        if action.action_type == "file_write":
            return True
        if action.action_type == "custom" and action.custom_type:
            return action.custom_type in self.OUTPUT_ACTIONS
        return False

    def _extract_text(self, action: GuardAction) -> str:
        """Extract text content from action."""
        if action.action_type == "file_write":
            if action.content is not None:
                try:
                    return action.content.decode("utf-8", errors="replace")
                except (AttributeError, UnicodeDecodeError):
                    return str(action.content)
            return ""

        data = action.custom_data
        if data is None:
            return ""
        for key in ("content", "output", "result", "error", "text"):
            value = data.get(key)
            if isinstance(value, str) and value:
                return value
        return ""

    def _should_skip_path(self, path: Optional[str]) -> bool:
        """Check if path matches skip_paths patterns."""
        if not path or not self._config.skip_paths:
            return False
        import fnmatch
        for pattern in self._config.skip_paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def check(self, action: GuardAction, context: GuardContext) -> GuardResult:
        if not self._config.enabled:
            return GuardResult.allow(self.name)

        if not self.handles(action):
            return GuardResult.allow(self.name)

        if self._should_skip_path(action.path):
            return GuardResult.allow(self.name)

        text = self._extract_text(action)
        if not text:
            return GuardResult.allow(self.name)

        # Check regex patterns
        for sp, compiled in self._compiled_patterns:
            match = compiled.search(text)
            if match:
                return GuardResult.block(
                    self.name,
                    _severity_from_str(sp.severity),
                    f"Secret pattern matched: {sp.name}",
                ).with_details({
                    "pattern_name": sp.name,
                    "action_type": action.custom_type or action.action_type,
                })

        # Legacy literal secret matching
        for secret in self._secrets:
            if secret in text:
                hint = secret[:4] + "..." if len(secret) > 4 else secret[:2] + "..."
                return GuardResult.block(
                    self.name,
                    Severity.CRITICAL,
                    "Secret value exposed in output",
                ).with_details({
                    "secret_hint": hint,
                    "action_type": action.custom_type or action.action_type,
                })

        return GuardResult.allow(self.name)


__all__ = ["SecretLeakGuard", "SecretLeakConfig", "SecretPattern", "DEFAULT_SECRET_PATTERNS"]
