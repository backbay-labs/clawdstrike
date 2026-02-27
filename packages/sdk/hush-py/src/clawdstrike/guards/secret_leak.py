"""Secret leak guard - detects secrets in output using regex patterns."""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field

from clawdstrike.guards.base import (
    Action,
    Guard,
    GuardContext,
    GuardResult,
    Severity,
)

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "info": Severity.INFO,
}


@dataclass
class SecretPattern:
    """A named regex pattern for secret detection."""

    name: str
    pattern: str
    severity: Severity | str = "critical"

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            resolved = _SEVERITY_MAP.get(self.severity.lower())
            if resolved is not None:
                object.__setattr__(self, "severity", resolved)
            else:
                warnings.warn(
                    f"Unknown severity {self.severity!r} on SecretPattern {self.name!r}; "
                    f"defaulting to CRITICAL",
                    stacklevel=2,
                )
                object.__setattr__(self, "severity", Severity.CRITICAL)


DEFAULT_SECRET_PATTERNS: list[SecretPattern] = [
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
    SecretPattern(
        name="aws_secret_key",
        pattern=r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}",
        severity="critical",
    ),
    SecretPattern(
        name="github_pat",
        pattern=r"github_pat_[A-Za-z0-9_]{82}",
        severity="critical",
    ),
    SecretPattern(
        name="anthropic_key",
        pattern=r"\bsk-ant-[A-Za-z0-9_-]{40,}",
        severity="critical",
    ),
    SecretPattern(
        name="npm_token",
        pattern=r"npm_[A-Za-z0-9]{36}",
        severity="critical",
    ),
    SecretPattern(
        name="slack_token",
        pattern=r"xox[baprs]-[A-Za-z0-9\-]{10,}",
        severity="critical",
    ),
    SecretPattern(
        name="generic_secret",
        pattern=r"(?i)(secret|password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9!@#$%^&*]{8,}",
        severity="critical",
    ),
]


def _severity_from_pattern(sp: SecretPattern) -> Severity:
    """Get the Severity enum value from a SecretPattern.

    After __post_init__, severity is always a Severity enum, but this
    provides a safe fallback for any edge cases.
    """
    if isinstance(sp.severity, Severity):
        return sp.severity
    return _SEVERITY_MAP.get(str(sp.severity).lower(), Severity.CRITICAL)


@dataclass
class SecretLeakConfig:
    """Configuration for SecretLeakGuard."""

    patterns: list[SecretPattern] = field(default_factory=lambda: list(DEFAULT_SECRET_PATTERNS))
    skip_paths: list[str] = field(default_factory=list)
    enabled: bool = True
    # Legacy field for backwards compatibility
    secrets: list[str] = field(default_factory=list)


class SecretLeakGuard(Guard):
    """Guard that detects secret values in file writes and output using regex patterns."""

    OUTPUT_ACTIONS = {"output", "bash_output", "tool_result", "response"}

    def __init__(self, config: SecretLeakConfig | None = None) -> None:
        self._config = config or SecretLeakConfig()
        self._compiled_patterns: list[tuple[SecretPattern, re.Pattern[str]]] = []
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

    def handles(self, action: Action) -> bool:
        if action.action_type in ("file_write", "patch"):
            return True
        if action.action_type == "custom":
            custom_type: str | None = getattr(action, "custom_type", None)
            return custom_type is not None and custom_type in self.OUTPUT_ACTIONS
        return False

    def _extract_text(self, action: Action) -> str:
        """Extract text content from action."""
        if action.action_type == "file_write":
            content: bytes | None = getattr(action, "content", None)
            if content is not None:
                try:
                    return content.decode("utf-8", errors="replace")
                except (AttributeError, UnicodeDecodeError):
                    return str(content)
            return ""

        if action.action_type == "patch":
            diff: str | None = getattr(action, "diff", None)
            if diff is not None:
                return diff
            content = getattr(action, "content", None)
            if content is not None:
                try:
                    return content.decode("utf-8", errors="replace")
                except (AttributeError, UnicodeDecodeError):
                    return str(content)
            return ""

        data: dict | None = getattr(action, "custom_data", None)
        if data is None:
            return ""
        for key in ("content", "output", "result", "error", "text"):
            value = data.get(key)
            if isinstance(value, str) and value:
                return value
        return ""

    def _should_skip_path(self, path: str | None) -> bool:
        """Check if path matches skip_paths patterns."""
        if not path or not self._config.skip_paths:
            return False
        import fnmatch
        for pattern in self._config.skip_paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        if not self._config.enabled:
            return GuardResult.allow(self.name)

        if not self.handles(action):
            return GuardResult.allow(self.name)

        path: str | None = getattr(action, "path", None)
        if self._should_skip_path(path):
            return GuardResult.allow(self.name)

        text = self._extract_text(action)
        if not text:
            return GuardResult.allow(self.name)

        # Check regex patterns
        for sp, compiled in self._compiled_patterns:
            match = compiled.search(text)
            if match:
                custom_type: str | None = getattr(action, "custom_type", None)
                return GuardResult.block(
                    self.name,
                    _severity_from_pattern(sp),
                    f"Secret pattern matched: {sp.name}",
                ).with_details({
                    "pattern_name": sp.name,
                    "action_type": custom_type or action.action_type,
                })

        # Legacy literal secret matching
        for secret in self._secrets:
            if secret in text:
                hint = secret[:4] + "..." if len(secret) > 4 else secret[:2] + "..."
                custom_type = getattr(action, "custom_type", None)
                return GuardResult.block(
                    self.name,
                    Severity.CRITICAL,
                    "Secret value exposed in output",
                ).with_details({
                    "secret_hint": hint,
                    "action_type": custom_type or action.action_type,
                })

        return GuardResult.allow(self.name)


__all__ = ["SecretLeakGuard", "SecretLeakConfig", "SecretPattern", "DEFAULT_SECRET_PATTERNS"]
