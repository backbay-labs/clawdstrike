"""Forbidden path guard - blocks access to sensitive paths."""

from __future__ import annotations

from dataclasses import dataclass, field

from wcmatch import glob as wcglob

from clawdstrike.guards.base import (
    Action,
    Guard,
    GuardContext,
    GuardResult,
    Severity,
)


def default_forbidden_patterns() -> list[str]:
    """Default patterns for forbidden paths."""
    return [
        # SSH keys
        "**/.ssh/**",
        "**/id_rsa*",
        "**/id_ed25519*",
        "**/id_ecdsa*",
        # AWS credentials
        "**/.aws/**",
        # Environment files
        "**/.env",
        "**/.env.*",
        # Git credentials
        "**/.git-credentials",
        "**/.gitconfig",
        # GPG keys
        "**/.gnupg/**",
        # Kubernetes
        "**/.kube/**",
        # Docker
        "**/.docker/**",
        # NPM tokens
        "**/.npmrc",
        # Password stores
        "**/.password-store/**",
        "**/pass/**",
        # 1Password
        "**/.1password/**",
        # System paths
        "/etc/shadow",
        "/etc/passwd",
        "/etc/sudoers",
    ]


@dataclass
class ForbiddenPathConfig:
    """Configuration for ForbiddenPathGuard."""

    patterns: list[str] = field(default_factory=default_forbidden_patterns)
    exceptions: list[str] = field(default_factory=list)


class ForbiddenPathGuard(Guard):
    """Guard that blocks access to sensitive paths."""

    def __init__(self, config: ForbiddenPathConfig | None = None) -> None:
        self._config = config or ForbiddenPathConfig()

    @property
    def name(self) -> str:
        return "forbidden_path"

    def handles(self, action: Action) -> bool:
        return action.action_type in ("file_access", "file_write", "patch")

    def is_forbidden(self, path: str) -> bool:
        """Check if a path is forbidden.

        Args:
            path: Path to check

        Returns:
            True if path is forbidden, False otherwise
        """
        # Normalize path (handle Windows paths)
        normalized = path.replace("\\", "/")

        # Check exceptions first
        for exception in self._config.exceptions:
            if wcglob.globmatch(normalized, exception, flags=wcglob.GLOBSTAR):
                return False

        # Check forbidden patterns
        for pattern in self._config.patterns:
            if wcglob.globmatch(normalized, pattern, flags=wcglob.GLOBSTAR):
                return True

        return False

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        """Check if file access is allowed.

        Args:
            action: The action to check
            context: Execution context

        Returns:
            GuardResult
        """
        if not self.handles(action):
            return GuardResult.allow(self.name)

        path: str | None = getattr(action, "path", None)
        if path is None:
            return GuardResult.allow(self.name)

        if self.is_forbidden(path):
            return GuardResult.block(
                self.name,
                Severity.CRITICAL,
                f"Access to forbidden path: {path}",
            ).with_details({
                "path": path,
                "reason": "matches_forbidden_pattern",
            })

        return GuardResult.allow(self.name)


__all__ = ["ForbiddenPathGuard", "ForbiddenPathConfig"]
