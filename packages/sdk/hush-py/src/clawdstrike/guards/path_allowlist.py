"""Path allowlist guard - restricts file access to allowed paths only."""

from __future__ import annotations

from dataclasses import dataclass, field

from wcmatch import glob as wcglob

from clawdstrike.guards.base import Action, Guard, GuardContext, GuardResult, Severity


@dataclass
class PathAllowlistConfig:
    """Configuration for PathAllowlistGuard."""
    allowed_paths: list[str] = field(default_factory=list)
    enabled: bool = True


class PathAllowlistGuard(Guard):
    """Guard that restricts file access to allowed paths only.

    Inverse of ForbiddenPathGuard -- only paths matching the allowlist are permitted.
    If the allowlist is empty, all paths are allowed (guard is effectively disabled).
    """

    def __init__(self, config: PathAllowlistConfig | None = None) -> None:
        self._config = config or PathAllowlistConfig()

    @property
    def name(self) -> str:
        return "path_allowlist"

    def handles(self, action: Action) -> bool:
        return action.action_type in ("file_access", "file_write", "patch")

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        if not self._config.enabled:
            return GuardResult.allow(self.name)
        if not self.handles(action):
            return GuardResult.allow(self.name)

        # If no allowlist configured, allow all
        if not self._config.allowed_paths:
            return GuardResult.allow(self.name)

        path: str | None = getattr(action, "path", None)
        if path is None:
            return GuardResult.allow(self.name)

        normalized = path.replace("\\", "/")

        for pattern in self._config.allowed_paths:
            if wcglob.globmatch(normalized, pattern, flags=wcglob.GLOBSTAR):
                return GuardResult.allow(self.name)

        return GuardResult.block(
            self.name,
            Severity.ERROR,
            f"Path not in allowlist: {path}",
        ).with_details({
            "path": path,
            "reason": "not_in_allowlist",
        })
