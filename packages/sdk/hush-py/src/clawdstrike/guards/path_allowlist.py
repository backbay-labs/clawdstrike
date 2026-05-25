"""Path allowlist guard - restricts file access to allowed paths only."""

from __future__ import annotations

from dataclasses import dataclass, field

from wcmatch import glob as wcglob

from clawdstrike.guards.base import Action, Guard, GuardContext, GuardResult, Severity


@dataclass(init=False)
class PathAllowlistConfig:
    """Configuration for PathAllowlistGuard.

    Mirrors the Rust schema (`crates/libs/clawdstrike/src/guards/path_allowlist.rs`):
    ``file_access_allow``, ``file_write_allow``, and ``patch_allow`` provide
    per-action-type allowlists. ``allowed_paths`` is a legacy alias kept for
    backward compatibility: if provided, it seeds all three per-action lists when
    they would otherwise be empty.
    """

    enabled: bool = True
    file_access_allow: list[str] = field(default_factory=list)
    file_write_allow: list[str] = field(default_factory=list)
    patch_allow: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)

    def __init__(
        self,
        *,
        enabled: bool = True,
        file_access_allow: list[str] | None = None,
        file_write_allow: list[str] | None = None,
        patch_allow: list[str] | None = None,
        allowed_paths: list[str] | None = None,
    ) -> None:
        self.enabled = enabled
        legacy = list(allowed_paths or [])
        self.allowed_paths = legacy
        # If the legacy `allowed_paths` field is provided and a per-action list is
        # missing, fall back to the legacy list to preserve prior behaviour.
        self.file_access_allow = list(file_access_allow) if file_access_allow is not None else list(legacy)
        self.file_write_allow = list(file_write_allow) if file_write_allow is not None else list(legacy)
        self.patch_allow = list(patch_allow) if patch_allow is not None else []


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

    def _patterns_for(self, action: Action) -> list[str]:
        """Return the allowlist that applies to ``action.action_type``.

        Mirrors the Rust behaviour where ``patch_allow`` falls back to
        ``file_write_allow`` when empty.
        """
        action_type = action.action_type
        if action_type == "file_access":
            return self._config.file_access_allow
        if action_type == "file_write":
            return self._config.file_write_allow
        if action_type == "patch":
            return self._config.patch_allow or self._config.file_write_allow
        return []

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        if not self._config.enabled:
            return GuardResult.allow(self.name)
        if not self.handles(action):
            return GuardResult.allow(self.name)

        patterns = self._patterns_for(action)
        # If no allowlist configured for this action type, allow.
        if not patterns:
            return GuardResult.allow(self.name)

        path: str | None = getattr(action, "path", None)
        if path is None:
            return GuardResult.allow(self.name)

        normalized = path.replace("\\", "/")

        for pattern in patterns:
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
