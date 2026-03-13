"""Shell command guard - blocks dangerous shell commands before execution."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from clawdstrike.exceptions import ConfigurationError
from clawdstrike.guards.base import Action, Guard, GuardContext, GuardResult, Severity

DEFAULT_BLOCKED_COMMANDS: list[str] = [
    r"rm\s+-rf\s+/",           # rm -rf /
    r"rm\s+-rf\s+\*",          # rm -rf *
    r"rm\s+-rf\s+~",           # rm -rf ~
    r":\(\)\{\s*:\|:&\s*\};:", # fork bomb
    r"mkfs\.",                  # format filesystem
    r"dd\s+if=.*?of=/dev/",    # overwrite device
    r">\s*/dev/sd[a-z]",       # redirect to device
    r"chmod\s+-R\s+777\s+/",   # chmod 777 /
    r"curl\s+.*?\|\s*sh",      # pipe curl to sh
    r"wget\s+.*?\|\s*sh",      # pipe wget to sh
    r"curl\s+.*?\|\s*bash",    # pipe curl to bash
    r"wget\s+.*?\|\s*bash",    # pipe wget to bash
    r"eval\s*\(",              # eval
    r"python\s+-c\s+.*?exec\(",  # python exec
    r"nc\s+-l",                # netcat listen
    r"ncat\s+-l",              # ncat listen
]


@dataclass(init=False)
class ShellCommandConfig:
    """Configuration for ShellCommandGuard."""
    forbidden_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_BLOCKED_COMMANDS))
    additional_blocked: list[str] = field(default_factory=list)
    allowed_commands: list[str] = field(default_factory=list)
    enabled: bool = True

    def __init__(
        self,
        *,
        forbidden_patterns: list[str] | None = None,
        blocked_patterns: list[str] | None = None,
        additional_blocked: list[str] | None = None,
        allowed_commands: list[str] | None = None,
        enabled: bool = True,
    ) -> None:
        if forbidden_patterns is not None and blocked_patterns is not None:
            msg = "shell_command cannot define both blocked_patterns and forbidden_patterns"
            raise ConfigurationError(msg)

        pattern_source = forbidden_patterns
        if pattern_source is None:
            pattern_source = blocked_patterns

        self.forbidden_patterns = list(
            DEFAULT_BLOCKED_COMMANDS if pattern_source is None else pattern_source
        )
        self.additional_blocked = list(additional_blocked or [])
        self.allowed_commands = list(allowed_commands or [])
        self.enabled = enabled


class ShellCommandGuard(Guard):
    """Guard that blocks dangerous shell commands before execution."""

    def __init__(self, config: ShellCommandConfig | None = None) -> None:
        self._config = config or ShellCommandConfig()
        all_patterns = self._config.forbidden_patterns + self._config.additional_blocked
        self._compiled: list[tuple[str, re.Pattern[str]]] = []
        for pattern in all_patterns:
            try:
                self._compiled.append((pattern, re.compile(pattern)))
            except re.error as e:
                msg = f"Invalid regex in shell_command blocked pattern: {pattern!r}: {e}"
                raise ConfigurationError(msg) from e

    @property
    def name(self) -> str:
        return "shell_command"

    def handles(self, action: Action) -> bool:
        return action.action_type == "shell_command"

    def check(self, action: Action, context: GuardContext) -> GuardResult:
        if not self._config.enabled:
            return GuardResult.allow(self.name)
        if not self.handles(action):
            return GuardResult.allow(self.name)

        command: str | None = getattr(action, "command", None)
        if command is None:
            return GuardResult.allow(self.name)

        # Check blocked patterns first (before allowlist)
        for pattern_str, compiled in self._compiled:
            if compiled.search(command):
                return GuardResult.block(
                    self.name,
                    Severity.CRITICAL,
                    f"Dangerous shell command blocked: matches pattern {pattern_str!r}",
                ).with_details({
                    "command": command[:200],
                    "matched_pattern": pattern_str,
                })

        # Check allowed commands (exact first-word match)
        if self._config.allowed_commands:
            first_word = command.strip().split()[0] if command.strip() else ""
            if first_word in self._config.allowed_commands:
                return GuardResult.allow(self.name)
            return GuardResult.block(
                self.name,
                Severity.ERROR,
                f"Command not in allowlist: {first_word!r}",
            ).with_details({
                "command": command[:200],
                "allowed_commands": self._config.allowed_commands,
            })

        return GuardResult.allow(self.name)
