"""Tests for ForbiddenPathGuard."""

import pytest
from hush.guards.forbidden_path import ForbiddenPathGuard, ForbiddenPathConfig
from hush.guards.base import GuardAction, GuardContext, Severity


class TestForbiddenPathConfig:
    def test_default_patterns(self) -> None:
        config = ForbiddenPathConfig()
        assert "**/.ssh/**" in config.patterns
        assert "**/.env" in config.patterns
        assert "**/.aws/**" in config.patterns

    def test_custom_patterns(self) -> None:
        config = ForbiddenPathConfig(
            patterns=["**/secret/**"],
            exceptions=["**/secret/public/**"],
        )
        assert config.patterns == ["**/secret/**"]
        assert config.exceptions == ["**/secret/public/**"]


class TestForbiddenPathGuard:
    def test_default_forbidden_paths(self) -> None:
        guard = ForbiddenPathGuard()

        # SSH keys
        assert guard.is_forbidden("/home/user/.ssh/id_rsa") is True
        assert guard.is_forbidden("/home/user/.ssh/authorized_keys") is True

        # AWS credentials
        assert guard.is_forbidden("/home/user/.aws/credentials") is True

        # Environment files
        assert guard.is_forbidden("/app/.env") is True
        assert guard.is_forbidden("/app/.env.local") is True

        # Normal files should be allowed
        assert guard.is_forbidden("/app/src/main.py") is False
        assert guard.is_forbidden("/home/user/project/README.md") is False

    def test_exceptions(self) -> None:
        config = ForbiddenPathConfig(
            patterns=["**/.env"],
            exceptions=["**/project/.env"],
        )
        guard = ForbiddenPathGuard(config)

        assert guard.is_forbidden("/app/.env") is True
        assert guard.is_forbidden("/app/project/.env") is False

    def test_windows_path_normalization(self) -> None:
        guard = ForbiddenPathGuard()

        # Windows paths should be normalized
        assert guard.is_forbidden("C:\\Users\\user\\.ssh\\id_rsa") is True
        assert guard.is_forbidden("C:\\app\\.env") is True

    def test_handles_file_actions(self) -> None:
        guard = ForbiddenPathGuard()

        assert guard.handles(GuardAction.file_access("/test")) is True
        assert guard.handles(GuardAction.file_write("/test", b"")) is True
        assert guard.handles(GuardAction.patch("/test", "")) is True
        assert guard.handles(GuardAction.network_egress("host", 80)) is False

    def test_check_forbidden_path(self) -> None:
        guard = ForbiddenPathGuard()
        context = GuardContext()

        result = guard.check(
            GuardAction.file_access("/home/user/.ssh/id_rsa"),
            context,
        )
        assert result.allowed is False
        assert result.severity == Severity.CRITICAL
        assert "forbidden" in result.message.lower()

    def test_check_allowed_path(self) -> None:
        guard = ForbiddenPathGuard()
        context = GuardContext()

        result = guard.check(
            GuardAction.file_access("/app/src/main.py"),
            context,
        )
        assert result.allowed is True

    def test_guard_name(self) -> None:
        guard = ForbiddenPathGuard()
        assert guard.name == "forbidden_path"
