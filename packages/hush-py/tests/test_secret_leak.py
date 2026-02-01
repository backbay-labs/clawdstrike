"""Tests for SecretLeakGuard."""

import pytest
from hush.guards.secret_leak import SecretLeakGuard, SecretLeakConfig
from hush.guards.base import GuardAction, GuardContext, Severity


class TestSecretLeakConfig:
    def test_default_config(self) -> None:
        config = SecretLeakConfig()
        assert config.secrets == []
        assert config.enabled is True

    def test_with_secrets(self) -> None:
        config = SecretLeakConfig(secrets=["secret1", "secret2"])
        assert len(config.secrets) == 2


class TestSecretLeakGuard:
    def test_detect_secret_in_output(self) -> None:
        config = SecretLeakConfig(secrets=["sk-abc123secretkey"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        # Create action with output containing secret
        action = GuardAction.custom("output", {
            "content": "The API key is sk-abc123secretkey",
        })

        result = guard.check(action, context)
        assert result.allowed is False
        assert result.severity == Severity.CRITICAL

    def test_no_secret_in_output(self) -> None:
        config = SecretLeakConfig(secrets=["sk-abc123secretkey"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = GuardAction.custom("output", {
            "content": "This is safe output with no secrets",
        })

        result = guard.check(action, context)
        assert result.allowed is True

    def test_empty_secrets_list(self) -> None:
        config = SecretLeakConfig(secrets=[])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = GuardAction.custom("output", {
            "content": "Any output is allowed",
        })

        result = guard.check(action, context)
        assert result.allowed is True

    def test_disabled_guard(self) -> None:
        config = SecretLeakConfig(
            secrets=["secret123"],
            enabled=False,
        )
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = GuardAction.custom("output", {
            "content": "Contains secret123 but guard is disabled",
        })

        result = guard.check(action, context)
        assert result.allowed is True

    def test_secret_hint_in_details(self) -> None:
        config = SecretLeakConfig(secrets=["verylongsecretvalue"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = GuardAction.custom("output", {
            "content": "Leaked: verylongsecretvalue",
        })

        result = guard.check(action, context)
        assert result.details is not None
        assert "secret_hint" in result.details
        # Should only show first 4 chars
        assert result.details["secret_hint"] == "very..."

    def test_handles_output_actions(self) -> None:
        guard = SecretLeakGuard()

        assert guard.handles(GuardAction.custom("output", {})) is True
        assert guard.handles(GuardAction.custom("bash_output", {})) is True
        assert guard.handles(GuardAction.custom("tool_result", {})) is True
        assert guard.handles(GuardAction.file_access("/test")) is False

    def test_guard_name(self) -> None:
        guard = SecretLeakGuard()
        assert guard.name == "secret_leak"

    def test_filters_empty_secrets(self) -> None:
        config = SecretLeakConfig(secrets=["", "  ", "valid"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        # Only "valid" should be checked
        action = GuardAction.custom("output", {"content": "valid secret"})
        result = guard.check(action, context)
        assert result.allowed is False

    def test_multiple_content_fields(self) -> None:
        config = SecretLeakConfig(secrets=["secret123"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        # Test with "output" field
        action = GuardAction.custom("output", {"output": "secret123 leaked"})
        result = guard.check(action, context)
        assert result.allowed is False

        # Test with "result" field
        action = GuardAction.custom("tool_result", {"result": "secret123 leaked"})
        result = guard.check(action, context)
        assert result.allowed is False
