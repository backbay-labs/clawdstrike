"""Tests for SecretLeakGuard."""

import pytest
from clawdstrike.guards.secret_leak import (
    SecretLeakGuard,
    SecretLeakConfig,
    SecretPattern,
)
from clawdstrike.guards.base import (
    CustomAction,
    FileAccessAction,
    FileWriteAction,
    GuardContext,
    Severity,
)


class TestSecretLeakConfig:
    def test_default_config(self) -> None:
        config = SecretLeakConfig()
        assert len(config.patterns) > 0
        assert config.enabled is True

    def test_default_patterns_match_known_secrets(self) -> None:
        config = SecretLeakConfig()
        assert any(p.name == "aws_access_key" for p in config.patterns)
        assert any(p.name == "github_token" for p in config.patterns)

    def test_with_custom_patterns(self) -> None:
        config = SecretLeakConfig(patterns=[
            SecretPattern(name="custom", pattern=r"CUSTOM_[A-Z]{10}"),
        ])
        assert len(config.patterns) == 1

    def test_legacy_secrets_field(self) -> None:
        config = SecretLeakConfig(secrets=["secret1", "secret2"])
        assert len(config.secrets) == 2


class TestSecretLeakGuard:
    def test_detect_aws_key_pattern(self) -> None:
        guard = SecretLeakGuard()
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={
            "content": "AWS key: AKIAIOSFODNN7EXAMPLE",
        })

        result = guard.check(action, context)
        assert result.allowed is False
        assert result.severity == Severity.CRITICAL
        assert result.details is not None
        assert result.details["pattern_name"] == "aws_access_key"

    def test_detect_github_token_pattern(self) -> None:
        guard = SecretLeakGuard()
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={
            "content": "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        })

        result = guard.check(action, context)
        assert result.allowed is False
        assert result.details is not None
        assert result.details["pattern_name"] == "github_token"

    def test_detect_private_key_pattern(self) -> None:
        guard = SecretLeakGuard()
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={
            "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBAI...",
        })

        result = guard.check(action, context)
        assert result.allowed is False
        assert result.details is not None
        assert result.details["pattern_name"] == "private_key"

    def test_no_secret_in_output(self) -> None:
        guard = SecretLeakGuard()
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={
            "content": "This is safe output with no secrets",
        })

        result = guard.check(action, context)
        assert result.allowed is True

    def test_detect_in_file_write(self) -> None:
        guard = SecretLeakGuard()
        context = GuardContext()

        action = FileWriteAction(
            path="/tmp/config.env",
            content=b"AWS_KEY=AKIAIOSFODNN7EXAMPLE",
        )

        result = guard.check(action, context)
        assert result.allowed is False

    def test_skip_paths(self) -> None:
        config = SecretLeakConfig(skip_paths=["**/test/**"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = FileWriteAction(
            path="/project/test/fixtures.py",
            content=b"AWS_KEY=AKIAIOSFODNN7EXAMPLE",
        )

        result = guard.check(action, context)
        assert result.allowed is True

    def test_disabled_guard(self) -> None:
        config = SecretLeakConfig(enabled=False)
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={
            "content": "AKIAIOSFODNN7EXAMPLE",
        })

        result = guard.check(action, context)
        assert result.allowed is True

    def test_legacy_literal_secrets(self) -> None:
        config = SecretLeakConfig(
            patterns=[],
            secrets=["sk-abc123secretkey"],
        )
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={
            "content": "The API key is sk-abc123secretkey",
        })

        result = guard.check(action, context)
        assert result.allowed is False
        assert result.details is not None
        assert "secret_hint" in result.details

    def test_handles_output_actions(self) -> None:
        guard = SecretLeakGuard()

        assert guard.handles(CustomAction(custom_type="output", custom_data={})) is True
        assert guard.handles(CustomAction(custom_type="bash_output", custom_data={})) is True
        assert guard.handles(CustomAction(custom_type="tool_result", custom_data={})) is True
        assert guard.handles(FileWriteAction(path="/test", content=b"")) is True
        assert guard.handles(FileAccessAction(path="/test")) is False

    def test_guard_name(self) -> None:
        guard = SecretLeakGuard()
        assert guard.name == "secret_leak"

    def test_filters_empty_legacy_secrets(self) -> None:
        config = SecretLeakConfig(patterns=[], secrets=["", "  ", "valid"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={"content": "valid secret"})
        result = guard.check(action, context)
        assert result.allowed is False

    def test_multiple_content_fields(self) -> None:
        config = SecretLeakConfig(patterns=[], secrets=["secret123"])
        guard = SecretLeakGuard(config)
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={"output": "secret123 leaked"})
        result = guard.check(action, context)
        assert result.allowed is False

        action = CustomAction(custom_type="tool_result", custom_data={"result": "secret123 leaked"})
        result = guard.check(action, context)
        assert result.allowed is False

    def test_invalid_regex_raises_on_init(self) -> None:
        config = SecretLeakConfig(patterns=[
            SecretPattern(name="bad", pattern=r"[invalid"),
        ])
        with pytest.raises(ValueError, match="Invalid regex in secret pattern 'bad'"):
            SecretLeakGuard(config)

    def test_openai_key_pattern_no_false_positive_on_short_sk(self) -> None:
        guard = SecretLeakGuard()
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={
            "content": "Use sk-something for the key name",
        })
        result = guard.check(action, context)
        assert result.allowed is True

    def test_openai_key_pattern_detects_proj_key(self) -> None:
        guard = SecretLeakGuard()
        context = GuardContext()

        key = "sk-proj-" + "A" * 48
        action = CustomAction(custom_type="output", custom_data={
            "content": f"Key: {key}",
        })
        result = guard.check(action, context)
        assert result.allowed is False
        assert result.details["pattern_name"] == "openai_key"

    def test_stripe_key_detected(self) -> None:
        guard = SecretLeakGuard()
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={
            "content": "sk_live_" + "X" * 24,
        })
        result = guard.check(action, context)
        assert result.allowed is False
        assert result.details["pattern_name"] == "generic_api_key"

    def test_no_false_positive_on_uuid(self) -> None:
        guard = SecretLeakGuard()
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={
            "content": "ID: 550e8400-e29b-41d4-a716-446655440000",
        })
        result = guard.check(action, context)
        assert result.allowed is True

    def test_no_false_positive_on_base64_blob(self) -> None:
        guard = SecretLeakGuard()
        context = GuardContext()

        action = CustomAction(custom_type="output", custom_data={
            "content": "data: SGVsbG8gV29ybGQ=",
        })
        result = guard.check(action, context)
        assert result.allowed is True
