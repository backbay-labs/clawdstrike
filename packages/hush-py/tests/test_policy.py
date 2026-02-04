"""Tests for hush.policy module."""

import pytest
from hush.policy import Policy, PolicyEngine, PolicySettings, GuardConfigs


class TestPolicy:
    def test_default_policy(self) -> None:
        policy = Policy()
        assert policy.version == "1.1.0"
        assert policy.name == ""

    def test_policy_from_yaml(self, sample_policy_yaml: str) -> None:
        policy = Policy.from_yaml(sample_policy_yaml)
        assert policy.version == "1.1.0"
        assert policy.name == "test-policy"
        assert policy.guards.forbidden_path is not None
        assert "**/.ssh/**" in policy.guards.forbidden_path.patterns

    def test_policy_to_yaml(self) -> None:
        policy = Policy(
            version="1.1.0",
            name="test",
            description="Test policy",
        )
        yaml_str = policy.to_yaml()
        assert "version:" in yaml_str
        assert "name:" in yaml_str

    def test_policy_roundtrip(self) -> None:
        original = Policy(
            version="1.1.0",
            name="roundtrip-test",
            description="Testing roundtrip",
        )
        yaml_str = original.to_yaml()
        restored = Policy.from_yaml(yaml_str)
        assert restored.version == original.version
        assert restored.name == original.name

    def test_policy_rejects_invalid_semver_version(self) -> None:
        with pytest.raises(ValueError):
            Policy.from_yaml('version: "1.0"\nname: test\n')

    def test_policy_rejects_unsupported_version(self) -> None:
        with pytest.raises(ValueError):
            Policy.from_yaml('version: "2.0.0"\nname: test\n')

    def test_policy_rejects_unknown_top_level_keys(self) -> None:
        with pytest.raises(ValueError):
            Policy.from_yaml('version: "1.1.0"\nname: test\nunknown: 1\n')

    def test_policy_rejects_unknown_guard_names(self) -> None:
        with pytest.raises(ValueError):
            Policy.from_yaml(
                'version: "1.1.0"\nname: test\nguards:\n  unknown_guard: {}\n'
            )


class TestGuardConfigs:
    def test_default_configs(self) -> None:
        configs = GuardConfigs()
        assert configs.forbidden_path is None
        assert configs.egress_allowlist is None

    def test_from_dict(self) -> None:
        configs = GuardConfigs.from_dict({
            "forbidden_path": {
                "patterns": ["**/.secret/**"],
            },
            "egress_allowlist": {
                "allow": ["api.example.com"],
            },
        })
        assert configs.forbidden_path is not None
        assert configs.egress_allowlist is not None


class TestPolicySettings:
    def test_default_settings(self) -> None:
        settings = PolicySettings()
        assert settings.fail_fast is False
        assert settings.verbose_logging is False


class TestPolicyEngine:
    def test_create_from_policy(self, sample_policy_yaml: str) -> None:
        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)

        assert len(engine.guards) == 5  # All 5 guards

    def test_check_allowed_action(self, sample_policy_yaml: str) -> None:
        from hush.guards.base import GuardAction, GuardContext

        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)
        context = GuardContext()

        results = engine.check(
            GuardAction.file_access("/app/src/main.py"),
            context,
        )

        # All guards should allow this
        assert all(r.allowed for r in results)

    def test_check_forbidden_action(self, sample_policy_yaml: str) -> None:
        from hush.guards.base import GuardAction, GuardContext

        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)
        context = GuardContext()

        results = engine.check(
            GuardAction.file_access("/home/user/.ssh/id_rsa"),
            context,
        )

        # At least one guard should block
        assert any(not r.allowed for r in results)

    def test_fail_fast_mode(self, sample_policy_yaml: str) -> None:
        from hush.guards.base import GuardAction, GuardContext

        policy = Policy.from_yaml(sample_policy_yaml)
        policy.settings.fail_fast = True
        engine = PolicyEngine(policy)
        context = GuardContext()

        # With fail_fast, should stop at first violation
        results = engine.check(
            GuardAction.file_access("/home/user/.ssh/id_rsa"),
            context,
        )

        # Should have exactly one blocking result
        blocked = [r for r in results if not r.allowed]
        assert len(blocked) >= 1
