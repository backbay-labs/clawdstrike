"""Tests for hush.policy module."""

import pytest
from clawdstrike.exceptions import PolicyError
from clawdstrike.policy import (
    Policy,
    PolicyEngine,
    PolicySettings,
    GuardConfigs,
    PostureConfig,
)


class TestPolicy:
    def test_default_policy(self) -> None:
        policy = Policy()
        assert policy.version == "1.2.0"
        assert policy.name == ""

    def test_policy_from_yaml(self, sample_policy_yaml: str) -> None:
        policy = Policy.from_yaml(sample_policy_yaml)
        assert policy.version == "1.1.0"
        assert policy.name == "test-policy"
        assert policy.guards.forbidden_path is not None
        assert "**/.ssh/**" in policy.guards.forbidden_path.patterns

    def test_policy_v12_from_yaml(self, sample_policy_yaml_v12: str) -> None:
        policy = Policy.from_yaml(sample_policy_yaml_v12)
        assert policy.version == "1.2.0"
        assert policy.name == "test-posture-policy"
        assert policy.guards.prompt_injection is not None
        assert policy.guards.jailbreak is not None
        assert policy.posture is not None
        assert policy.posture.initial == "restricted"
        assert "restricted" in policy.posture.states
        assert "standard" in policy.posture.states

    def test_policy_to_yaml(self) -> None:
        policy = Policy(
            version="1.2.0",
            name="test",
            description="Test policy",
        )
        yaml_str = policy.to_yaml()
        assert "version:" in yaml_str
        assert "name:" in yaml_str

    def test_policy_roundtrip(self) -> None:
        original = Policy(
            version="1.2.0",
            name="roundtrip-test",
            description="Testing roundtrip",
        )
        yaml_str = original.to_yaml()
        restored = Policy.from_yaml(yaml_str)
        assert restored.version == original.version
        assert restored.name == original.name

    def test_policy_rejects_invalid_semver_version(self) -> None:
        with pytest.raises(PolicyError):
            Policy.from_yaml('version: "1.0"\nname: test\n')

    def test_policy_rejects_unsupported_version(self) -> None:
        with pytest.raises(PolicyError):
            Policy.from_yaml('version: "2.0.0"\nname: test\n')

    def test_policy_rejects_unknown_top_level_keys(self) -> None:
        with pytest.raises(PolicyError):
            Policy.from_yaml('version: "1.1.0"\nname: test\nunknown: 1\n')

    def test_policy_rejects_unknown_guard_names(self) -> None:
        with pytest.raises(PolicyError):
            Policy.from_yaml(
                'version: "1.1.0"\nname: test\nguards:\n  unknown_guard: {}\n'
            )

    def test_policy_accepts_v1_1_0(self) -> None:
        policy = Policy.from_yaml('version: "1.1.0"\nname: test\n')
        assert policy.version == "1.1.0"

    def test_policy_accepts_v1_2_0(self) -> None:
        policy = Policy.from_yaml('version: "1.2.0"\nname: test\n')
        assert policy.version == "1.2.0"

    def test_posture_rejected_for_v1_1_0(self) -> None:
        yaml_str = """
version: "1.1.0"
name: test
posture:
  initial: work
  states:
    work:
      capabilities:
        - file_access
"""
        with pytest.raises(PolicyError, match="posture requires policy version 1.2.0"):
            Policy.from_yaml(yaml_str)

    def test_extends_field_parsed(self) -> None:
        policy = Policy.from_yaml('version: "1.1.0"\nname: test\nextends: strict\n')
        assert policy.extends == "strict"

    def test_extends_field_none_by_default(self) -> None:
        policy = Policy.from_yaml('version: "1.1.0"\nname: test\n')
        assert policy.extends is None

    def test_extends_builtin_strict(self) -> None:
        yaml_str = """
version: "1.1.0"
name: CustomStrict
extends: strict
settings:
  verbose_logging: true
"""
        policy = Policy.from_yaml_with_extends(yaml_str)
        assert policy.settings.fail_fast is True  # from strict base
        assert policy.settings.verbose_logging is True  # from child
        assert policy.name == "CustomStrict"

    def test_extends_with_clawdstrike_prefix(self) -> None:
        yaml_str = """
version: "1.1.0"
name: CustomDefault
extends: clawdstrike:default
"""
        policy = Policy.from_yaml_with_extends(yaml_str)
        assert policy.name == "CustomDefault"
        assert policy.guards.forbidden_path is not None

    def test_extends_builtin_spider_sense(self) -> None:
        yaml_str = """
version: "1.3.0"
name: CustomSpiderSense
extends: spider-sense
"""
        policy = Policy.from_yaml_with_extends(yaml_str)
        assert policy.name == "CustomSpiderSense"
        assert policy.guards.spider_sense is not None
        assert policy.guards.spider_sense.pattern_db_path == "builtin:s2bench-v1"

    def test_extends_unknown_raises(self) -> None:
        yaml_str = """
version: "1.1.0"
name: test
extends: nonexistent_ruleset
"""
        with pytest.raises(PolicyError, match="Unknown ruleset"):
            Policy.from_yaml_with_extends(yaml_str)

    def test_from_yaml_file_with_path_object(self, tmp_path) -> None:
        p = tmp_path / "policy.yaml"
        p.write_text('version: "1.1.0"\nname: path-test\n')
        from pathlib import Path
        policy = Policy.from_yaml_file(Path(p))
        assert policy.name == "path-test"


class TestGuardConfigs:
    def test_default_configs(self) -> None:
        configs = GuardConfigs()
        assert configs.forbidden_path is None
        assert configs.egress_allowlist is None
        assert configs.prompt_injection is None
        assert configs.jailbreak is None

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

    def test_from_dict_with_new_guards(self) -> None:
        configs = GuardConfigs.from_dict({
            "prompt_injection": {
                "enabled": True,
                "warn_at_or_above": "suspicious",
                "block_at_or_above": "high",
            },
            "jailbreak": {
                "enabled": True,
                "detector": {
                    "block_threshold": 60,
                    "warn_threshold": 25,
                },
            },
        })
        assert configs.prompt_injection is not None
        assert configs.prompt_injection.block_at_or_above == "high"
        assert configs.jailbreak is not None
        assert configs.jailbreak.block_threshold == 60

    def test_from_dict_secret_leak_with_patterns(self) -> None:
        configs = GuardConfigs.from_dict({
            "secret_leak": {
                "patterns": [
                    {"name": "aws", "pattern": "AKIA[0-9A-Z]{16}", "severity": "critical"},
                ],
                "enabled": True,
            },
        })
        assert configs.secret_leak is not None
        assert len(configs.secret_leak.patterns) == 1
        assert configs.secret_leak.patterns[0].name == "aws"

    def test_from_dict_patch_integrity_with_forbidden_patterns(self) -> None:
        configs = GuardConfigs.from_dict({
            "patch_integrity": {
                "max_additions": 500,
                "forbidden_patterns": [r"(?i)disable\s+security"],
            },
        })
        assert configs.patch_integrity is not None
        assert len(configs.patch_integrity.forbidden_patterns) == 1

    def test_from_dict_spider_sense_object(self) -> None:
        configs = GuardConfigs.from_dict({
            "spider_sense": {
                "enabled": True,
                "pattern_db_path": "builtin:s2bench-v1",
                "pattern_db_version": "s2bench-v1",
                "pattern_db_checksum": (
                    "8943003a9de9619d2f8f0bf133c9c7690ab3a582cbcbe4cb9692d44ee9643a73"
                ),
                "pattern_db_signature_key_id": "abcd1234",
                "pattern_db_trusted_keys": [
                    {"public_key": "11" * 32, "status": "active"},
                ],
                "pattern_db_manifest_path": "/tmp/spider/manifest.json",
                "pattern_db_manifest_trust_store_path": "/tmp/spider/manifest-roots.json",
                "embedding_api_url": "https://api.openai.com/v1/embeddings",
                "embedding_api_key": "test-key",
                "embedding_model": "text-embedding-3-small",
                "llm_prompt_template_id": "spider_sense.deep_path.json_classifier",
                "llm_prompt_template_version": "1.0.0",
                "llm_timeout_ms": 1200,
                "llm_fail_mode": "warn",
                "async": {"timeout_ms": 5000},
            },
        })
        assert configs.spider_sense is not None
        assert configs.spider_sense.pattern_db_path == "builtin:s2bench-v1"
        assert configs.spider_sense.async_config == {"timeout_ms": 5000}
        assert configs.spider_sense.pattern_db_signature_key_id == "abcd1234"
        assert configs.spider_sense.pattern_db_manifest_path == "/tmp/spider/manifest.json"
        assert configs.spider_sense.llm_prompt_template_id == "spider_sense.deep_path.json_classifier"
        assert configs.spider_sense.llm_timeout_ms == 1200

    def test_from_dict_spider_sense_bool_rejected(self) -> None:
        with pytest.raises(PolicyError, match="Expected mapping for guards.spider_sense"):
            GuardConfigs.from_dict({
                "spider_sense": True,
            })


class TestPolicySettings:
    def test_default_settings(self) -> None:
        settings = PolicySettings()
        assert settings.fail_fast is False
        assert settings.verbose_logging is False


class TestPolicyEngine:
    def test_create_from_policy(self, sample_policy_yaml: str) -> None:
        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)

        assert len(engine.guards) == 9  # All 9 guards

    def test_create_from_v12_policy(self, sample_policy_yaml_v12: str) -> None:
        policy = Policy.from_yaml(sample_policy_yaml_v12)
        engine = PolicyEngine(policy)

        assert len(engine.guards) == 9

    def test_check_allowed_action(self, sample_policy_yaml: str) -> None:
        from clawdstrike.guards.base import FileAccessAction, NetworkEgressAction, GuardContext

        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)
        context = GuardContext()

        results = engine.check(
            FileAccessAction(path="/app/src/main.py"),
            context,
        )

        # All guards should allow this
        assert all(r.allowed for r in results)

    def test_check_forbidden_action(self, sample_policy_yaml: str) -> None:
        from clawdstrike.guards.base import FileAccessAction, NetworkEgressAction, GuardContext

        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)
        context = GuardContext()

        results = engine.check(
            FileAccessAction(path="/home/user/.ssh/id_rsa"),
            context,
        )

        # At least one guard should block
        assert any(not r.allowed for r in results)

    def test_fail_fast_mode(self, sample_policy_yaml: str) -> None:
        from clawdstrike.guards.base import FileAccessAction, NetworkEgressAction, GuardContext

        policy = Policy.from_yaml(sample_policy_yaml)
        policy.settings.fail_fast = True
        engine = PolicyEngine(policy)
        context = GuardContext()

        # With fail_fast, should stop at first violation
        results = engine.check(
            FileAccessAction(path="/home/user/.ssh/id_rsa"),
            context,
        )

        # Should have exactly one blocking result
        blocked = [r for r in results if not r.allowed]
        assert len(blocked) >= 1


    def test_merge_child_explicit_false_overrides_base_true(self) -> None:
        base_yaml = """
version: "1.1.0"
name: base
settings:
  fail_fast: true
"""
        child_yaml = """
version: "1.1.0"
name: child
extends: base_policy
settings:
  fail_fast: false
"""
        base = Policy.from_yaml(base_yaml)
        child = Policy.from_yaml(child_yaml)
        merged = base.merge(child)
        assert merged.settings.fail_fast is False

    def test_merge_child_inherits_unspecified_settings(self) -> None:
        base_yaml = """
version: "1.1.0"
name: base
settings:
  fail_fast: true
  verbose_logging: true
"""
        child_yaml = """
version: "1.1.0"
name: child
extends: base_policy
"""
        base = Policy.from_yaml(base_yaml)
        child = Policy.from_yaml(child_yaml)
        merged = base.merge(child)
        assert merged.settings.fail_fast is True
        assert merged.settings.verbose_logging is True


class TestPolicyMergeGuards:
    def test_merge_preserves_base_forbidden_path_patterns_when_child_omits(self) -> None:
        base_yaml = """
version: "1.1.0"
name: base
guards:
  forbidden_path:
    patterns:
      - "**/repo/**"
"""
        child_yaml = """
version: "1.1.0"
name: child
extends: base_policy
guards:
  forbidden_path:
    exceptions:
      - "**/repo/**/public/**"
"""
        base = Policy.from_yaml(base_yaml)
        child = Policy.from_yaml(child_yaml)
        merged = base.merge(child)

        assert merged.guards.forbidden_path is not None
        # Must keep base patterns instead of falling back to guard defaults.
        assert merged.guards.forbidden_path.patterns == ["**/repo/**"]
        assert "**/repo/**/public/**" in merged.guards.forbidden_path.exceptions

    def test_merge_preserves_base_patch_integrity_limits_when_child_omits(self) -> None:
        base_yaml = """
version: "1.1.0"
name: base
guards:
  patch_integrity:
    max_additions: 10
"""
        child_yaml = """
version: "1.1.0"
name: child
extends: base_policy
guards:
  patch_integrity:
    forbidden_patterns:
      - "(?i)password"
"""
        base = Policy.from_yaml(base_yaml)
        child = Policy.from_yaml(child_yaml)
        merged = base.merge(child)

        assert merged.guards.patch_integrity is not None
        assert merged.guards.patch_integrity.max_additions == 10
        assert "(?i)password" in merged.guards.patch_integrity.forbidden_patterns

    def test_merge_preserves_base_secret_leak_enabled_when_child_omits(self) -> None:
        base_yaml = """
version: "1.1.0"
name: base
guards:
  secret_leak:
    enabled: false
"""
        child_yaml = """
version: "1.1.0"
name: child
extends: base_policy
guards:
  secret_leak:
    skip_paths:
      - "**/fixtures/**"
"""
        base = Policy.from_yaml(base_yaml)
        child = Policy.from_yaml(child_yaml)
        merged = base.merge(child)

        assert merged.guards.secret_leak is not None
        assert merged.guards.secret_leak.enabled is False
        assert "**/fixtures/**" in merged.guards.secret_leak.skip_paths


class TestPostureConfig:
    def test_posture_from_dict(self) -> None:
        data = {
            "initial": "restricted",
            "states": {
                "restricted": {
                    "description": "Read-only",
                    "capabilities": ["file_access"],
                    "budgets": {},
                },
                "standard": {
                    "capabilities": ["file_access", "file_write"],
                    "budgets": {"file_writes": 50},
                },
            },
            "transitions": [
                {"from": "restricted", "to": "standard", "on": "user_approval"},
            ],
        }
        posture = PostureConfig.from_dict(data)
        assert posture.initial == "restricted"
        assert len(posture.states) == 2
        assert posture.states["standard"].budgets["file_writes"] == 50
        assert len(posture.transitions) == 1
        assert posture.transitions[0].on == "user_approval"

    def test_posture_rejects_invalid_initial_state(self) -> None:
        data = {
            "initial": "nonexistent",
            "states": {
                "work": {"capabilities": ["file_access"]},
            },
        }
        with pytest.raises(PolicyError, match="initial state.*not found"):
            PostureConfig.from_dict(data)

    def test_posture_rejects_invalid_transition_state(self) -> None:
        data = {
            "initial": "work",
            "states": {
                "work": {"capabilities": ["file_access"]},
            },
            "transitions": [
                {"from": "work", "to": "nonexistent", "on": "escalate"},
            ],
        }
        with pytest.raises(PolicyError, match="unknown to_state"):
            PostureConfig.from_dict(data)
