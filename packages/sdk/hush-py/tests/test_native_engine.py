"""Tests for the NativeEngine Rust extension.

All tests in this module are skipped if clawdstrike._native is not available.
"""

from __future__ import annotations

import json

import pytest

from clawdstrike.native import NATIVE_AVAILABLE, init_native

pytestmark = pytest.mark.skipif(not NATIVE_AVAILABLE, reason="clawdstrike._native not installed")


def _has_native_engine() -> bool:
    return init_native()


skip_no_engine = pytest.mark.skipif(
    not _has_native_engine() if NATIVE_AVAILABLE else True,
    reason="NativeEngine not available in clawdstrike._native",
)


@skip_no_engine
class TestNativeEngineFromRuleset:
    def test_strict(self) -> None:
        from clawdstrike import _native as native_mod

        engine = native_mod.NativeEngine.from_ruleset("strict")
        assert engine is not None

    def test_default(self) -> None:
        from clawdstrike import _native as native_mod

        engine = native_mod.NativeEngine.from_ruleset("default")
        assert engine is not None

    def test_permissive(self) -> None:
        from clawdstrike import _native as native_mod

        engine = native_mod.NativeEngine.from_ruleset("permissive")
        assert engine is not None

    def test_invalid_ruleset_raises(self) -> None:
        from clawdstrike import _native as native_mod

        with pytest.raises(ValueError):
            native_mod.NativeEngine.from_ruleset("nonexistent_ruleset_xyz")


@skip_no_engine
class TestNativeEngineChecks:
    @pytest.fixture
    def engine(self):
        from clawdstrike import _native as native_mod

        return native_mod.NativeEngine.from_ruleset("strict")

    def test_check_shell_blocks_rm_rf(self, engine) -> None:
        report = engine.check_shell("rm -rf /")
        assert isinstance(report, dict)
        assert "overall" in report
        assert "per_guard" in report
        assert report["overall"]["allowed"] is False

    def test_check_shell_allows_ls(self, engine) -> None:
        report = engine.check_shell("ls -la")
        assert report["overall"]["allowed"] is True

    def test_check_file_access_blocks_shadow(self, engine) -> None:
        report = engine.check_file_access("/etc/shadow")
        assert report["overall"]["allowed"] is False

    def test_check_file_access_allows_safe_path(self, engine) -> None:
        report = engine.check_file_access("/app/src/main.py")
        assert report["overall"]["allowed"] is True

    def test_check_file_access_blocks_ssh_key(self, engine) -> None:
        report = engine.check_file_access("/home/user/.ssh/id_rsa")
        assert report["overall"]["allowed"] is False

    def test_check_network_blocks_unknown(self, engine) -> None:
        report = engine.check_network("unknown-evil.com", 443)
        assert report["overall"]["allowed"] is False

    def test_check_network_allows_known(self, engine) -> None:
        report = engine.check_network("api.openai.com", 443)
        assert report["overall"]["allowed"] is True

    def test_check_file_write_blocks_ssh_key(self, engine) -> None:
        report = engine.check_file_write("/home/user/.ssh/id_rsa", b"key data")
        assert report["overall"]["allowed"] is False

    def test_check_file_write_allows_safe(self, engine) -> None:
        report = engine.check_file_write("/app/output.txt", b"hello")
        assert report["overall"]["allowed"] is True

    def test_check_mcp_tool_blocks_shell_exec(self, engine) -> None:
        import json

        report = engine.check_mcp_tool("shell_exec", json.dumps({"cmd": "ls"}))
        assert report["overall"]["allowed"] is False

    def test_check_patch_allows_small(self, engine) -> None:
        diff = "--- a/f.py\n+++ b/f.py\n@@ -1 +1 @@\n-old\n+new\n"
        report = engine.check_patch("/app/f.py", diff)
        assert report["overall"]["allowed"] is True

    def test_check_with_context(self, engine) -> None:
        report = engine.check_shell("ls", {"cwd": "/app", "session_id": "test-123"})
        assert report["overall"]["allowed"] is True

    def test_check_with_origin_context(self, engine) -> None:
        report = engine.check_shell(
            "ls",
            {
                "cwd": "/app",
                "origin": {
                    "provider": "slack",
                    "tenantId": "T123",
                    "actorRole": "owner",
                },
            },
        )
        assert report["overall"]["allowed"] is True

    def test_check_custom_output_send_with_origin_context(self, engine) -> None:
        report = engine.check_custom(
            "origin.output_send",
            json.dumps({"text": "ok", "target": "slack://room"}),
            {"origin": {"provider": "slack", "tenantId": "T123"}},
        )
        assert "overall" in report

    def test_check_with_invalid_origin_context_raises(self, engine) -> None:
        with pytest.raises(ValueError, match="Invalid origin JSON"):
            engine.check_shell("ls", {"origin": {"tenantId": "T123"}})

    def test_policy_yaml(self, engine) -> None:
        yaml = engine.policy_yaml()
        assert isinstance(yaml, str)
        assert "version" in yaml

    def test_stats(self, engine) -> None:
        stats = engine.stats()
        assert isinstance(stats, dict)
        assert "action_count" in stats
        assert "violation_count" in stats


@skip_no_engine
class TestNativeEngineFromYaml:
    def test_from_yaml(self) -> None:
        from clawdstrike import _native as native_mod

        yaml_str = 'version: "1.1.0"\nname: test\nextends: strict\n'
        engine = native_mod.NativeEngine.from_yaml(yaml_str)
        assert engine is not None

    def test_from_yaml_invalid(self) -> None:
        from clawdstrike import _native as native_mod

        with pytest.raises(ValueError):
            native_mod.NativeEngine.from_yaml("not: valid: yaml: policy:")


@skip_no_engine
class TestNativeVsPurePythonParity:
    """Verify that native and pure Python backends agree on verdicts."""

    def test_shell_command_parity(self) -> None:
        from clawdstrike import _native as native_mod
        from clawdstrike.backend import PurePythonBackend
        from clawdstrike.policy import Policy, PolicyEngine

        yaml = 'version: "1.1.0"\nname: test\nextends: strict\n'
        native_engine = native_mod.NativeEngine.from_ruleset("strict")
        policy = Policy.from_yaml_with_extends(yaml)
        pure = PurePythonBackend(PolicyEngine(policy))

        test_commands = [
            ("rm -rf /", False),
            ("ls -la", True),
        ]

        for cmd, _ in test_commands:
            ctx = {"cwd": "/tmp"}
            native_report = native_engine.check_shell(cmd, ctx)
            pure_report = pure.check_shell(cmd, ctx)
            assert native_report["overall"]["allowed"] == pure_report["overall"]["allowed"], (
                f"Parity mismatch for '{cmd}': "
                f"native={native_report['overall']['allowed']} vs "
                f"pure={pure_report['overall']['allowed']}"
            )

    def test_file_access_parity(self) -> None:
        from clawdstrike import _native as native_mod
        from clawdstrike.backend import PurePythonBackend
        from clawdstrike.policy import Policy, PolicyEngine

        yaml = 'version: "1.1.0"\nname: test\nextends: strict\n'
        native_engine = native_mod.NativeEngine.from_ruleset("strict")
        policy = Policy.from_yaml_with_extends(yaml)
        pure = PurePythonBackend(PolicyEngine(policy))

        test_paths = [
            "/home/user/.ssh/id_rsa",
            "/app/src/main.py",
            "/etc/shadow",
        ]

        for path in test_paths:
            ctx = {"cwd": "/tmp"}
            native_report = native_engine.check_file_access(path, ctx)
            pure_report = pure.check_file_access(path, ctx)
            assert native_report["overall"]["allowed"] == pure_report["overall"]["allowed"], (
                f"Parity mismatch for '{path}': "
                f"native={native_report['overall']['allowed']} vs "
                f"pure={pure_report['overall']['allowed']}"
            )
