"""Tests for Clawdstrike facade."""

import pytest

from clawdstrike import Clawdstrike, Decision, DecisionStatus
from clawdstrike.exceptions import ConfigurationError
from clawdstrike.native import NATIVE_AVAILABLE
from clawdstrike.policy import Policy, PolicyEngine


class TestClawdstrikeWithDefaults:
    def test_strict_blocks_ssh(self) -> None:
        cs = Clawdstrike.with_defaults("strict")
        d = cs.check_file("/home/user/.ssh/id_rsa")
        assert d.denied

    def test_strict_blocks_network(self) -> None:
        cs = Clawdstrike.with_defaults("strict")
        d = cs.check_network("unknown-evil-host.com")
        assert d.denied

    def test_default_allows_safe_file(self) -> None:
        cs = Clawdstrike.with_defaults("default")
        d = cs.check_file("/app/src/main.py")
        assert d.allowed

    def test_default_allows_known_egress(self) -> None:
        cs = Clawdstrike.with_defaults("default")
        d = cs.check_network("api.openai.com")
        assert d.allowed

    def test_permissive_allows_all_egress(self) -> None:
        cs = Clawdstrike.with_defaults("permissive")
        d = cs.check_network("anything.example.com")
        assert d.allowed

    def test_unknown_ruleset_raises(self) -> None:
        with pytest.raises(ConfigurationError):
            Clawdstrike.with_defaults("nonexistent_ruleset")


class TestClawdstrikeCheckMethods:
    def test_check_file_read(self) -> None:
        cs = Clawdstrike.with_defaults("strict")
        d = cs.check_file("/etc/shadow")
        assert d.denied

    def test_check_mcp_tool(self) -> None:
        cs = Clawdstrike.with_defaults("strict")
        d = cs.check_mcp_tool("shell_exec", {"command": "rm -rf /"})
        assert d.denied

    def test_check_mcp_tool_allowed(self) -> None:
        cs = Clawdstrike.with_defaults("strict")
        d = cs.check_mcp_tool("read_file", {"path": "/app/README.md"})
        assert d.allowed

    def test_check_patch(self) -> None:
        cs = Clawdstrike.with_defaults("default")
        diff = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n"
        d = cs.check_patch("/app/file.py", diff)
        assert d.allowed

    def test_decision_is_frozen(self) -> None:
        cs = Clawdstrike.with_defaults("default")
        d = cs.check_file("/app/safe.txt")
        with pytest.raises(AttributeError):
            d.status = DecisionStatus.DENY  # type: ignore[misc]


class TestClawdstrikeConfigure:
    def test_configure_with_default_policy(self) -> None:
        cs = Clawdstrike.configure()
        d = cs.check_file("/app/safe.txt")
        assert isinstance(d, Decision)

    def test_configure_with_fail_fast(self) -> None:
        cs = Clawdstrike.configure(fail_fast=True)
        d = cs.check_file("/home/user/.ssh/id_rsa")
        # Should have at most 1 deny result in per_guard
        denies = [r for r in d.per_guard if not r.allowed]
        assert len(denies) >= 1


class TestClawdstrikeBackendAware:
    """Tests that exercise both backends via the facade."""

    def test_backend_is_pure_python_by_default(self) -> None:
        """Without native, the backend should be pure_python."""
        from unittest.mock import patch

        with patch("clawdstrike.clawdstrike.NativeEngineBackend") as mock:
            mock.from_ruleset.side_effect = Exception("no native")
            cs = Clawdstrike.with_defaults("strict")
            assert cs._backend.name == "pure_python"

    @pytest.mark.skipif(not NATIVE_AVAILABLE, reason="native backend not available")
    def test_backend_is_native_when_available(self) -> None:
        cs = Clawdstrike.with_defaults("strict")
        assert cs._backend.name == "native"

    def test_facade_accepts_policy_engine(self) -> None:
        """Backward compat: passing a PolicyEngine wraps in PurePythonBackend."""
        yaml_str = 'version: "1.1.0"\nname: test\nextends: default\n'
        policy = Policy.from_yaml_with_extends(yaml_str)
        cs = Clawdstrike(PolicyEngine(policy))
        assert cs._backend.name == "pure_python"
        d = cs.check_file("/app/safe.txt")
        assert d.allowed
