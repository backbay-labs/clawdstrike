"""Tests for the backend dispatch layer."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from clawdstrike import Clawdstrike, Decision
from clawdstrike.backend import (
    NativeEngineBackend,
    PurePythonBackend,
    _results_to_report_dict,
)
from clawdstrike.guards.base import GuardResult, Severity
from clawdstrike.native import NATIVE_AVAILABLE
from clawdstrike.policy import Policy, PolicyEngine

# ---------------------------------------------------------------------------
# PurePythonBackend
# ---------------------------------------------------------------------------

class TestPurePythonBackend:
    @pytest.fixture
    def backend(self) -> PurePythonBackend:
        yaml = 'version: "1.1.0"\nname: test\nextends: strict\n'
        policy = Policy.from_yaml_with_extends(yaml)
        return PurePythonBackend(PolicyEngine(policy))

    def test_name(self, backend: PurePythonBackend) -> None:
        assert backend.name == "pure_python"

    def test_check_shell_deny(self, backend: PurePythonBackend) -> None:
        report = backend.check_shell("rm -rf /", {"cwd": "/tmp"})
        assert isinstance(report, dict)
        assert "overall" in report
        assert "per_guard" in report
        assert report["overall"]["allowed"] is False

    def test_check_shell_allow(self, backend: PurePythonBackend) -> None:
        report = backend.check_shell("ls -la", {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is True

    def test_check_file_access_deny(self, backend: PurePythonBackend) -> None:
        report = backend.check_file_access("/home/user/.ssh/id_rsa", {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is False

    def test_check_file_access_allow(self, backend: PurePythonBackend) -> None:
        report = backend.check_file_access("/app/src/main.py", {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is True

    def test_check_network_deny(self, backend: PurePythonBackend) -> None:
        report = backend.check_network("unknown-evil.com", 443, {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is False

    def test_check_network_allow(self) -> None:
        yaml = 'version: "1.1.0"\nname: test\nextends: default\n'
        policy = Policy.from_yaml_with_extends(yaml)
        backend = PurePythonBackend(PolicyEngine(policy))
        report = backend.check_network("api.openai.com", 443, {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is True

    def test_check_mcp_tool_deny(self, backend: PurePythonBackend) -> None:
        report = backend.check_mcp_tool("shell_exec", {"command": "rm -rf /"}, {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is False

    def test_check_mcp_tool_allow(self, backend: PurePythonBackend) -> None:
        report = backend.check_mcp_tool("read_file", {"path": "/app/README"}, {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is True

    def test_check_file_write(self, backend: PurePythonBackend) -> None:
        report = backend.check_file_write("/app/safe.txt", b"hello", {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is True

    def test_check_patch(self, backend: PurePythonBackend) -> None:
        diff = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n"
        report = backend.check_patch("/app/file.py", diff, {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is True

    def test_policy_yaml(self, backend: PurePythonBackend) -> None:
        yaml = backend.policy_yaml()
        assert isinstance(yaml, str)
        assert "version" in yaml


# ---------------------------------------------------------------------------
# NativeEngineBackend (skip if native unavailable)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not NATIVE_AVAILABLE, reason="native backend not available")
class TestNativeEngineBackend:
    @pytest.fixture
    def backend(self) -> NativeEngineBackend:
        return NativeEngineBackend.from_ruleset("strict")

    def test_name(self, backend: NativeEngineBackend) -> None:
        assert backend.name == "native"

    def test_check_shell_deny(self, backend: NativeEngineBackend) -> None:
        report = backend.check_shell("rm -rf /", {"cwd": "/tmp"})
        assert isinstance(report, dict)
        assert report["overall"]["allowed"] is False

    def test_check_shell_allow(self, backend: NativeEngineBackend) -> None:
        report = backend.check_shell("ls -la", {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is True

    def test_check_file_access_deny(self, backend: NativeEngineBackend) -> None:
        report = backend.check_file_access("/home/user/.ssh/id_rsa", {"cwd": "/tmp"})
        assert report["overall"]["allowed"] is False


# ---------------------------------------------------------------------------
# Results-to-report helper
# ---------------------------------------------------------------------------

class TestResultsToReportDict:
    def test_empty_results(self) -> None:
        report = _results_to_report_dict([])
        assert report["overall"]["allowed"] is True
        assert report["per_guard"] == []

    def test_single_allow(self) -> None:
        results = [GuardResult.allow("test_guard")]
        report = _results_to_report_dict(results)
        assert report["overall"]["allowed"] is True
        assert len(report["per_guard"]) == 1

    def test_single_deny(self) -> None:
        results = [GuardResult.block("test_guard", Severity.CRITICAL, "blocked")]
        report = _results_to_report_dict(results)
        assert report["overall"]["allowed"] is False
        assert report["overall"]["guard"] == "test_guard"
        assert report["overall"]["severity"] == "critical"

    def test_mixed_results(self) -> None:
        results = [
            GuardResult.allow("guard_a"),
            GuardResult.block("guard_b", Severity.ERROR, "denied"),
        ]
        report = _results_to_report_dict(results)
        assert report["overall"]["allowed"] is False
        assert len(report["per_guard"]) == 2


# ---------------------------------------------------------------------------
# Fallback behavior
# ---------------------------------------------------------------------------

class TestFallbackBehavior:
    def test_facade_works_without_native(self) -> None:
        """Verify that Clawdstrike works when native is not available."""
        with patch("clawdstrike.clawdstrike.NativeEngineBackend") as mock_cls:
            mock_cls.from_ruleset.side_effect = Exception("no native")
            mock_cls.from_yaml.side_effect = Exception("no native")

            cs = Clawdstrike.with_defaults("strict")
            assert cs._backend.name == "pure_python"

            d = cs.check_command("rm -rf /")
            assert d.denied

    def test_from_report_dict_roundtrip(self) -> None:
        """Verify Decision.from_report_dict produces the same result as from_guard_results."""
        results = [
            GuardResult.allow("guard_a"),
            GuardResult.block("guard_b", Severity.ERROR, "blocked"),
        ]

        # Direct path
        d1 = Decision.from_guard_results(results)

        # Report dict path (simulating backend output)
        report = _results_to_report_dict(results)
        d2 = Decision.from_report_dict(report)

        assert d1.status == d2.status
        assert d1.denied == d2.denied
        assert d1.guard == d2.guard
