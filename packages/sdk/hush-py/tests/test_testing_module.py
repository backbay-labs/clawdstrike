"""Tests for clawdstrike.testing module.

Covers:
1. ScenarioSuite YAML parsing (from_yaml, round-trip to_yaml)
2. ScenarioRunner with inline policy (file_access, shell_command, network_egress)
3. ScenarioRunner.check() convenience method
4. SuiteReport.print_summary() and to_json()
5. Scenario expect/expect_guard assertion logic
6. diff_policies() between permissive and strict rulesets
7. Edge cases: empty suite, unknown action types
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
import yaml

from clawdstrike.testing import (
    DiffEntry,
    DiffReport,
    Scenario,
    ScenarioResult,
    ScenarioRunner,
    ScenarioSuite,
    SuiteReport,
    diff_policies,
)
from clawdstrike.types import DecisionStatus

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

TEST_POLICY_YAML = """\
version: "1.2.0"
name: test-policy
guards:
  forbidden_path:
    patterns:
      - "~/.ssh/**"
      - "~/.aws/**"
  egress_allowlist:
    allow:
      - "*.openai.com"
      - "registry.npmjs.org"
    default_action: block
  shell_command:
    forbidden_patterns:
      - "rm\\\\s+-rf"
  jailbreak:
    detector:
      block_threshold: 70
      warn_threshold: 30
settings:
  fail_fast: false
"""

SUITE_YAML = """\
name: basic-checks
scenarios:
  - name: SSH key denied
    action: file_access
    target: ~/.ssh/id_rsa
    expect: deny
    expect_guard: forbidden_path

  - name: Temp file allowed
    action: file_access
    target: /tmp/test.txt
    expect: allow

  - name: Dangerous rm denied
    action: shell_command
    target: "rm -rf /"
    expect: deny

  - name: Simple ls allowed
    action: shell_command
    target: "ls"
    expect: allow

  - name: OpenAI egress allowed
    action: network_egress
    target: api.openai.com
    expect: allow

  - name: Blocked domain denied
    action: network_egress
    target: evil-domain.example.com
    expect: deny
"""


@pytest.fixture
def runner() -> ScenarioRunner:
    return ScenarioRunner(TEST_POLICY_YAML)


@pytest.fixture
def suite() -> ScenarioSuite:
    return ScenarioSuite.from_yaml(SUITE_YAML)


# ---------------------------------------------------------------------------
# 1. ScenarioSuite YAML parsing
# ---------------------------------------------------------------------------


class TestScenarioSuiteYaml:
    def test_from_yaml_parses_name(self, suite: ScenarioSuite) -> None:
        assert suite.name == "basic-checks"

    def test_from_yaml_parses_scenarios(self, suite: ScenarioSuite) -> None:
        assert len(suite.scenarios) == 6

    def test_from_yaml_scenario_fields(self, suite: ScenarioSuite) -> None:
        ssh = suite.scenarios[0]
        assert ssh.name == "SSH key denied"
        assert ssh.action == "file_access"
        assert ssh.target == "~/.ssh/id_rsa"
        assert ssh.expect == "deny"
        assert ssh.expect_guard == "forbidden_path"

    def test_from_yaml_scenario_defaults(self, suite: ScenarioSuite) -> None:
        temp = suite.scenarios[1]
        assert temp.expect_guard is None
        assert temp.content is None
        assert temp.payload == {}
        assert temp.tags == []

    def test_from_yaml_invalid_not_mapping(self) -> None:
        with pytest.raises(ValueError, match="must be a mapping"):
            ScenarioSuite.from_yaml("- item1\n- item2\n")

    def test_from_yaml_empty_scenarios(self) -> None:
        s = ScenarioSuite.from_yaml("scenarios: []\n")
        assert len(s.scenarios) == 0

    def test_from_yaml_missing_scenarios_key(self) -> None:
        s = ScenarioSuite.from_yaml("name: empty\n")
        assert len(s.scenarios) == 0

    def test_round_trip_to_yaml(self, suite: ScenarioSuite) -> None:
        """Serialize to YAML and re-parse; scenarios should match."""
        yaml_out = suite.to_yaml()
        reparsed = ScenarioSuite.from_yaml(yaml_out)
        assert len(reparsed.scenarios) == len(suite.scenarios)
        for orig, rt in zip(suite.scenarios, reparsed.scenarios, strict=True):
            assert orig.name == rt.name
            assert orig.action == rt.action
            assert orig.target == rt.target
            assert orig.expect == rt.expect
            assert orig.expect_guard == rt.expect_guard

    def test_to_yaml_preserves_name(self, suite: ScenarioSuite) -> None:
        yaml_out = suite.to_yaml()
        data = yaml.safe_load(yaml_out)
        assert data["name"] == "basic-checks"

    def test_to_yaml_omits_unnamed(self) -> None:
        s = ScenarioSuite([], name="unnamed")
        yaml_out = s.to_yaml()
        data = yaml.safe_load(yaml_out)
        assert "name" not in data

    def test_from_yaml_file(self, suite: ScenarioSuite, tmp_path: Path) -> None:
        yaml_file = tmp_path / "suite.yaml"
        yaml_file.write_text(SUITE_YAML)
        loaded = ScenarioSuite.from_yaml_file(yaml_file)
        assert len(loaded.scenarios) == len(suite.scenarios)
        assert loaded.name == suite.name

    def test_from_dict(self) -> None:
        data = {
            "name": "dict-suite",
            "scenarios": [
                {"name": "test1", "action": "file_access", "target": "/tmp/x"},
            ],
        }
        s = ScenarioSuite.from_dict(data)
        assert s.name == "dict-suite"
        assert len(s.scenarios) == 1
        assert s.scenarios[0].target == "/tmp/x"

    def test_policy_ref_preserved(self) -> None:
        s = ScenarioSuite.from_yaml("policy: ./my-policy.yaml\nscenarios: []\n")
        assert s.policy_ref == "./my-policy.yaml"
        yaml_out = s.to_yaml()
        data = yaml.safe_load(yaml_out)
        assert data["policy"] == "./my-policy.yaml"

    def test_tags_and_payload_round_trip(self) -> None:
        raw = """\
scenarios:
  - name: tagged
    action: shell_command
    target: echo hello
    tags: [ci, smoke]
    payload:
      env: production
"""
        s = ScenarioSuite.from_yaml(raw)
        assert s.scenarios[0].tags == ["ci", "smoke"]
        assert s.scenarios[0].payload == {"env": "production"}

        reparsed = ScenarioSuite.from_yaml(s.to_yaml())
        assert reparsed.scenarios[0].tags == ["ci", "smoke"]
        assert reparsed.scenarios[0].payload == {"env": "production"}

    def test_content_round_trip(self) -> None:
        raw = """\
scenarios:
  - name: write test
    action: file_write
    target: /tmp/out.txt
    content: "some content"
    expect: allow
"""
        s = ScenarioSuite.from_yaml(raw)
        assert s.scenarios[0].content == "some content"
        reparsed = ScenarioSuite.from_yaml(s.to_yaml())
        assert reparsed.scenarios[0].content == "some content"

    def test_description_round_trip(self) -> None:
        raw = """\
scenarios:
  - name: described
    action: file_access
    target: /tmp/x
    description: "This scenario tests read access"
"""
        s = ScenarioSuite.from_yaml(raw)
        assert s.scenarios[0].description == "This scenario tests read access"
        reparsed = ScenarioSuite.from_yaml(s.to_yaml())
        assert reparsed.scenarios[0].description == "This scenario tests read access"


# ---------------------------------------------------------------------------
# 2. ScenarioRunner with policy -- file_access, shell_command, network_egress
# ---------------------------------------------------------------------------


class TestScenarioRunnerFileAccess:
    def test_ssh_key_denied(self, runner: ScenarioRunner) -> None:
        result = runner.check("SSH key", "file_access", "~/.ssh/id_rsa", expect="deny")
        assert result.passed
        assert result.decision.status == DecisionStatus.DENY

    def test_aws_credentials_denied(self, runner: ScenarioRunner) -> None:
        result = runner.check("AWS creds", "file_access", "~/.aws/credentials", expect="deny")
        assert result.passed
        assert result.decision.denied

    def test_tmp_file_allowed(self, runner: ScenarioRunner) -> None:
        result = runner.check("Temp file", "file_access", "/tmp/test.txt", expect="allow")
        assert result.passed
        assert result.decision.allowed

    def test_safe_file_allowed(self, runner: ScenarioRunner) -> None:
        result = runner.check("Source file", "file_access", "/app/src/main.py", expect="allow")
        assert result.passed


class TestScenarioRunnerShellCommand:
    def test_rm_rf_denied(self, runner: ScenarioRunner) -> None:
        result = runner.check("rm -rf", "shell_command", "rm -rf /", expect="deny")
        assert result.passed
        assert result.decision.denied

    def test_ls_allowed(self, runner: ScenarioRunner) -> None:
        result = runner.check("ls", "shell_command", "ls", expect="allow")
        assert result.passed
        assert result.decision.allowed

    def test_git_status_allowed(self, runner: ScenarioRunner) -> None:
        result = runner.check("git", "shell_command", "git status", expect="allow")
        assert result.passed


class TestScenarioRunnerNetworkEgress:
    def test_openai_allowed(self, runner: ScenarioRunner) -> None:
        result = runner.check("OpenAI", "network_egress", "api.openai.com", expect="allow")
        assert result.passed
        assert result.decision.allowed

    def test_npmjs_allowed(self, runner: ScenarioRunner) -> None:
        result = runner.check("npm", "network_egress", "registry.npmjs.org", expect="allow")
        assert result.passed

    def test_unknown_domain_denied(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "Unknown domain",
            "network_egress",
            "evil-domain.example.com",
            expect="deny",
        )
        assert result.passed
        assert result.decision.denied

    def test_random_domain_denied(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "Random domain",
            "network_egress",
            "data-exfil.attacker.io",
            expect="deny",
        )
        assert result.passed
        assert result.decision.denied


# ---------------------------------------------------------------------------
# 3. ScenarioRunner.check() convenience method
# ---------------------------------------------------------------------------


class TestScenarioRunnerCheck:
    def test_check_returns_scenario_result(self, runner: ScenarioRunner) -> None:
        result = runner.check("test", "file_access", "/tmp/safe.txt")
        assert isinstance(result, ScenarioResult)

    def test_check_no_expect_always_passes(self, runner: ScenarioRunner) -> None:
        """Without expect, result should always pass (no assertion to fail)."""
        result = runner.check("no-expect", "file_access", "~/.ssh/id_rsa")
        assert result.passed is True

    def test_check_wrong_expect_fails(self, runner: ScenarioRunner) -> None:
        """Expecting allow on a denied path should fail."""
        result = runner.check(
            "wrong expect", "file_access", "~/.ssh/id_rsa", expect="allow"
        )
        assert result.passed is False
        assert result.mismatch is not None
        assert "Expected allow" in result.mismatch

    def test_check_with_content(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "file write",
            "file_write",
            "/tmp/out.json",
            content="{}",
            expect="allow",
        )
        assert result.passed

    def test_check_with_payload(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "custom port",
            "network_egress",
            "api.openai.com",
            expect="allow",
            payload={"port": 8080},
        )
        assert result.passed

    def test_check_with_tags(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "tagged",
            "file_access",
            "/tmp/safe.txt",
            tags=["smoke", "ci"],
        )
        assert result.scenario.tags == ["smoke", "ci"]

    def test_check_duration_positive(self, runner: ScenarioRunner) -> None:
        result = runner.check("timing", "file_access", "/tmp/test.txt")
        assert result.duration_ms >= 0


# ---------------------------------------------------------------------------
# 4. SuiteReport: print_summary() and to_json()
# ---------------------------------------------------------------------------


class TestSuiteReport:
    def test_run_produces_report(self, runner: ScenarioRunner, suite: ScenarioSuite) -> None:
        report = runner.run(suite)
        assert isinstance(report, SuiteReport)
        assert report.total == 6
        assert report.passed + report.failed == report.total

    def test_all_scenarios_pass(self, runner: ScenarioRunner, suite: ScenarioSuite) -> None:
        report = runner.run(suite)
        assert report.passed == report.total
        assert report.failed == 0

    def test_print_summary_output(self, runner: ScenarioRunner, suite: ScenarioSuite) -> None:
        report = runner.run(suite)
        buf = io.StringIO()
        report.print_summary(file=buf)
        output = buf.getvalue()
        assert "Policy Test Report" in output
        assert "Total:" in output
        assert "Passed:" in output
        assert "Failed:" in output
        assert "PASS" in output

    def test_print_summary_shows_failures(self, runner: ScenarioRunner) -> None:
        """Create a scenario that fails and verify FAIL shows up."""
        bad_scenario = Scenario(
            name="wrong-expect",
            action="file_access",
            target="~/.ssh/id_rsa",
            expect="allow",  # will actually be denied
        )
        report = runner.run_scenarios([bad_scenario])
        buf = io.StringIO()
        report.print_summary(file=buf)
        output = buf.getvalue()
        assert "FAIL" in output
        assert report.failed == 1

    def test_to_json_valid(self, runner: ScenarioRunner, suite: ScenarioSuite) -> None:
        report = runner.run(suite)
        json_str = report.to_json()
        data = json.loads(json_str)
        assert data["policy"] == TEST_POLICY_YAML
        assert data["total"] == 6
        assert "results" in data
        assert len(data["results"]) == 6

    def test_to_json_result_fields(self, runner: ScenarioRunner, suite: ScenarioSuite) -> None:
        report = runner.run(suite)
        data = json.loads(report.to_json())
        first = data["results"][0]
        assert "scenario" in first
        assert "action" in first
        assert "target" in first
        assert "status" in first
        assert "passed" in first
        assert "duration_ms" in first
        assert "per_guard" in first

    def test_to_dict(self, runner: ScenarioRunner, suite: ScenarioSuite) -> None:
        report = runner.run(suite)
        d = report.to_dict()
        assert isinstance(d, dict)
        assert d["total"] == 6
        assert isinstance(d["results"], list)

    def test_save_to_file(
        self, runner: ScenarioRunner, suite: ScenarioSuite, tmp_path: Path
    ) -> None:
        report = runner.run(suite)
        out_file = tmp_path / "report.json"
        report.save(out_file)
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert data["total"] == 6

    def test_duration_ms_positive(self, runner: ScenarioRunner, suite: ScenarioSuite) -> None:
        report = runner.run(suite)
        assert report.duration_ms >= 0

    def test_print_json_lines(self, runner: ScenarioRunner, suite: ScenarioSuite) -> None:
        report = runner.run(suite)
        buf = io.StringIO()
        report.print_json_lines(file=buf)
        lines = buf.getvalue().strip().split("\n")
        assert len(lines) == 6
        for line in lines:
            data = json.loads(line)
            assert "scenario" in data
            assert "passed" in data


# ---------------------------------------------------------------------------
# 5. Scenario expect/expect_guard assertion logic
# ---------------------------------------------------------------------------


class TestScenarioAssertionLogic:
    def test_expect_deny_matches_deny(self, runner: ScenarioRunner) -> None:
        result = runner.check("ssh deny", "file_access", "~/.ssh/id_rsa", expect="deny")
        assert result.passed is True
        assert result.mismatch is None

    def test_expect_allow_matches_allow(self, runner: ScenarioRunner) -> None:
        result = runner.check("safe read", "file_access", "/tmp/ok.txt", expect="allow")
        assert result.passed is True
        assert result.mismatch is None

    def test_expect_mismatch_sets_mismatch_message(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "mismatch", "file_access", "~/.ssh/id_rsa", expect="allow"
        )
        assert result.passed is False
        assert result.mismatch is not None
        assert "Expected allow" in result.mismatch
        assert "deny" in result.mismatch

    def test_expect_guard_matches(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "guard match",
            "file_access",
            "~/.ssh/id_rsa",
            expect="deny",
            expect_guard="forbidden_path",
        )
        assert result.passed is True

    def test_expect_guard_mismatch(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "wrong guard",
            "file_access",
            "~/.ssh/id_rsa",
            expect="deny",
            expect_guard="nonexistent_guard",
        )
        assert result.passed is False
        assert result.mismatch is not None
        assert "Expected guard" in result.mismatch

    def test_no_expect_always_passes(self, runner: ScenarioRunner) -> None:
        """Without expect, any verdict passes."""
        denied = runner.check("no-assert deny", "file_access", "~/.ssh/id_rsa")
        assert denied.passed is True

        allowed = runner.check("no-assert allow", "file_access", "/tmp/safe.txt")
        assert allowed.passed is True

    def test_expect_guard_only_checked_when_verdict_passes(self, runner: ScenarioRunner) -> None:
        """If expect verdict mismatches, expect_guard mismatch should not override."""
        result = runner.check(
            "verdict mismatch first",
            "file_access",
            "~/.ssh/id_rsa",
            expect="allow",
            expect_guard="wrong_guard",
        )
        assert result.passed is False
        # The mismatch should be about verdict, not guard
        assert "Expected allow" in result.mismatch

    def test_invalid_expect_value_no_crash(self, runner: ScenarioRunner) -> None:
        """An invalid expect value should fail the scenario (not crash)."""
        result = runner.check(
            "invalid expect",
            "file_access",
            "/tmp/test.txt",
            expect="invalid_status",
        )
        # Invalid expect value is now treated as a test failure
        assert result.passed is False
        assert "must be one of allow, warn, or deny" in (result.mismatch or "")


# ---------------------------------------------------------------------------
# 6. diff_policies() between permissive and strict
# ---------------------------------------------------------------------------


class TestDiffPolicies:
    def test_diff_detects_changes(self) -> None:
        """Permissive vs strict should differ on blocked egress/paths."""
        permissive_yaml = """\
version: "1.2.0"
name: permissive
guards:
  forbidden_path:
    patterns: []
  egress_allowlist:
    allow: []
    default_action: allow
  shell_command:
    enabled: false
settings:
  fail_fast: false
"""
        strict_yaml = TEST_POLICY_YAML

        scenarios_yaml = """\
scenarios:
  - name: SSH key
    action: file_access
    target: ~/.ssh/id_rsa

  - name: Safe file
    action: file_access
    target: /tmp/test.txt

  - name: Unknown domain
    action: network_egress
    target: evil.example.com

  - name: Safe command
    action: shell_command
    target: ls
"""
        suite = ScenarioSuite.from_yaml(scenarios_yaml)
        report = diff_policies(permissive_yaml, strict_yaml, suite)

        assert isinstance(report, DiffReport)
        assert report.total == 4
        # SSH key and unknown domain should differ
        assert len(report.changed) >= 1
        assert report.unchanged_count + len(report.changed) == report.total

    def test_diff_same_policy_no_changes(self) -> None:
        suite = ScenarioSuite.from_yaml("""\
scenarios:
  - name: test
    action: file_access
    target: /tmp/test.txt
""")
        report = diff_policies(TEST_POLICY_YAML, TEST_POLICY_YAML, suite)
        assert len(report.changed) == 0
        assert report.unchanged_count == 1

    def test_diff_report_print_summary(self) -> None:
        suite = ScenarioSuite.from_yaml("""\
scenarios:
  - name: test
    action: file_access
    target: /tmp/test.txt
""")
        report = diff_policies(TEST_POLICY_YAML, TEST_POLICY_YAML, suite)
        buf = io.StringIO()
        report.print_summary(file=buf)
        output = buf.getvalue()
        assert "Policy Diff" in output
        assert "No behavior changes detected" in output

    def test_diff_entry_fields(self) -> None:
        permissive_yaml = """\
version: "1.2.0"
name: permissive
guards:
  forbidden_path:
    patterns: []
settings:
  fail_fast: false
"""
        suite = ScenarioSuite.from_yaml("""\
scenarios:
  - name: SSH key
    action: file_access
    target: ~/.ssh/id_rsa
""")
        report = diff_policies(permissive_yaml, TEST_POLICY_YAML, suite)
        assert len(report.changed) == 1
        entry = report.changed[0]
        assert isinstance(entry, DiffEntry)
        assert entry.scenario_name == "SSH key"
        assert entry.action == "file_access"
        assert entry.baseline_verdict == "allow"
        assert entry.candidate_verdict == "deny"

    def test_diff_with_changed_scenarios_prints_delta(self) -> None:
        permissive_yaml = """\
version: "1.2.0"
name: permissive
guards:
  forbidden_path:
    patterns: []
settings:
  fail_fast: false
"""
        suite = ScenarioSuite.from_yaml("""\
scenarios:
  - name: SSH key
    action: file_access
    target: ~/.ssh/id_rsa
""")
        report = diff_policies(permissive_yaml, TEST_POLICY_YAML, suite)
        buf = io.StringIO()
        report.print_summary(file=buf)
        output = buf.getvalue()
        assert "ALLOW -> DENY" in output

    def test_diff_detects_guard_change_when_verdict_stays_the_same(self) -> None:
        baseline_yaml = """\
version: "1.2.0"
name: baseline
guards:
  forbidden_path:
    patterns:
      - /etc/secret.txt
"""
        candidate_yaml = """\
version: "1.2.0"
name: candidate
guards:
  path_allowlist:
    allowed_paths:
      - /tmp/**
"""
        suite = ScenarioSuite.from_yaml("""\
scenarios:
  - name: Secret file
    action: file_access
    target: /etc/secret.txt
""")

        report = diff_policies(baseline_yaml, candidate_yaml, suite)

        assert len(report.changed) == 1
        assert report.changed[0].baseline_verdict == "deny"
        assert report.changed[0].candidate_verdict == "deny"
        assert report.changed[0].baseline_guard == "forbidden_path"
        assert report.changed[0].candidate_guard == "path_allowlist"


# ---------------------------------------------------------------------------
# 7. Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_suite_produces_empty_report(self, runner: ScenarioRunner) -> None:
        empty = ScenarioSuite([], name="empty")
        report = runner.run(empty)
        assert report.total == 0
        assert report.passed == 0
        assert report.failed == 0
        assert report.results == []

    def test_empty_suite_print_summary(self, runner: ScenarioRunner) -> None:
        empty = ScenarioSuite([], name="empty")
        report = runner.run(empty)
        buf = io.StringIO()
        report.print_summary(file=buf)
        output = buf.getvalue()
        assert "Total:  0" in output

    def test_empty_suite_to_json(self, runner: ScenarioRunner) -> None:
        empty = ScenarioSuite([], name="empty")
        report = runner.run(empty)
        data = json.loads(report.to_json())
        assert data["total"] == 0
        assert data["results"] == []

    def test_unknown_action_type_does_not_crash(self, runner: ScenarioRunner) -> None:
        """Unknown action types should be dispatched as custom actions."""
        result = runner.check(
            "custom action",
            "totally_custom_type",
            "some_target",
        )
        assert isinstance(result, ScenarioResult)
        # Should pass since no expect is set
        assert result.passed is True

    def test_unknown_action_type_with_payload(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "custom with data",
            "my_custom_action",
            "target_value",
            payload={"key": "value"},
        )
        assert isinstance(result, ScenarioResult)

    def test_run_scenarios_convenience(self, runner: ScenarioRunner) -> None:
        scenarios = [
            Scenario(name="s1", action="file_access", target="/tmp/a.txt", expect="allow"),
            Scenario(name="s2", action="file_access", target="~/.ssh/id_rsa", expect="deny"),
        ]
        report = runner.run_scenarios(scenarios)
        assert report.total == 2
        assert report.passed == 2

    def test_scenario_id_auto_generated(self) -> None:
        s = Scenario(name="auto-id", action="file_access", target="/tmp/x")
        assert s.id is not None
        assert len(s.id) == 8

    def test_scenario_result_to_dict(self, runner: ScenarioRunner) -> None:
        result = runner.check("dict test", "file_access", "/tmp/test.txt", expect="allow")
        d = result.to_dict()
        assert d["scenario"] == "dict test"
        assert d["action"] == "file_access"
        assert d["target"] == "/tmp/test.txt"
        assert d["passed"] is True
        assert isinstance(d["duration_ms"], float)

    def test_scenario_result_to_json_line(self, runner: ScenarioRunner) -> None:
        result = runner.check("json line", "file_access", "/tmp/test.txt")
        line = result.to_json_line()
        data = json.loads(line)
        assert data["scenario"] == "json line"

    def test_runner_from_clawdstrike_instance(self) -> None:
        """ScenarioRunner should accept a pre-built Clawdstrike instance."""
        from clawdstrike.clawdstrike import Clawdstrike

        cs = Clawdstrike.from_policy(TEST_POLICY_YAML)
        runner = ScenarioRunner(cs)
        result = runner.check("via instance", "file_access", "/tmp/test.txt", expect="allow")
        assert result.passed

    def test_file_write_action_dispatched(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "write test",
            "file_write",
            "/tmp/output.json",
            content='{"data": true}',
            expect="allow",
        )
        assert result.passed

    def test_patch_apply_action_dispatched(self, runner: ScenarioRunner) -> None:
        diff = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n"
        result = runner.check(
            "patch test",
            "patch_apply",
            "/app/file.py",
            content=diff,
        )
        assert isinstance(result, ScenarioResult)

    def test_user_input_action_dispatched(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "user input",
            "user_input",
            "Hello, world!",
        )
        assert isinstance(result, ScenarioResult)

    def test_mcp_tool_call_dispatched(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "mcp tool",
            "mcp_tool_call",
            "read_file",
            payload={"args": {"path": "/tmp/x"}},
        )
        assert isinstance(result, ScenarioResult)

    def test_invalid_network_port_fails_closed_without_aborting_suite(
        self, runner: ScenarioRunner
    ) -> None:
        suite = ScenarioSuite.from_yaml(
            """\
scenarios:
  - name: malformed port
    action: network_egress
    target: api.example.com
    payload:
      port: abc
  - name: safe write
    action: file_write
    target: /tmp/output.json
    content: "{}"
    expect: allow
"""
        )

        report = runner.run(suite)

        assert report.total == 2
        assert report.failed == 1
        assert report.results[0].decision.status == DecisionStatus.DENY
        assert report.results[0].passed is False
        assert report.results[0].mismatch is not None
        assert "Invalid network_egress port" in report.results[0].mismatch
        assert report.results[1].passed is True

    def test_missing_user_input_text_fails_closed(self, runner: ScenarioRunner) -> None:
        result = runner.check(
            "missing text",
            "user_input",
            expect="deny",
        )

        assert result.decision.status == DecisionStatus.DENY
        assert result.passed is True
        assert result.decision.message == "Invalid user_input payload: missing text field"

    def test_invalid_expect_rejected_during_suite_load(self) -> None:
        with pytest.raises(
            ValueError,
            match=r"Scenario 'bad expect' expect must be one of allow, warn, or deny",
        ):
            ScenarioSuite.from_yaml(
                """\
scenarios:
  - name: bad expect
    action: file_access
    target: /tmp/test.txt
    expect: invalid_status
"""
            )

    def test_non_mapping_runtime_payload_fails_scenario_without_aborting_suite(
        self, runner: ScenarioRunner
    ) -> None:
        report = runner.run_scenarios(
            [
                Scenario(
                    name="bad payload",
                    action="network_egress",
                    target="api.example.com",
                    payload=["443"],  # type: ignore[arg-type]
                ),
                Scenario(
                    name="good payload",
                    action="file_access",
                    target="/tmp/test.txt",
                    expect="allow",
                ),
            ]
        )

        assert report.total == 2
        assert report.failed == 1
        assert report.results[0].passed is False
        assert report.results[0].decision.status == DecisionStatus.DENY
        assert "payload must be a mapping" in (report.results[0].mismatch or "")
        assert report.results[1].passed is True
