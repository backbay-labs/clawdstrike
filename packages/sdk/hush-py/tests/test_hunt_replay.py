"""Tests for clawdstrike.hunt.replay — event replay / retrohunt."""

from __future__ import annotations

import json

from clawdstrike.hunt.correlate import parse_rule
from clawdstrike.hunt.ioc import IocDatabase
from clawdstrike.hunt.replay import ReplayResult, replay
from clawdstrike.hunt.types import IocEntry, IocType


SINGLE_RULE_YAML = """\
schema: clawdstrike.hunt.correlation.v1
name: "Forbidden Path Access"
severity: critical
description: "Detects any denied file access"
window: 5m
conditions:
  - source: receipt
    action_type: file
    verdict: deny
    bind: denied_access
output:
  title: "File access denied"
  evidence:
    - denied_access
"""


class TestReplay:
    def test_replay_with_rules_and_events(self, tmp_path) -> None:
        rule = parse_rule(SINGLE_RULE_YAML)
        # Write a test envelope to directory
        events_file = tmp_path / "events.json"
        events_file.write_text(json.dumps([
            {
                "payload": {"action": "file", "verdict": "deny", "target": "/etc/passwd"},
                "signed_at": "2025-06-15T12:00:00Z",
            },
        ]))

        result = replay(rules=[rule], dirs=[str(tmp_path)])
        assert isinstance(result, ReplayResult)
        assert result.rules_evaluated == 1
        assert isinstance(result.alerts, tuple)
        assert isinstance(result.ioc_matches, tuple)

    def test_replay_no_events(self, tmp_path) -> None:
        rule = parse_rule(SINGLE_RULE_YAML)
        result = replay(rules=[rule], dirs=[str(tmp_path)])
        assert len(result.alerts) == 0
        assert len(result.ioc_matches) == 0
        assert result.events_scanned == 0
        assert result.time_range is None
        assert result.rules_evaluated == 1

    def test_replay_with_ioc_database(self, tmp_path) -> None:
        rule = parse_rule(SINGLE_RULE_YAML)
        ioc_db = IocDatabase()
        ioc_db.add_entry(IocEntry(
            indicator="evil.com",
            ioc_type=IocType.DOMAIN,
        ))
        result = replay(rules=[rule], dirs=[str(tmp_path)], ioc_db=ioc_db)
        assert isinstance(result.ioc_matches, tuple)
        assert result.rules_evaluated == 1

    def test_replay_with_rule_file_paths(self, tmp_path) -> None:
        rule_file = tmp_path / "rule.yaml"
        rule_file.write_text(SINGLE_RULE_YAML)
        result = replay(rules=[str(rule_file)], dirs=[str(tmp_path)])
        assert result.rules_evaluated == 1
        assert result.events_scanned == 0

    def test_time_range_none_for_empty(self, tmp_path) -> None:
        rule = parse_rule(SINGLE_RULE_YAML)
        result = replay(rules=[rule], dirs=[str(tmp_path)])
        assert result.time_range is None

    def test_rules_evaluated_count(self, tmp_path) -> None:
        rule1 = parse_rule(SINGLE_RULE_YAML)
        rule2 = parse_rule("""\
schema: clawdstrike.hunt.correlation.v1
name: "Another rule"
severity: low
description: "test"
window: 1m
conditions:
  - source: receipt
    action_type: egress
    bind: evt
output:
  title: "test"
  evidence:
    - evt
""")
        result = replay(rules=[rule1, rule2], dirs=[str(tmp_path)])
        assert result.rules_evaluated == 2
