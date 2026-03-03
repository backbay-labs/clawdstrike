"""Tests for clawdstrike.hunt.correlate — rule parsing, validation, and engine."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from clawdstrike.hunt.correlate import (
    CorrelationEngine,
    correlate,
    load_rules_from_files,
    parse_rule,
)
from clawdstrike.hunt.errors import CorrelationError
from clawdstrike.hunt.types import (
    EventSourceType,
    NormalizedVerdict,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXAMPLE_RULE = """\
schema: clawdstrike.hunt.correlation.v1
name: "MCP Tool Exfiltration Attempt"
severity: high
description: >
  Detects an MCP tool reading sensitive files followed by
  network egress to an external domain within 30 seconds.
window: 30s
conditions:
  - source: receipt
    action_type: file
    verdict: allow
    target_pattern: "/etc/passwd|/etc/shadow|\\\\.ssh/|\\\\.(env|pem|key)$"
    bind: file_access
  - source: [receipt, hubble]
    action_type: egress
    after: file_access
    within: 30s
    bind: egress_event
output:
  title: "Potential data exfiltration via MCP tool"
  evidence:
    - file_access
    - egress_event
"""

SINGLE_CONDITION_RULE = """\
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


def _make_event(
    source: EventSourceType,
    action_type: str,
    verdict: NormalizedVerdict,
    summary: str,
    ts: datetime,
) -> TimelineEvent:
    return TimelineEvent(
        timestamp=ts,
        source=source,
        kind=TimelineEventKind.GUARD_DECISION,
        verdict=verdict,
        summary=summary,
        action_type=action_type,
    )


# ---------------------------------------------------------------------------
# Rule parsing
# ---------------------------------------------------------------------------


class TestParseRule:
    def test_parse_valid_rule(self) -> None:
        rule = parse_rule(EXAMPLE_RULE)
        assert rule.schema == "clawdstrike.hunt.correlation.v1"
        assert rule.name == "MCP Tool Exfiltration Attempt"
        assert rule.severity == RuleSeverity.HIGH
        assert rule.window == timedelta(seconds=30)
        assert len(rule.conditions) == 2
        assert rule.conditions[0].source == ("receipt",)
        assert rule.conditions[0].action_type == "file"
        assert rule.conditions[0].verdict == "allow"
        assert rule.conditions[0].bind == "file_access"
        assert rule.conditions[1].source == ("receipt", "hubble")
        assert rule.conditions[1].after == "file_access"
        assert rule.conditions[1].within == timedelta(seconds=30)
        assert rule.output.title == "Potential data exfiltration via MCP tool"
        assert rule.output.evidence == ("file_access", "egress_event")

    def test_parse_single_source_string(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Single source test"
severity: low
description: "test"
window: 5m
conditions:
  - source: tetragon
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"""
        rule = parse_rule(yaml_str)
        assert rule.conditions[0].source == ("tetragon",)

    def test_parse_single_condition_rule(self) -> None:
        rule = parse_rule(SINGLE_CONDITION_RULE)
        assert rule.severity == RuleSeverity.CRITICAL
        assert len(rule.conditions) == 1


# ---------------------------------------------------------------------------
# Rule validation errors
# ---------------------------------------------------------------------------


class TestValidateRule:
    def test_reject_unknown_schema(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v99
name: "Bad schema"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"""
        with pytest.raises(CorrelationError, match="unsupported schema"):
            parse_rule(yaml_str)

    def test_reject_empty_conditions(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "No conditions"
severity: medium
description: "test"
window: 10s
conditions: []
output:
  title: "test"
  evidence: []
"""
        with pytest.raises(CorrelationError, match="at least one condition"):
            parse_rule(yaml_str)

    def test_reject_invalid_after_reference(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Bad after ref"
severity: high
description: "test"
window: 30s
conditions:
  - source: receipt
    after: nonexistent
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"""
        with pytest.raises(CorrelationError, match="unknown bind 'nonexistent'"):
            parse_rule(yaml_str)

    def test_reject_invalid_evidence_reference(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Bad evidence ref"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: evt
output:
  title: "test"
  evidence:
    - missing_bind
"""
        with pytest.raises(CorrelationError, match="unknown bind 'missing_bind'"):
            parse_rule(yaml_str)

    def test_reject_duplicate_bind_names(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Duplicate bind"
severity: high
description: "test"
window: 30s
conditions:
  - source: receipt
    action_type: file
    bind: evt
  - source: hubble
    action_type: egress
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"""
        with pytest.raises(CorrelationError, match="reuses bind name 'evt'"):
            parse_rule(yaml_str)

    def test_reject_within_without_after(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Within without after"
severity: low
description: "test"
window: 30s
conditions:
  - source: receipt
    within: 10s
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"""
        with pytest.raises(CorrelationError, match="'within' but no 'after'"):
            parse_rule(yaml_str)

    def test_reject_within_exceeding_window(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Within exceeds window"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: first
  - source: hubble
    after: first
    within: 60s
    bind: second
output:
  title: "test"
  evidence:
    - first
    - second
"""
        with pytest.raises(CorrelationError, match="exceeds global window"):
            parse_rule(yaml_str)

    def test_reject_zero_window(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Zero window"
severity: low
description: "test"
window: 0s
conditions:
  - source: receipt
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"""
        with pytest.raises(CorrelationError, match="window must be a positive duration"):
            parse_rule(yaml_str)

    def test_reject_zero_within(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Zero within"
severity: low
description: "test"
window: 30s
conditions:
  - source: receipt
    bind: first
  - source: receipt
    after: first
    within: 0s
    bind: second
output:
  title: "test"
  evidence:
    - first
    - second
"""
        with pytest.raises(CorrelationError, match="'within' must be a positive duration"):
            parse_rule(yaml_str)

    def test_reject_non_mapping_condition_entry(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Bad condition entry"
severity: low
description: "test"
window: 10s
conditions:
  - "oops"
output:
  title: "test"
  evidence: []
"""
        with pytest.raises(CorrelationError, match="condition 0 must be a mapping"):
            parse_rule(yaml_str)

    def test_reject_non_mapping_sequence_entry(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Bad sequence entry"
severity: low
description: "test"
window: 10s
sequence:
  - source: receipt
    bind: first
  - "oops"
output:
  title: "test"
  evidence:
    - first
"""
        with pytest.raises(CorrelationError, match="sequence item 1 must be a mapping"):
            parse_rule(yaml_str)

    def test_reject_condition_missing_bind(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Missing bind"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
output:
  title: "test"
  evidence: []
"""
        with pytest.raises(CorrelationError, match="condition 0 has invalid 'bind'"):
            parse_rule(yaml_str)

    def test_reject_condition_missing_source(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Missing source"
severity: low
description: "test"
window: 10s
conditions:
  - bind: evt
output:
  title: "test"
  evidence:
    - evt
"""
        with pytest.raises(CorrelationError, match="condition 0 has invalid 'source'"):
            parse_rule(yaml_str)

    def test_reject_condition_invalid_source_entry(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Bad source list"
severity: low
description: "test"
window: 10s
conditions:
  - bind: evt
    source: [receipt, 123]
output:
  title: "test"
  evidence:
    - evt
"""
        with pytest.raises(CorrelationError, match="condition 0 has invalid 'source'"):
            parse_rule(yaml_str)

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("action_type", "123"),
            ("verdict", "true"),
            ("target_pattern", "[oops]"),
            ("not_target_pattern", "{bad: value}"),
            ("after", "[first]"),
        ],
    )
    def test_reject_non_string_optional_condition_fields(self, field: str, value: str) -> None:
        yaml_str = f"""\
schema: clawdstrike.hunt.correlation.v1
name: "Bad optional field"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    bind: evt
    {field}: {value}
output:
  title: "test"
  evidence:
    - evt
"""
        with pytest.raises(CorrelationError, match=f"condition 0 has invalid '{field}'"):
            parse_rule(yaml_str)


# ---------------------------------------------------------------------------
# Load from files
# ---------------------------------------------------------------------------


class TestLoadRulesFromFiles:
    def test_load_from_temp_files(self, tmp_path) -> None:
        rule1_path = tmp_path / "rule1.yaml"
        rule1_path.write_text(SINGLE_CONDITION_RULE)

        rule2_yaml = """\
schema: clawdstrike.hunt.correlation.v1
name: "Lateral movement"
severity: critical
description: "Detects lateral movement patterns"
window: 5m
conditions:
  - source: tetragon
    action_type: process
    bind: proc
output:
  title: "Lateral movement detected"
  evidence:
    - proc
"""
        rule2_path = tmp_path / "rule2.yaml"
        rule2_path.write_text(rule2_yaml)

        rules = load_rules_from_files([str(rule1_path), str(rule2_path)])
        assert len(rules) == 2
        assert rules[0].name == "Forbidden Path Access"
        assert rules[1].name == "Lateral movement"

    def test_load_missing_file(self) -> None:
        with pytest.raises(CorrelationError):
            load_rules_from_files(["/nonexistent/rule.yaml"])


# ---------------------------------------------------------------------------
# Correlation engine — single condition
# ---------------------------------------------------------------------------


class TestCorrelationEngineSingle:
    def test_single_condition_fires_immediately(self) -> None:
        rule = parse_rule(SINGLE_CONDITION_RULE)
        engine = CorrelationEngine([rule])

        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY, "/etc/passwd", ts
        )

        alerts = engine.process_event(event)
        assert len(alerts) == 1
        assert alerts[0].rule_name == "Forbidden Path Access"
        assert alerts[0].severity == RuleSeverity.CRITICAL
        assert len(alerts[0].evidence) == 1

    def test_non_matching_event_no_alert(self) -> None:
        rule = parse_rule(SINGLE_CONDITION_RULE)
        engine = CorrelationEngine([rule])

        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = _make_event(
            EventSourceType.TETRAGON, "process", NormalizedVerdict.NONE, "ls", ts
        )

        alerts = engine.process_event(event)
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Correlation engine — multi-condition
# ---------------------------------------------------------------------------


class TestCorrelationEngineMulti:
    def test_two_condition_sequence_generates_alert(self) -> None:
        rule = parse_rule(EXAMPLE_RULE)
        engine = CorrelationEngine([rule])

        ts1 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2025, 6, 15, 12, 0, 10, tzinfo=timezone.utc)

        e1 = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW,
            "read /etc/passwd", ts1,
        )
        alerts = engine.process_event(e1)
        assert len(alerts) == 0

        e2 = _make_event(
            EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW,
            "egress TCP 10.0.0.1:8080 -> 93.184.216.34:443", ts2,
        )
        alerts = engine.process_event(e2)
        assert len(alerts) == 1
        assert alerts[0].title == "Potential data exfiltration via MCP tool"
        assert len(alerts[0].evidence) == 2

    def test_within_constraint_rejects_late_event(self) -> None:
        rule = parse_rule(EXAMPLE_RULE)
        engine = CorrelationEngine([rule])

        ts1 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2025, 6, 15, 12, 0, 31, tzinfo=timezone.utc)

        e1 = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW,
            "read /home/user/.ssh/id_rsa", ts1,
        )
        engine.process_event(e1)

        e2 = _make_event(
            EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW,
            "evil.com:443", ts2,
        )
        alerts = engine.process_event(e2)
        assert len(alerts) == 0


# ---------------------------------------------------------------------------
# Window eviction
# ---------------------------------------------------------------------------


class TestWindowEviction:
    def test_expired_window_evicted(self) -> None:
        rule = parse_rule(SINGLE_CONDITION_RULE)
        engine = CorrelationEngine([rule])

        old_ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        new_ts = datetime(2025, 6, 15, 12, 10, 0, tzinfo=timezone.utc)

        e1 = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW,
            "read /tmp/data", old_ts,
        )
        engine.process_event(e1)

        engine._evict_expired_at(new_ts)
        # After eviction, windows should be clear
        alerts = engine.flush()
        assert len(alerts) == 0

    def test_process_event_uses_event_time_for_capped_eviction(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Capped eviction"
severity: low
description: "test"
window: 5m
conditions:
  - source: receipt
    action_type: file
    bind: first
  - source: receipt
    action_type: egress
    after: first
    within: 5m
    bind: second
output:
  title: "Capped eviction match"
  evidence:
    - first
    - second
"""
        rule = parse_rule(yaml_str)
        engine = CorrelationEngine([rule])

        ts1 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2025, 6, 15, 12, 0, 45, tzinfo=timezone.utc)

        first = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW,
            "read /tmp/data", ts1,
        )
        second = _make_event(
            EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW,
            "egress TCP 10.0.0.1:8080 -> 93.184.216.34:443", ts2,
        )

        assert len(engine.process_event(first, timedelta(seconds=30))) == 0
        # Event-time capped eviction should drop the first window before second arrives.
        assert len(engine.process_event(second, timedelta(seconds=30))) == 0


# ---------------------------------------------------------------------------
# Dependent ordering
# ---------------------------------------------------------------------------


class TestDependentOrdering:
    def test_single_event_cannot_satisfy_root_and_dependent(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Self-match guard"
severity: high
description: "Should require two distinct events"
window: 30s
conditions:
  - source: receipt
    action_type: egress
    bind: first
  - source: receipt
    action_type: egress
    after: first
    within: 30s
    bind: second
output:
  title: "Two egress events"
  evidence:
    - first
    - second
"""
        rule = parse_rule(yaml_str)
        engine = CorrelationEngine([rule])

        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = _make_event(
            EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW,
            "evil.com:443", ts,
        )

        alerts = engine.process_event(event)
        assert len(alerts) == 0, "single event must not satisfy both conditions"

        ts2 = datetime(2025, 6, 15, 12, 0, 5, tzinfo=timezone.utc)
        event2 = _make_event(
            EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW,
            "other.com:443", ts2,
        )
        alerts = engine.process_event(event2)
        assert len(alerts) == 1

    def test_after_without_within_rejects_out_of_order(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Ordered Dependent Sequence"
severity: medium
description: "Dependent events must occur after their prerequisite"
window: 5m
conditions:
  - source: receipt
    action_type: file
    bind: first
  - source: receipt
    action_type: egress
    after: first
    bind: second
output:
  title: "Ordered sequence matched"
  evidence:
    - first
    - second
"""
        rule = parse_rule(yaml_str)
        engine = CorrelationEngine([rule])

        ts_first = datetime(2025, 6, 15, 12, 0, 10, tzinfo=timezone.utc)
        ts_older = datetime(2025, 6, 15, 12, 0, 5, tzinfo=timezone.utc)
        ts_newer = datetime(2025, 6, 15, 12, 0, 20, tzinfo=timezone.utc)

        first = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW,
            "read /etc/passwd", ts_first,
        )
        engine.process_event(first)

        out_of_order = _make_event(
            EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW,
            "egress TCP 10.0.0.1:8080 -> 93.184.216.34:443", ts_older,
        )
        alerts = engine.process_event(out_of_order)
        assert len(alerts) == 0, "older dependent must not match"

        ordered = _make_event(
            EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW,
            "egress TCP 10.0.0.1:8080 -> 93.184.216.34:443", ts_newer,
        )
        alerts = engine.process_event(ordered)
        assert len(alerts) == 1

    def test_three_condition_chain(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Dependent chain"
severity: high
description: "Should require three distinct events"
window: 30s
conditions:
  - source: receipt
    action_type: file
    bind: first
  - source: receipt
    action_type: egress
    after: first
    within: 30s
    bind: second
  - source: receipt
    action_type: egress
    after: second
    within: 30s
    bind: third
output:
  title: "Three-step sequence"
  evidence:
    - first
    - second
    - third
"""
        rule = parse_rule(yaml_str)
        engine = CorrelationEngine([rule])

        ts1 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2025, 6, 15, 12, 0, 5, tzinfo=timezone.utc)
        ts3 = datetime(2025, 6, 15, 12, 0, 10, tzinfo=timezone.utc)

        first = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW,
            "read /tmp/data", ts1,
        )
        assert len(engine.process_event(first)) == 0

        second = _make_event(
            EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW,
            "evil.com:443", ts2,
        )
        assert len(engine.process_event(second)) == 0, \
            "single dependent must not satisfy entire chain"

        third = _make_event(
            EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW,
            "other.com:443", ts3,
        )
        assert len(engine.process_event(third)) == 1


# ---------------------------------------------------------------------------
# Flush
# ---------------------------------------------------------------------------


class TestFlush:
    def test_flush_incomplete_window(self) -> None:
        rule = parse_rule(EXAMPLE_RULE)
        engine = CorrelationEngine([rule])

        ts1 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        e1 = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW,
            "read /etc/passwd", ts1,
        )
        engine.process_event(e1)

        alerts = engine.flush()
        assert len(alerts) == 0, "incomplete window should not produce alert"

    def test_process_event_cleans_up_empty_rule_window_bucket(self) -> None:
        rule = parse_rule(SINGLE_CONDITION_RULE)
        engine = CorrelationEngine([rule])

        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY,
            "/tmp/forbidden", ts,
        )

        alerts = engine.process_event(event)
        assert len(alerts) == 1
        assert 0 not in engine._windows

    def test_multiple_rules_same_event(self) -> None:
        rule1 = parse_rule(SINGLE_CONDITION_RULE)
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Any File Deny"
severity: medium
description: "Any file denial"
window: 1m
conditions:
  - source: receipt
    action_type: file
    verdict: deny
    bind: evt
output:
  title: "File denial observed"
  evidence:
    - evt
"""
        rule2 = parse_rule(yaml_str)
        engine = CorrelationEngine([rule1, rule2])

        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY,
            "/secret", ts,
        )

        alerts = engine.process_event(event)
        assert len(alerts) == 2
        names = [a.rule_name for a in alerts]
        assert "Forbidden Path Access" in names
        assert "Any File Deny" in names

    def test_hubble_source_matches(self) -> None:
        rule = parse_rule(EXAMPLE_RULE)
        engine = CorrelationEngine([rule])

        ts1 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2025, 6, 15, 12, 0, 5, tzinfo=timezone.utc)

        e1 = _make_event(
            EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW,
            "read /home/user/.env", ts1,
        )
        engine.process_event(e1)

        e2 = _make_event(
            EventSourceType.HUBBLE, "egress", NormalizedVerdict.ALLOW,
            "evil.com:443", ts2,
        )
        alerts = engine.process_event(e2)
        assert len(alerts) == 1

    def test_bad_regex_raises(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Bad regex"
severity: low
description: "test"
window: 10s
conditions:
  - source: receipt
    target_pattern: "[invalid"
    bind: evt
output:
  title: "test"
  evidence:
    - evt
"""
        rule = parse_rule(yaml_str)
        with pytest.raises(CorrelationError):
            CorrelationEngine([rule])


# ---------------------------------------------------------------------------
# correlate() convenience function
# ---------------------------------------------------------------------------


class TestSequenceShorthand:
    def test_parse_two_step_sequence(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Two step sequence"
severity: high
description: "test"
window: 30s
sequence:
  - bind: file_access
    source: receipt
    action_type: file
  - bind: egress_event
    source: receipt
    action_type: egress
output:
  title: "test"
  evidence:
    - file_access
    - egress_event
"""
        rule = parse_rule(yaml_str)
        assert len(rule.conditions) == 2
        assert rule.conditions[0].after is None
        assert rule.conditions[0].bind == "file_access"
        assert rule.conditions[1].after == "file_access"
        assert rule.conditions[1].bind == "egress_event"

    def test_parse_three_step_sequence(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Three step"
severity: high
description: "test"
window: 60s
sequence:
  - bind: step_a
    source: receipt
    action_type: file
  - bind: step_b
    source: receipt
    action_type: egress
  - bind: step_c
    source: receipt
    action_type: egress
output:
  title: "test"
  evidence:
    - step_a
    - step_b
    - step_c
"""
        rule = parse_rule(yaml_str)
        assert len(rule.conditions) == 3
        assert rule.conditions[0].after is None
        assert rule.conditions[1].after == "step_a"
        assert rule.conditions[2].after == "step_b"

    def test_explicit_after_override(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Override after"
severity: medium
description: "test"
window: 60s
sequence:
  - bind: step_a
    source: receipt
    action_type: file
  - bind: step_b
    source: receipt
    action_type: egress
  - bind: step_c
    source: receipt
    action_type: egress
    after: step_a
output:
  title: "test"
  evidence:
    - step_a
    - step_b
    - step_c
"""
        rule = parse_rule(yaml_str)
        assert rule.conditions[2].after == "step_a"

    def test_within_preserved(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Within in sequence"
severity: high
description: "test"
window: 60s
sequence:
  - bind: step_a
    source: receipt
    action_type: file
  - bind: step_b
    source: receipt
    action_type: egress
    within: 10s
output:
  title: "test"
  evidence:
    - step_a
    - step_b
"""
        rule = parse_rule(yaml_str)
        assert rule.conditions[1].within == timedelta(seconds=10)

    def test_empty_sequence_raises(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Empty sequence"
severity: low
description: "test"
window: 10s
sequence: []
output:
  title: "test"
  evidence: []
"""
        with pytest.raises(CorrelationError, match="sequence must have at least one item"):
            parse_rule(yaml_str)

    def test_sequence_and_conditions_mutually_exclusive(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Both"
severity: low
description: "test"
window: 10s
sequence:
  - bind: a
    source: receipt
conditions:
  - bind: b
    source: receipt
output:
  title: "test"
  evidence:
    - a
"""
        with pytest.raises(CorrelationError, match="mutually exclusive"):
            parse_rule(yaml_str)

    def test_single_item_sequence(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "Single"
severity: low
description: "test"
window: 30s
sequence:
  - bind: only
    source: receipt
    action_type: file
output:
  title: "test"
  evidence:
    - only
"""
        rule = parse_rule(yaml_str)
        assert len(rule.conditions) == 1
        assert rule.conditions[0].after is None
        assert rule.conditions[0].bind == "only"

    def test_end_to_end_sequence(self) -> None:
        yaml_str = """\
schema: clawdstrike.hunt.correlation.v1
name: "E2E sequence"
severity: high
description: "test"
window: 30s
sequence:
  - bind: file_read
    source: receipt
    action_type: file
    verdict: allow
  - bind: net_egress
    source: receipt
    action_type: egress
    within: 30s
output:
  title: "Sequence matched"
  evidence:
    - file_read
    - net_egress
"""
        rule = parse_rule(yaml_str)
        ts1 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2025, 6, 15, 12, 0, 5, tzinfo=timezone.utc)

        events = [
            _make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW, "read /etc/passwd", ts1),
            _make_event(EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW, "evil.com:443", ts2),
        ]

        alerts = correlate([rule], events)
        assert len(alerts) == 1
        assert alerts[0].title == "Sequence matched"
        assert len(alerts[0].evidence) == 2


# ---------------------------------------------------------------------------
# correlate() convenience function
# ---------------------------------------------------------------------------


class TestCorrelateFunction:
    def test_processes_events_and_returns_alerts(self) -> None:
        rule = parse_rule(SINGLE_CONDITION_RULE)
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY, "/etc/passwd", ts),
            _make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY, "/etc/shadow", ts),
        ]

        alerts = correlate([rule], events)
        assert len(alerts) == 2
        assert alerts[0].rule_name == "Forbidden Path Access"

    def test_multi_step_sequence(self) -> None:
        rule = parse_rule(EXAMPLE_RULE)
        ts1 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2025, 6, 15, 12, 0, 10, tzinfo=timezone.utc)
        events = [
            _make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW, "read /etc/passwd", ts1),
            _make_event(EventSourceType.RECEIPT, "egress", NormalizedVerdict.ALLOW, "egress TCP -> 93.184.216.34:443", ts2),
        ]

        alerts = correlate([rule], events)
        assert len(alerts) == 1
        assert alerts[0].title == "Potential data exfiltration via MCP tool"

    def test_returns_empty_for_no_matches(self) -> None:
        rule = parse_rule(SINGLE_CONDITION_RULE)
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW, "test", ts),
        ]

        alerts = correlate([rule], events)
        assert len(alerts) == 0
