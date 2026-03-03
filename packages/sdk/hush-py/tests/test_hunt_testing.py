"""Tests for clawdstrike.hunt.testing — rule testing framework."""

from __future__ import annotations

from datetime import datetime, timezone

from clawdstrike.hunt.correlate import parse_rule
from clawdstrike.hunt.testing import event
from clawdstrike.hunt.testing import test_rule as run_test_rule
from clawdstrike.hunt.types import (
    EventSourceType,
    NormalizedVerdict,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
)

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


class TestEventHelper:
    def test_defaults(self) -> None:
        e = event()
        assert isinstance(e.timestamp, datetime)
        assert e.source == EventSourceType.RECEIPT
        assert e.kind == TimelineEventKind.GUARD_DECISION
        assert e.verdict == NormalizedVerdict.ALLOW
        assert e.summary == "test event"

    def test_overrides(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        e = event(
            timestamp=ts,
            source=EventSourceType.TETRAGON,
            summary="custom",
            action_type="file",
        )
        assert e.timestamp == ts
        assert e.source == EventSourceType.TETRAGON
        assert e.summary == "custom"
        assert e.action_type == "file"


class TestTestRule:
    def test_yaml_string_alerts_match(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY, "/etc/passwd", ts)]
        result = run_test_rule(SINGLE_RULE_YAML, given=events, expect_alerts=1)
        assert result.passed is True
        assert len(result.alerts) == 1
        assert result.events_processed == 1
        assert len(result.mismatches) == 0

    def test_correlation_rule_object(self) -> None:
        rule = parse_rule(SINGLE_RULE_YAML)
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY, "/etc/passwd", ts)]
        result = run_test_rule(rule, given=events, expect_alerts=1)
        assert result.passed is True
        assert len(result.alerts) == 1

    def test_file_path(self, tmp_path) -> None:
        rule_file = tmp_path / "rule.yaml"
        rule_file.write_text(SINGLE_RULE_YAML)
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY, "/etc/passwd", ts)]
        result = run_test_rule(str(rule_file), given=events, expect_alerts=1)
        assert result.passed is True

    def test_expect_alerts_mismatch(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.ALLOW, "test", ts)]
        result = run_test_rule(SINGLE_RULE_YAML, given=events, expect_alerts=1)
        assert result.passed is False
        assert len(result.mismatches) == 1
        assert "expected 1 alerts, got 0" in result.mismatches[0]

    def test_expect_severity(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY, "/etc/passwd", ts)]
        result = run_test_rule(SINGLE_RULE_YAML, given=events, expect_severity=RuleSeverity.LOW)
        assert result.passed is False
        assert "expected severity 'low'" in result.mismatches[0]

    def test_expect_rule_name(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY, "/etc/passwd", ts)]
        result = run_test_rule(SINGLE_RULE_YAML, given=events, expect_rule_name="Wrong Name")
        assert result.passed is False
        assert "expected rule name 'Wrong Name'" in result.mismatches[0]

    def test_no_events_expect_zero(self) -> None:
        result = run_test_rule(SINGLE_RULE_YAML, given=[], expect_alerts=0)
        assert result.passed is True
        assert len(result.alerts) == 0
        assert result.events_processed == 0

    def test_multiple_mismatches(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY, "/etc/passwd", ts)]
        result = run_test_rule(
            SINGLE_RULE_YAML,
            given=events,
            expect_alerts=2,
            expect_severity=RuleSeverity.LOW,
            expect_rule_name="Wrong",
        )
        assert result.passed is False
        assert len(result.mismatches) >= 2

    def test_severity_passes_when_correct(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        events = [_make_event(EventSourceType.RECEIPT, "file", NormalizedVerdict.DENY, "/etc/passwd", ts)]
        result = run_test_rule(SINGLE_RULE_YAML, given=events, expect_severity=RuleSeverity.CRITICAL)
        assert result.passed is True
