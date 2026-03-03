"""Tests for clawdstrike.hunt.playbook — hunt playbook builder."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from clawdstrike.hunt.correlate import parse_rule
from clawdstrike.hunt.ioc import IocDatabase
from clawdstrike.hunt.playbook import Playbook, PlaybookResult
from clawdstrike.hunt.types import (
    CorrelationRule,
    EventSourceType,
    IocEntry,
    IocType,
    NormalizedVerdict,
    TimelineEvent,
    TimelineEventKind,
)


SINGLE_CONDITION_RULE_YAML = """\
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
    summary: str = "test event",
    verdict: NormalizedVerdict = NormalizedVerdict.ALLOW,
    action_type: str = "file",
    ts: datetime | None = None,
) -> TimelineEvent:
    return TimelineEvent(
        timestamp=ts or datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        source=EventSourceType.RECEIPT,
        kind=TimelineEventKind.GUARD_DECISION,
        verdict=verdict,
        summary=summary,
        action_type=action_type,
    )


def _rule() -> CorrelationRule:
    return parse_rule(SINGLE_CONDITION_RULE_YAML)


class TestPlaybookBuilder:
    def test_create_returns_instance(self) -> None:
        pb = Playbook.create()
        assert isinstance(pb, Playbook)

    def test_builder_chaining(self) -> None:
        pb = (
            Playbook.create()
            .since("1h")
            .filter(NormalizedVerdict.DENY)
            .correlate([_rule()])
            .deduplicate(timedelta(seconds=5))
            .report("Test Report")
            .sign("aabbccdd")
        )
        assert isinstance(pb, Playbook)

    def test_immutability(self) -> None:
        pb1 = Playbook.create()
        d1 = pb1.to_dict()
        pb2 = pb1.since("1h")
        d2 = pb1.to_dict()
        assert d1 == d2
        assert pb1 is not pb2


class TestPlaybookRun:
    @patch("clawdstrike.hunt.playbook.hunt")
    def test_run_with_no_rules_returns_just_events(self, mock_hunt) -> None:
        events = [_make_event()]
        mock_hunt.return_value = events

        result = Playbook.create().since("1h").run()

        assert len(result.events) == 1
        assert len(result.alerts) == 0
        assert len(result.ioc_matches) == 0
        assert result.report is None

    @patch("clawdstrike.hunt.playbook.hunt")
    def test_run_with_rules_returns_alerts(self, mock_hunt) -> None:
        events = [_make_event(verdict=NormalizedVerdict.DENY, summary="/etc/passwd")]
        mock_hunt.return_value = events

        result = Playbook.create().since("1h").correlate([_rule()]).run()

        assert len(result.alerts) == 1
        assert result.alerts[0].rule_name == "Forbidden Path Access"

    @patch("clawdstrike.hunt.playbook.hunt")
    def test_run_with_ioc_db(self, mock_hunt) -> None:
        events = [_make_event(summary="evil.com download")]
        mock_hunt.return_value = events

        db = IocDatabase()
        db.add_entry(IocEntry(
            indicator="evil.com",
            ioc_type=IocType.DOMAIN,
            description="malicious domain",
        ))

        result = Playbook.create().since("1h").enrich(db).run()

        assert len(result.ioc_matches) == 1

    @patch("clawdstrike.hunt.playbook.hunt")
    def test_deduplication(self, mock_hunt) -> None:
        ts1 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2025, 6, 15, 12, 0, 1, tzinfo=timezone.utc)
        ts3 = datetime(2025, 6, 15, 12, 0, 10, tzinfo=timezone.utc)
        events = [
            _make_event(verdict=NormalizedVerdict.DENY, summary="/etc/passwd", ts=ts1),
            _make_event(verdict=NormalizedVerdict.DENY, summary="/etc/shadow", ts=ts2),
            _make_event(verdict=NormalizedVerdict.DENY, summary="/etc/hosts", ts=ts3),
        ]
        mock_hunt.return_value = events

        result = (
            Playbook.create()
            .since("1h")
            .correlate([_rule()])
            .deduplicate(timedelta(seconds=5))
            .run()
        )

        # ts1 and ts2 within 5s, ts3 outside
        assert len(result.alerts) == 2

    @patch("clawdstrike.hunt.playbook.hunt")
    def test_report_generation(self, mock_hunt) -> None:
        events = [_make_event(verdict=NormalizedVerdict.DENY, summary="/etc/passwd")]
        mock_hunt.return_value = events

        result = (
            Playbook.create()
            .since("1h")
            .correlate([_rule()])
            .report("Security Hunt Report")
            .run()
        )

        assert result.report is not None
        assert result.report.title == "Security Hunt Report"
        assert result.report.merkle_root

    @patch("clawdstrike.hunt.playbook.hunt")
    def test_empty_events(self, mock_hunt) -> None:
        mock_hunt.return_value = []

        result = Playbook.create().since("1h").correlate([_rule()]).run()

        assert len(result.events) == 0
        assert len(result.alerts) == 0
        assert result.report is None

    @patch("clawdstrike.hunt.playbook.hunt")
    def test_verdict_filter(self, mock_hunt) -> None:
        events = [
            _make_event(verdict=NormalizedVerdict.ALLOW, summary="read /tmp/test"),
            _make_event(verdict=NormalizedVerdict.DENY, summary="/etc/passwd"),
        ]
        mock_hunt.return_value = events

        result = (
            Playbook.create()
            .since("1h")
            .filter(NormalizedVerdict.DENY)
            .correlate([_rule()])
            .run()
        )

        assert len(result.events) == 1
        assert result.events[0].verdict == NormalizedVerdict.DENY
        assert len(result.alerts) == 1


class TestPlaybookSerialization:
    def test_to_dict_from_dict_roundtrip(self) -> None:
        pb = (
            Playbook.create()
            .since("1h")
            .filter(NormalizedVerdict.DENY)
            .deduplicate(timedelta(seconds=5))
            .report("Test Report")
        )

        d = pb.to_dict()
        restored = Playbook.from_dict(d)
        d2 = restored.to_dict()

        assert d["start"] == d2["start"]
        assert d["verdict_filter"] == d2["verdict_filter"]
        assert d["deduplicate_window"] == d2["deduplicate_window"]
        assert d["report_title"] == d2["report_title"]

    def test_deduplicate_with_string_duration(self) -> None:
        pb = Playbook.create().deduplicate("5s")
        d = pb.to_dict()
        assert d["deduplicate_window"] == 5.0


class TestPlaybookResult:
    def test_frozen_dataclass(self) -> None:
        result = PlaybookResult(events=(), alerts=(), ioc_matches=())
        assert result.events == ()
        assert result.alerts == ()
        assert result.report is None

        with pytest.raises(AttributeError):
            result.events = ()  # type: ignore[misc]
