"""Tests for clawdstrike.hunt.dataframe — DataFrame/notebook integration."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from clawdstrike.hunt.dataframe import (
    _alert_to_dict,
    _event_to_dict,
    alerts_to_dataframe,
    display_timeline,
    to_dataframe,
    to_polars,
)
from clawdstrike.hunt.types import (
    Alert,
    EventSourceType,
    NormalizedVerdict,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
)


def _make_event(
    summary: str = "test event",
    process: str | None = None,
) -> TimelineEvent:
    return TimelineEvent(
        timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        source=EventSourceType.RECEIPT,
        kind=TimelineEventKind.GUARD_DECISION,
        verdict=NormalizedVerdict.DENY,
        summary=summary,
        process=process,
    )


def _make_alert() -> Alert:
    return Alert(
        rule_name="test-rule",
        severity=RuleSeverity.HIGH,
        title="Test Alert",
        triggered_at=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        evidence=(_make_event(),),
        description="A test alert",
    )


class TestEventToDict:
    def test_converts_event_fields(self) -> None:
        event = _make_event(summary="hello", process="curl")
        d = _event_to_dict(event)
        assert d["source"] == "receipt"
        assert d["kind"] == "guard_decision"
        assert d["verdict"] == "deny"
        assert d["summary"] == "hello"
        assert d["process"] == "curl"
        assert d["namespace"] is None
        assert d["pod"] is None

    def test_timestamp_is_iso_string(self) -> None:
        event = _make_event()
        d = _event_to_dict(event)
        assert "2025-06-15" in d["timestamp"]


class TestAlertToDict:
    def test_converts_alert_fields(self) -> None:
        alert = _make_alert()
        d = _alert_to_dict(alert)
        assert d["rule_name"] == "test-rule"
        assert d["severity"] == "high"
        assert d["title"] == "Test Alert"
        assert d["evidence_count"] == 1
        assert "2025-06-15" in d["triggered_at"]


class TestToDataframe:
    def test_requires_pandas(self) -> None:
        pytest.importorskip("pandas")
        events = [_make_event(), _make_event(summary="second")]
        df = to_dataframe(events)
        assert len(df) == 2
        assert "source" in df.columns
        assert "verdict" in df.columns

    def test_empty_events(self) -> None:
        pytest.importorskip("pandas")
        df = to_dataframe([])
        assert len(df) == 0


class TestToPolars:
    def test_requires_polars(self) -> None:
        pytest.importorskip("polars")
        events = [_make_event()]
        df = to_polars(events)
        assert df.shape[0] == 1
        assert "source" in df.columns


class TestAlertsToDataframe:
    def test_converts_alerts(self) -> None:
        pytest.importorskip("pandas")
        alerts = [_make_alert()]
        df = alerts_to_dataframe(alerts)
        assert len(df) == 1
        assert "rule_name" in df.columns


class TestDisplayTimeline:
    def test_calls_ipython_display(self) -> None:
        mock_display = MagicMock()
        mock_html = MagicMock()
        with patch.dict("sys.modules", {
            "IPython": MagicMock(),
            "IPython.display": MagicMock(display=mock_display, HTML=mock_html),
        }):
            events = [_make_event()]
            display_timeline(events)
            mock_display.assert_called_once()
            mock_html.assert_called_once()
            html_arg = mock_html.call_args[0][0]
            assert "<table>" in html_arg
            assert "test event" in html_arg
