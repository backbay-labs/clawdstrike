"""Tests for clawdstrike.hunt.anomaly — anomaly scoring and baselines."""

from __future__ import annotations

from datetime import datetime, timezone

from clawdstrike.hunt.anomaly import (
    Baseline,
    score_anomalies,
)
from clawdstrike.hunt.types import (
    EventSourceType,
    NormalizedVerdict,
    TimelineEvent,
    TimelineEventKind,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    source: EventSourceType = EventSourceType.TETRAGON,
    kind: TimelineEventKind = TimelineEventKind.PROCESS_EXEC,
    verdict: NormalizedVerdict = NormalizedVerdict.ALLOW,
    timestamp: datetime | None = None,
    process: str | None = None,
    namespace: str | None = None,
    action_type: str | None = None,
) -> TimelineEvent:
    return TimelineEvent(
        timestamp=timestamp or datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        source=source,
        kind=kind,
        verdict=verdict,
        summary="test event",
        process=process,
        namespace=namespace,
        action_type=action_type,
    )


def _make_events(
    count: int,
    **kwargs,
) -> list[TimelineEvent]:
    return [_make_event(**kwargs) for _ in range(count)]


# ---------------------------------------------------------------------------
# Baseline.build
# ---------------------------------------------------------------------------


class TestBaselineBuild:
    def test_correct_counts(self) -> None:
        events = [
            _make_event(source=EventSourceType.TETRAGON),
            _make_event(source=EventSourceType.TETRAGON),
            _make_event(source=EventSourceType.HUBBLE),
        ]
        baseline = Baseline.build(events)
        data = baseline.to_json()
        assert data["total_events"] == 3
        assert data["source_counts"]["tetragon"] == 2
        assert data["source_counts"]["hubble"] == 1


# ---------------------------------------------------------------------------
# Baseline.score
# ---------------------------------------------------------------------------


class TestBaselineScore:
    def test_common_event_low_score(self) -> None:
        events = _make_events(10)
        baseline = Baseline.build(events)
        score = baseline.score(_make_event())
        assert score < 0.3

    def test_rare_event_high_score(self) -> None:
        events = _make_events(10)
        baseline = Baseline.build(events)
        rare = _make_event(
            source=EventSourceType.HUBBLE,
            kind=TimelineEventKind.NETWORK_FLOW,
            verdict=NormalizedVerdict.DENY,
        )
        score = baseline.score(rare)
        assert score > 0.5

    def test_unseen_event_near_1(self) -> None:
        events = _make_events(10)
        baseline = Baseline.build(events)
        unseen = _make_event(
            source=EventSourceType.SCAN,
            kind=TimelineEventKind.SCAN_RESULT,
            verdict=NormalizedVerdict.DENY,
            action_type="unknown_action",
            process="evil_process",
            namespace="rogue_ns",
            timestamp=datetime(2025, 6, 15, 3, 0, 0, tzinfo=timezone.utc),
        )
        score = baseline.score(unseen)
        assert score > 0.8


# ---------------------------------------------------------------------------
# Baseline.score_detailed
# ---------------------------------------------------------------------------


class TestBaselineScoreDetailed:
    def test_feature_breakdown(self) -> None:
        events = _make_events(5)
        baseline = Baseline.build(events)
        result = baseline.score_detailed(_make_event())
        assert "source" in result.feature_scores
        assert "kind" in result.feature_scores
        assert "verdict" in result.feature_scores
        assert "hour_of_day" in result.feature_scores
        assert 0 <= result.anomaly_score <= 1


# ---------------------------------------------------------------------------
# score_anomalies
# ---------------------------------------------------------------------------


class TestScoreAnomalies:
    def test_filters_by_threshold(self) -> None:
        baseline_events = _make_events(10)
        baseline = Baseline.build(baseline_events)
        test_events = [
            _make_event(),
            _make_event(
                source=EventSourceType.SCAN,
                kind=TimelineEventKind.SCAN_RESULT,
                verdict=NormalizedVerdict.DENY,
                timestamp=datetime(2025, 6, 15, 3, 0, 0, tzinfo=timezone.utc),
            ),
        ]
        result = score_anomalies(test_events, baseline, threshold=0.5)
        assert len(result) >= 1
        for s in result:
            assert s.anomaly_score >= 0.5

    def test_sorted_descending(self) -> None:
        baseline_events = _make_events(10)
        baseline = Baseline.build(baseline_events)
        test_events = [
            _make_event(),
            _make_event(
                source=EventSourceType.SCAN,
                kind=TimelineEventKind.SCAN_RESULT,
                verdict=NormalizedVerdict.DENY,
                timestamp=datetime(2025, 6, 15, 3, 0, 0, tzinfo=timezone.utc),
            ),
            _make_event(
                source=EventSourceType.HUBBLE,
                kind=TimelineEventKind.NETWORK_FLOW,
                verdict=NormalizedVerdict.WARN,
                timestamp=datetime(2025, 6, 15, 2, 0, 0, tzinfo=timezone.utc),
            ),
        ]
        result = score_anomalies(test_events, baseline, threshold=0)
        for i in range(1, len(result)):
            assert result[i - 1].anomaly_score >= result[i].anomaly_score

    def test_threshold_0_returns_all(self) -> None:
        baseline_events = _make_events(5)
        baseline = Baseline.build(baseline_events)
        test_events = _make_events(3)
        result = score_anomalies(test_events, baseline, threshold=0)
        assert len(result) == 3

    def test_threshold_1_returns_few_or_none(self) -> None:
        baseline_events = _make_events(10)
        baseline = Baseline.build(baseline_events)
        test_events = _make_events(5)
        result = score_anomalies(test_events, baseline, threshold=1.0)
        assert len(result) == 0


# ---------------------------------------------------------------------------
# Empty baseline
# ---------------------------------------------------------------------------


class TestEmptyBaseline:
    def test_score_is_1(self) -> None:
        baseline = Baseline.build([])
        score = baseline.score(_make_event())
        assert score == 1.0


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_roundtrip(self) -> None:
        events = [
            _make_event(source=EventSourceType.TETRAGON, process="curl"),
            _make_event(source=EventSourceType.HUBBLE, namespace="default"),
        ]
        baseline = Baseline.build(events)
        json_data = baseline.to_json()
        restored = Baseline.from_json(json_data)
        score1 = baseline.score(_make_event())
        score2 = restored.score(_make_event())
        assert score1 == score2


# ---------------------------------------------------------------------------
# hourOfDay feature
# ---------------------------------------------------------------------------


class TestHourOfDay:
    def test_includes_hour_of_day(self) -> None:
        events = _make_events(
            5,
            timestamp=datetime(2025, 6, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
        baseline = Baseline.build(events)
        night_event = _make_event(
            timestamp=datetime(2025, 6, 15, 3, 0, 0, tzinfo=timezone.utc),
        )
        result = baseline.score_detailed(night_event)
        assert result.feature_scores["hour_of_day"] == 1.0
