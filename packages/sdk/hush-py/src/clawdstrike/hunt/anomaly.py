"""Anomaly scoring for hunt timeline events."""

from __future__ import annotations

from dataclasses import dataclass, field

from clawdstrike.hunt.types import TimelineEvent


@dataclass(frozen=True)
class ScoredEvent:
    """A timeline event annotated with an anomaly score."""

    event: TimelineEvent
    anomaly_score: float
    feature_scores: dict[str, float]


@dataclass
class BaselineData:
    """Raw frequency data for building baselines."""

    total_events: int = 0
    source_counts: dict[str, int] = field(default_factory=dict)
    kind_counts: dict[str, int] = field(default_factory=dict)
    verdict_counts: dict[str, int] = field(default_factory=dict)
    action_type_counts: dict[str, int] = field(default_factory=dict)
    process_counts: dict[str, int] = field(default_factory=dict)
    namespace_counts: dict[str, int] = field(default_factory=dict)
    hour_of_day_counts: dict[int, int] = field(default_factory=dict)


class Baseline:
    """Statistical baseline for anomaly detection."""

    def __init__(self, data: BaselineData) -> None:
        self._data = data

    @staticmethod
    def build(events: list[TimelineEvent]) -> Baseline:
        """Build a baseline from a list of historical events."""
        data = BaselineData(total_events=len(events))
        for event in events:
            _increment(data.source_counts, event.source.value)
            _increment(data.kind_counts, event.kind.value)
            _increment(data.verdict_counts, event.verdict.value)
            if event.action_type:
                _increment(data.action_type_counts, event.action_type)
            if event.process:
                _increment(data.process_counts, event.process)
            if event.namespace:
                _increment(data.namespace_counts, event.namespace)
            hour = event.timestamp.hour
            _increment_int(data.hour_of_day_counts, hour)
        return Baseline(data)

    def score(self, event: TimelineEvent) -> float:
        """Return the anomaly score for a single event."""
        return self.score_detailed(event).anomaly_score

    def score_detailed(self, event: TimelineEvent) -> ScoredEvent:
        """Return a detailed scored event with per-feature breakdown."""
        total = self._data.total_events
        if total == 0:
            return ScoredEvent(event=event, anomaly_score=1.0, feature_scores={})

        feature_scores: dict[str, float] = {}
        feature_scores["source"] = 1 - self._data.source_counts.get(event.source.value, 0) / total
        feature_scores["kind"] = 1 - self._data.kind_counts.get(event.kind.value, 0) / total
        feature_scores["verdict"] = 1 - self._data.verdict_counts.get(event.verdict.value, 0) / total

        if event.action_type:
            feature_scores["action_type"] = 1 - self._data.action_type_counts.get(event.action_type, 0) / total
        if event.process:
            feature_scores["process"] = 1 - self._data.process_counts.get(event.process, 0) / total
        if event.namespace:
            feature_scores["namespace"] = 1 - self._data.namespace_counts.get(event.namespace, 0) / total

        hour = event.timestamp.hour
        feature_scores["hour_of_day"] = 1 - self._data.hour_of_day_counts.get(hour, 0) / total

        values = list(feature_scores.values())
        anomaly_score = sum(values) / len(values) if values else 1.0

        return ScoredEvent(event=event, anomaly_score=anomaly_score, feature_scores=feature_scores)

    def to_json(self) -> dict:
        """Serialize baseline data to a JSON-compatible dict."""
        return {
            "total_events": self._data.total_events,
            "source_counts": dict(self._data.source_counts),
            "kind_counts": dict(self._data.kind_counts),
            "verdict_counts": dict(self._data.verdict_counts),
            "action_type_counts": dict(self._data.action_type_counts),
            "process_counts": dict(self._data.process_counts),
            "namespace_counts": dict(self._data.namespace_counts),
            "hour_of_day_counts": {str(k): v for k, v in self._data.hour_of_day_counts.items()},
        }

    @staticmethod
    def from_json(data: dict) -> Baseline:
        """Deserialize a baseline from a JSON-compatible dict."""
        bd = BaselineData(
            total_events=data["total_events"],
            source_counts=data.get("source_counts", {}),
            kind_counts=data.get("kind_counts", {}),
            verdict_counts=data.get("verdict_counts", {}),
            action_type_counts=data.get("action_type_counts", {}),
            process_counts=data.get("process_counts", {}),
            namespace_counts=data.get("namespace_counts", {}),
            hour_of_day_counts={int(k): v for k, v in data.get("hour_of_day_counts", {}).items()},
        )
        return Baseline(bd)


def score_anomalies(
    events: list[TimelineEvent],
    baseline: Baseline,
    threshold: float = 0.5,
) -> list[ScoredEvent]:
    """Score events and return those above the threshold, sorted descending."""
    scored = [baseline.score_detailed(e) for e in events]
    filtered = [s for s in scored if s.anomaly_score >= threshold]
    filtered.sort(key=lambda s: s.anomaly_score, reverse=True)
    return filtered


def _increment(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def _increment_int(counts: dict[int, int], key: int) -> None:
    counts[key] = counts.get(key, 0) + 1


__all__ = [
    "ScoredEvent",
    "BaselineData",
    "Baseline",
    "score_anomalies",
]
