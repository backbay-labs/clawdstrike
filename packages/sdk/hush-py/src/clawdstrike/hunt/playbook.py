"""Hunt Playbook — composable builder for hunt workflows.

Provides an immutable builder that chains hunt, correlate, enrich,
deduplicate, and report generation steps.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from clawdstrike.hunt.correlate import correlate
from clawdstrike.hunt.duration import parse_human_duration
from clawdstrike.hunt.ioc import IocDatabase
from clawdstrike.hunt.local import hunt
from clawdstrike.hunt.report import build_report, collect_evidence, sign_report
from clawdstrike.hunt.types import (
    Alert,
    CorrelationRule,
    HuntReport,
    IocMatch,
    NormalizedVerdict,
    TimelineEvent,
)


@dataclass(frozen=True)
class PlaybookResult:
    """Result of a playbook execution."""

    events: tuple[TimelineEvent, ...]
    alerts: tuple[Alert, ...]
    ioc_matches: tuple[IocMatch, ...]
    report: HuntReport | None = None


def _deduplicate_alerts(alerts: list[Alert], window: timedelta) -> list[Alert]:
    """Remove alerts with the same rule_name within the dedup window."""
    seen: dict[str, datetime] = {}
    result: list[Alert] = []
    for alert in alerts:
        key = alert.rule_name
        last_seen = seen.get(key)
        if last_seen is not None and (alert.triggered_at - last_seen) < window:
            continue
        seen[key] = alert.triggered_at
        result.append(alert)
    return result


class Playbook:
    """Immutable builder for composing hunt workflows."""

    def __init__(
        self,
        *,
        start: datetime | str | None = None,
        verdict_filter: NormalizedVerdict | None = None,
        rules: tuple[CorrelationRule, ...] = (),
        ioc_db: IocDatabase | None = None,
        deduplicate_window: timedelta | None = None,
        report_title: str | None = None,
        sign_key: str | None = None,
        hunt_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self._start = start
        self._verdict_filter = verdict_filter
        self._rules = rules
        self._ioc_db = ioc_db
        self._deduplicate_window = deduplicate_window
        self._report_title = report_title
        self._sign_key = sign_key
        self._hunt_kwargs: dict[str, Any] = hunt_kwargs or {}

    def _copy(self, **overrides: Any) -> Playbook:
        base = {
            "start": self._start,
            "verdict_filter": self._verdict_filter,
            "rules": self._rules,
            "ioc_db": self._ioc_db,
            "deduplicate_window": self._deduplicate_window,
            "report_title": self._report_title,
            "sign_key": self._sign_key,
            "hunt_kwargs": self._hunt_kwargs,
        }
        base.update(overrides)
        return Playbook(**base)

    @classmethod
    def create(cls) -> Playbook:
        return cls()

    def since(self, time_range: datetime | str) -> Playbook:
        return self._copy(start=time_range)

    def filter(self, verdict: NormalizedVerdict) -> Playbook:
        return self._copy(verdict_filter=verdict)

    def correlate(self, rules: list[CorrelationRule]) -> Playbook:
        return self._copy(rules=tuple(rules))

    def enrich(self, ioc_db: IocDatabase) -> Playbook:
        return self._copy(ioc_db=ioc_db)

    def deduplicate(self, window: timedelta | str) -> Playbook:
        if isinstance(window, str):
            parsed = parse_human_duration(window)
            if parsed is None:
                parsed = timedelta(0)
            return self._copy(deduplicate_window=parsed)
        return self._copy(deduplicate_window=window)

    def report(self, title: str) -> Playbook:
        return self._copy(report_title=title)

    def sign(self, key_hex: str) -> Playbook:
        return self._copy(sign_key=key_hex)

    def run(self) -> PlaybookResult:
        """Execute the playbook pipeline and return results."""
        # 1. Hunt events
        events = hunt(start=self._start, **self._hunt_kwargs)

        # 2. Filter by verdict
        if self._verdict_filter is not None:
            events = [e for e in events if e.verdict == self._verdict_filter]

        # 3. Correlate
        alerts: list[Alert] = []
        if self._rules:
            alerts = correlate(list(self._rules), events)

        # 4. IOC enrichment
        ioc_matches: list[IocMatch] = []
        if self._ioc_db is not None:
            ioc_matches = self._ioc_db.match_events(events)

        # 5. Deduplicate
        if self._deduplicate_window is not None and self._deduplicate_window > timedelta(0):
            alerts = _deduplicate_alerts(alerts, self._deduplicate_window)

        # 6. Build report
        hunt_report: HuntReport | None = None
        if self._report_title is not None:
            evidence = collect_evidence(*alerts, events, ioc_matches)
            if evidence:
                hunt_report = build_report(self._report_title, evidence)
                # 7. Sign
                if self._sign_key is not None and hunt_report is not None:
                    hunt_report = sign_report(hunt_report, self._sign_key)

        return PlaybookResult(
            events=tuple(events),
            alerts=tuple(alerts),
            ioc_matches=tuple(ioc_matches),
            report=hunt_report,
        )

    def to_dict(self) -> dict[str, Any]:
        start_val = self._start
        if isinstance(start_val, datetime):
            start_val = start_val.isoformat()
        return {
            "start": start_val,
            "verdict_filter": self._verdict_filter.value if self._verdict_filter else None,
            "rules": [r.name for r in self._rules],
            "deduplicate_window": self._deduplicate_window.total_seconds() if self._deduplicate_window else None,
            "report_title": self._report_title,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Playbook:
        return cls(
            start=data.get("start"),
            verdict_filter=NormalizedVerdict(data["verdict_filter"]) if data.get("verdict_filter") else None,
            deduplicate_window=timedelta(seconds=data["deduplicate_window"]) if data.get("deduplicate_window") else None,
            report_title=data.get("report_title"),
        )


__all__ = ["Playbook", "PlaybookResult"]
