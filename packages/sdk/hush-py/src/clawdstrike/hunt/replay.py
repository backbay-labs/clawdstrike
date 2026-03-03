"""Event replay / retrohunt — re-evaluate rules against historical events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from clawdstrike.hunt.correlate import correlate, load_rules_from_files
from clawdstrike.hunt.ioc import IocDatabase
from clawdstrike.hunt.local import hunt
from clawdstrike.hunt.types import (
    Alert,
    CorrelationRule,
    EventSourceType,
    IocMatch,
    NormalizedVerdict,
)


@dataclass(frozen=True)
class ReplayResult:
    """Result of a replay / retrohunt operation."""

    alerts: tuple[Alert, ...]
    ioc_matches: tuple[IocMatch, ...]
    events_scanned: int
    time_range: tuple[datetime, datetime] | None
    rules_evaluated: int


def replay(
    *,
    rules: list[CorrelationRule] | list[str],
    ioc_db: IocDatabase | None = None,
    sources: tuple[EventSourceType, ...] = (),
    verdict: NormalizedVerdict | None = None,
    start: datetime | str | None = None,
    end: datetime | None = None,
    action_type: str | None = None,
    process: str | None = None,
    namespace: str | None = None,
    pod: str | None = None,
    entity: str | None = None,
    limit: int = 100,
    dirs: list[str] | None = None,
) -> ReplayResult:
    """Replay historical events against correlation rules and IOC database.

    *rules* may be a list of :class:`CorrelationRule` objects or file paths.
    """
    # Load rules if paths provided
    loaded_rules: list[CorrelationRule]
    if rules and isinstance(rules[0], str):
        loaded_rules = load_rules_from_files(list(rules))  # type: ignore[arg-type]
    else:
        loaded_rules = list(rules)  # type: ignore[arg-type]

    # Hunt events
    events = hunt(
        sources=sources,
        verdict=verdict,
        start=start,
        end=end,
        action_type=action_type,
        process=process,
        namespace=namespace,
        pod=pod,
        entity=entity,
        limit=limit,
        dirs=dirs,
    )

    # Correlate
    alerts = correlate(loaded_rules, events)

    # Optional IOC matching
    ioc_matches = ioc_db.match_events(events) if ioc_db is not None else []

    # Compute time range
    time_range: tuple[datetime, datetime] | None = None
    if events:
        timestamps = [e.timestamp for e in events]
        time_range = (min(timestamps), max(timestamps))

    return ReplayResult(
        alerts=tuple(alerts),
        ioc_matches=tuple(ioc_matches),
        events_scanned=len(events),
        time_range=time_range,
        rules_evaluated=len(loaded_rules),
    )


__all__ = [
    "ReplayResult",
    "replay",
]
