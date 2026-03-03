"""Event source helpers and query matching.

Port of ``hunt-query/src/query.rs``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from clawdstrike.hunt.types import (
    EventSourceType,
    HuntQuery,
    NormalizedVerdict,
    TimelineEvent,
)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)

# ---------------------------------------------------------------------------
# EventSource helpers
# ---------------------------------------------------------------------------

_SOURCE_ALIASES: dict[str, EventSourceType] = {
    "tetragon": EventSourceType.TETRAGON,
    "hubble": EventSourceType.HUBBLE,
    "receipt": EventSourceType.RECEIPT,
    "receipts": EventSourceType.RECEIPT,
    "scan": EventSourceType.SCAN,
    "scans": EventSourceType.SCAN,
}


def parse_event_source(s: str) -> EventSourceType | None:
    """Parse a single source string (case-insensitive)."""
    return _SOURCE_ALIASES.get(s.strip().lower())


def parse_event_source_list(s: str) -> list[EventSourceType]:
    """Parse a comma-separated list of sources."""
    results: list[EventSourceType] = []
    for part in s.split(","):
        src = parse_event_source(part.strip())
        if src is not None:
            results.append(src)
    return results


_STREAM_NAMES: dict[EventSourceType, str] = {
    EventSourceType.TETRAGON: "CLAWDSTRIKE_TETRAGON",
    EventSourceType.HUBBLE: "CLAWDSTRIKE_HUBBLE",
    EventSourceType.RECEIPT: "CLAWDSTRIKE_RECEIPTS",
    EventSourceType.SCAN: "CLAWDSTRIKE_SCANS",
}


def stream_name(source: EventSourceType) -> str:
    """JetStream stream name for the given source."""
    return _STREAM_NAMES[source]


_SUBJECT_FILTERS: dict[EventSourceType, str] = {
    EventSourceType.TETRAGON: "clawdstrike.sdr.fact.tetragon_event.>",
    EventSourceType.HUBBLE: "clawdstrike.sdr.fact.hubble_flow.>",
    EventSourceType.RECEIPT: "clawdstrike.sdr.fact.receipt.>",
    EventSourceType.SCAN: "clawdstrike.sdr.fact.scan.>",
}


def subject_filter(source: EventSourceType) -> str:
    """NATS subject filter pattern for the given source."""
    return _SUBJECT_FILTERS[source]


def all_event_sources() -> list[EventSourceType]:
    """All known event sources."""
    return [
        EventSourceType.TETRAGON,
        EventSourceType.HUBBLE,
        EventSourceType.RECEIPT,
        EventSourceType.SCAN,
    ]


# ---------------------------------------------------------------------------
# QueryVerdict parsing
# ---------------------------------------------------------------------------

_VERDICT_ALIASES: dict[str, NormalizedVerdict] = {
    "allow": NormalizedVerdict.ALLOW,
    "allowed": NormalizedVerdict.ALLOW,
    "pass": NormalizedVerdict.ALLOW,
    "passed": NormalizedVerdict.ALLOW,
    "deny": NormalizedVerdict.DENY,
    "denied": NormalizedVerdict.DENY,
    "block": NormalizedVerdict.DENY,
    "blocked": NormalizedVerdict.DENY,
    "warn": NormalizedVerdict.WARN,
    "warned": NormalizedVerdict.WARN,
    "warning": NormalizedVerdict.WARN,
    "forwarded": NormalizedVerdict.FORWARDED,
    "forward": NormalizedVerdict.FORWARDED,
    "dropped": NormalizedVerdict.DROPPED,
    "drop": NormalizedVerdict.DROPPED,
}


def parse_query_verdict(s: str) -> NormalizedVerdict | None:
    """Parse a verdict string (case-insensitive, supports aliases)."""
    return _VERDICT_ALIASES.get(s.strip().lower())


# ---------------------------------------------------------------------------
# Query matching
# ---------------------------------------------------------------------------

def effective_sources(query: HuntQuery) -> list[EventSourceType]:
    """Return the effective source list: configured or all, deduplicated."""
    if not query.sources:
        return all_event_sources()
    seen: set[EventSourceType] = set()
    deduped: list[EventSourceType] = []
    for src in query.sources:
        if src not in seen:
            seen.add(src)
            deduped.append(src)
    return deduped


def matches_query(query: HuntQuery, event: TimelineEvent) -> bool:
    """Return ``True`` if the event matches ALL active predicates in the query."""
    # Source filter
    if query.sources and event.source not in query.sources:
        return False

    # Verdict filter
    if query.verdict is not None:
        if event.verdict != query.verdict:
            return False

    # Time range
    if query.start is not None and _as_utc(event.timestamp) < _as_utc(query.start):
        return False
    if query.end is not None and _as_utc(event.timestamp) > _as_utc(query.end):
        return False

    # Action type (case-insensitive exact)
    if query.action_type is not None:
        if event.action_type is None:
            return False
        if event.action_type.lower() != query.action_type.lower():
            return False

    # Namespace (case-insensitive exact)
    if query.namespace is not None:
        if event.namespace is None:
            return False
        if event.namespace.lower() != query.namespace.lower():
            return False

    # Process (case-insensitive substring)
    if query.process is not None:
        if event.process is None:
            return False
        if query.process.lower() not in event.process.lower():
            return False

    # Pod (case-insensitive substring)
    if query.pod is not None:
        if event.pod is None:
            return False
        if query.pod.lower() not in event.pod.lower():
            return False

    # Entity (case-insensitive substring on pod OR namespace)
    if query.entity is not None:
        entity_lower = query.entity.lower()
        pod_match = event.pod is not None and entity_lower in event.pod.lower()
        ns_match = event.namespace is not None and entity_lower in event.namespace.lower()
        if not pod_match and not ns_match:
            return False

    return True
