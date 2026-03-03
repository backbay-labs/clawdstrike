"""Envelope parsing and timeline merging.

Port of ``hunt-query/src/timeline.rs``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from clawdstrike.hunt.types import (
    EventSourceType,
    NormalizedVerdict,
    TimelineEvent,
    TimelineEventKind,
)


def parse_envelope(envelope: dict[str, Any]) -> TimelineEvent | None:
    """Parse a spine envelope dict into a :class:`TimelineEvent`.

    Dispatches on ``fact.schema`` to determine the event source.
    Returns ``None`` for unrecognised or malformed envelopes.
    """
    fact = envelope.get("fact")
    if not isinstance(fact, dict):
        return None

    schema = fact.get("schema")
    if not isinstance(schema, str):
        return None

    issued_at = envelope.get("issued_at")
    if not isinstance(issued_at, str):
        return None

    timestamp = _parse_rfc3339(issued_at)
    if timestamp is None:
        return None

    if schema == "clawdstrike.sdr.fact.tetragon_event.v1":
        return _parse_tetragon(fact, timestamp, envelope)
    elif schema == "clawdstrike.sdr.fact.hubble_flow.v1":
        return _parse_hubble(fact, timestamp, envelope)
    elif schema.startswith("clawdstrike.sdr.fact.receipt"):
        return _parse_receipt(fact, timestamp, envelope)
    elif schema.startswith("clawdstrike.sdr.fact.scan"):
        return _parse_scan(fact, timestamp, envelope)
    else:
        return None


def merge_timeline(events: list[TimelineEvent]) -> list[TimelineEvent]:
    """Sort events by timestamp ascending."""
    return sorted(events, key=lambda e: e.timestamp)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_rfc3339(s: str) -> datetime | None:
    """Parse an RFC 3339 / ISO 8601 timestamp string."""
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def _parse_tetragon(
    fact: dict[str, Any],
    timestamp: datetime,
    raw: dict[str, Any],
) -> TimelineEvent | None:
    event_type = fact.get("event_type", "unknown")
    process_obj = fact.get("process") or {}
    binary = process_obj.get("binary") if isinstance(process_obj, dict) else None
    severity = fact.get("severity") if isinstance(fact.get("severity"), str) else None
    pod_obj = process_obj.get("pod") or {} if isinstance(process_obj, dict) else {}
    ns = pod_obj.get("namespace") if isinstance(pod_obj, dict) else None
    pod_name = pod_obj.get("name") if isinstance(pod_obj, dict) else None

    kind_map = {
        "PROCESS_EXEC": TimelineEventKind.PROCESS_EXEC,
        "PROCESS_EXIT": TimelineEventKind.PROCESS_EXIT,
        "PROCESS_KPROBE": TimelineEventKind.PROCESS_KPROBE,
    }
    kind = kind_map.get(event_type, TimelineEventKind.PROCESS_EXEC)

    summary = f"{event_type.lower()} {binary or '?'}"

    return TimelineEvent(
        timestamp=timestamp,
        source=EventSourceType.TETRAGON,
        kind=kind,
        verdict=NormalizedVerdict.NONE,
        summary=summary,
        severity=severity,
        process=binary,
        namespace=ns,
        pod=pod_name,
        action_type="process",
        raw=raw,
    )


def _parse_hubble(
    fact: dict[str, Any],
    timestamp: datetime,
    raw: dict[str, Any],
) -> TimelineEvent | None:
    verdict_str = fact.get("verdict", "UNKNOWN")
    direction = fact.get("traffic_direction", "unknown")
    flow_summary = fact.get("summary", "network flow")

    verdict_map = {
        "FORWARDED": NormalizedVerdict.FORWARDED,
        "DROPPED": NormalizedVerdict.DROPPED,
    }
    verdict = verdict_map.get(verdict_str, NormalizedVerdict.NONE)

    source_obj = fact.get("source") or {}
    ns = source_obj.get("namespace") if isinstance(source_obj, dict) else None
    pod_name = source_obj.get("pod_name") if isinstance(source_obj, dict) else None

    summary = f"{direction.lower()} {flow_summary}"

    direction_action = {
        "EGRESS": "egress",
        "INGRESS": "ingress",
    }
    action = direction_action.get(direction, "network")

    return TimelineEvent(
        timestamp=timestamp,
        source=EventSourceType.HUBBLE,
        kind=TimelineEventKind.NETWORK_FLOW,
        verdict=verdict,
        summary=summary,
        namespace=ns,
        pod=pod_name,
        action_type=action,
        raw=raw,
    )


def _parse_receipt(
    fact: dict[str, Any],
    timestamp: datetime,
    raw: dict[str, Any],
) -> TimelineEvent | None:
    decision = fact.get("decision", "unknown")
    guard_name = fact.get("guard", "unknown")
    action = fact.get("action_type")
    severity = fact.get("severity") if isinstance(fact.get("severity"), str) else None

    source_obj = fact.get("source") or {}
    ns = source_obj.get("namespace") if isinstance(source_obj, dict) else None
    pod_name = None
    if isinstance(source_obj, dict):
        pod_name = source_obj.get("pod_name") or source_obj.get("pod")

    decision_lower = decision.lower() if isinstance(decision, str) else ""
    verdict_map: dict[str, NormalizedVerdict] = {
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
    }
    verdict = verdict_map.get(decision_lower, NormalizedVerdict.NONE)

    summary = f"{guard_name} decision={decision}"

    return TimelineEvent(
        timestamp=timestamp,
        source=EventSourceType.RECEIPT,
        kind=TimelineEventKind.GUARD_DECISION,
        verdict=verdict,
        summary=summary,
        severity=severity,
        namespace=ns,
        pod=pod_name,
        action_type=action,
        raw=raw,
    )


def _parse_scan(
    fact: dict[str, Any],
    timestamp: datetime,
    raw: dict[str, Any],
) -> TimelineEvent | None:
    scan_type = fact.get("scan_type", "unknown")
    status = fact.get("status", "unknown")
    severity = fact.get("severity") if isinstance(fact.get("severity"), str) else None

    status_lower = status.lower() if isinstance(status, str) else ""
    verdict_map: dict[str, NormalizedVerdict] = {
        "pass": NormalizedVerdict.ALLOW,
        "passed": NormalizedVerdict.ALLOW,
        "clean": NormalizedVerdict.ALLOW,
        "fail": NormalizedVerdict.DENY,
        "failed": NormalizedVerdict.DENY,
        "dirty": NormalizedVerdict.DENY,
        "warn": NormalizedVerdict.WARN,
        "warning": NormalizedVerdict.WARN,
    }
    verdict = verdict_map.get(status_lower, NormalizedVerdict.NONE)

    summary = f"scan {scan_type} status={status}"

    return TimelineEvent(
        timestamp=timestamp,
        source=EventSourceType.SCAN,
        kind=TimelineEventKind.SCAN_RESULT,
        verdict=verdict,
        summary=summary,
        severity=severity,
        action_type="scan",
        raw=raw,
    )
