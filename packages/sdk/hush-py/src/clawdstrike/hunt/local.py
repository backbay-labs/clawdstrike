"""Local offline envelope loading from filesystem directories.

Port of ``hunt-query/src/local.rs``.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from clawdstrike.hunt.duration import parse_human_duration
from clawdstrike.hunt.query import matches_query
from clawdstrike.hunt.timeline import merge_timeline, parse_envelope
from clawdstrike.hunt.types import (
    EventSourceType,
    HuntQuery,
    NormalizedVerdict,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


def _normalize_utc(dt: datetime) -> datetime:
    """Normalize datetimes to timezone-aware UTC for safe comparisons."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def default_local_dirs() -> list[str]:
    """Return default directories to search for local envelopes.

    Only directories that actually exist are included.
    """
    home = Path.home()
    candidates = [
        home / ".clawdstrike" / "receipts",
        home / ".clawdstrike" / "scans",
        home / ".hush" / "receipts",
    ]
    return [str(d) for d in candidates if d.is_dir()]


def query_local_files(
    query: HuntQuery,
    search_dirs: list[str] | None = None,
) -> list[TimelineEvent]:
    """Query envelopes from local JSON/JSONL files.

    Reads all ``.json`` and ``.jsonl`` files from the given directories,
    parses envelopes, filters with the query predicates, merges by timestamp,
    and truncates to the newest ``query.limit`` events.

    If *search_dirs* is ``None``, defaults to :func:`default_local_dirs`.
    """
    dirs = search_dirs if search_dirs is not None else default_local_dirs()
    all_events: list[TimelineEvent] = []

    for dir_str in dirs:
        dir_path = Path(dir_str)
        if not dir_path.is_dir():
            logger.debug("skipping non-directory: %s", dir_path)
            continue

        try:
            entries = list(dir_path.iterdir())
        except OSError as exc:
            logger.warning("skipping unreadable directory %s: %s", dir_path, exc)
            continue

        for entry in entries:
            if not entry.is_file():
                continue

            suffix = entry.suffix.lower()
            if suffix == ".jsonl":
                try:
                    events = _read_jsonl_file(entry)
                except (OSError, json.JSONDecodeError, ValueError, UnicodeDecodeError):
                    logger.warning("skipping unreadable/invalid JSONL file %s", entry)
                    continue
            elif suffix == ".json":
                try:
                    events = _read_json_file(entry)
                except (OSError, json.JSONDecodeError, ValueError, UnicodeDecodeError):
                    logger.warning("skipping unreadable/invalid JSON file %s", entry)
                    continue
            else:
                continue

            for event in events:
                if matches_query(query, event):
                    all_events.append(event)

    merged = merge_timeline(all_events)
    _truncate_to_newest(merged, query.limit)
    return merged


def hunt(
    *,
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
) -> list[TimelineEvent]:
    """High-level convenience function for querying local events.

    Parses duration strings for *start* (e.g. ``"1h"``, ``"30m"``),
    applies defaults, builds a query, and calls :func:`query_local_files`.
    """
    start_dt: datetime | None = None
    if isinstance(start, str):
        td = parse_human_duration(start)
        if td is not None:
            start_dt = datetime.now(tz=timezone.utc) - td
    elif isinstance(start, datetime):
        start_dt = _normalize_utc(start)

    end_dt = _normalize_utc(end) if isinstance(end, datetime) else None

    query = HuntQuery(
        sources=sources,
        verdict=verdict,
        start=start_dt,
        end=end_dt,
        action_type=action_type,
        process=process,
        namespace=namespace,
        pod=pod,
        entity=entity,
        limit=limit,
    )

    return query_local_files(query, dirs)


def _truncate_to_newest(events: list[TimelineEvent], limit: int) -> None:
    """Truncate *in-place* keeping only the newest ``limit`` events."""
    if limit == 0:
        events.clear()
        return
    if len(events) > limit:
        del events[: len(events) - limit]


def _read_json_file(path: Path) -> list[TimelineEvent]:
    """Read a single JSON file as envelope(s)."""
    content = path.read_text(encoding="utf-8")
    value = json.loads(content)

    if isinstance(value, list):
        results: list[TimelineEvent] = []
        for item in value:
            if isinstance(item, dict):
                event = parse_envelope(item)
                if event is not None:
                    results.append(event)
        return results
    elif isinstance(value, dict):
        event = parse_envelope(value)
        return [event] if event is not None else []
    else:
        return []


def _read_jsonl_file(path: Path) -> list[TimelineEvent]:
    """Read a JSONL file (one JSON object per line)."""
    content = path.read_text(encoding="utf-8")
    events: list[TimelineEvent] = []

    for line in content.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue
        try:
            value = json.loads(trimmed)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(value, dict):
            event = parse_envelope(value)
            if event is not None:
                events.append(event)

    return events
