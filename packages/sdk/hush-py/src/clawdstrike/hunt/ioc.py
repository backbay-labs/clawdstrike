"""IOC (Indicator of Compromise) matching engine.

Port of ``hunt-correlate/src/ioc.rs``.
Supports loading from plain-text, CSV, and STIX 2.1 JSON bundles.
"""

from __future__ import annotations

import json
import re

from clawdstrike.hunt.errors import IocError
from clawdstrike.hunt.types import (
    IocEntry,
    IocMatch,
    IocType,
    TimelineEvent,
)

# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _is_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p:
            return False
        try:
            n = int(p)
        except ValueError:
            return False
        if n < 0 or n > 255:
            return False
        # Reject non-canonical representations (leading zeros, sign prefixes)
        if str(n) != p:
            return False
    return True


def detect_ioc_type(indicator: str) -> IocType | None:
    """Auto-detect the IOC type from the indicator string format.

    Returns ``None`` if the type cannot be determined.
    """
    trimmed = indicator.strip()
    if not trimmed:
        return None

    lower = trimmed.lower()

    # Hex hashes
    if len(lower) == 64 and _HEX_RE.match(lower):
        return IocType.SHA256
    if len(lower) == 40 and _HEX_RE.match(lower):
        return IocType.SHA1
    if len(lower) == 32 and _HEX_RE.match(lower):
        return IocType.MD5

    # URL
    if lower.startswith("http://") or lower.startswith("https://"):
        return IocType.URL

    # IPv4
    if _is_ipv4(trimmed):
        return IocType.IPV4

    # IPv6: contains colons and only hex digits / colons
    if ":" in trimmed and all(c in "0123456789abcdefABCDEF:" for c in trimmed):
        return IocType.IPV6

    # Domain: contains dot, no spaces, no slashes, no colons
    if "." in trimmed and " " not in trimmed and "/" not in trimmed and ":" not in trimmed:
        return IocType.DOMAIN

    return None


# ---------------------------------------------------------------------------
# Word-boundary matching
# ---------------------------------------------------------------------------


def _is_ioc_word_char(ch: str) -> bool:
    """IOC word character: alphanumeric, dot, or hyphen."""
    if len(ch) != 1:
        return False
    code = ord(ch)
    return (
        (ord("0") <= code <= ord("9"))
        or (ord("A") <= code <= ord("Z"))
        or (ord("a") <= code <= ord("z"))
        or ch == "."
        or ch == "-"
    )


def contains_word_bounded(haystack: str, needle: str) -> bool:
    """Check whether *needle* appears in *haystack* at word boundaries.

    Word characters for IOC matching are alphanumeric, ``'.'``, and ``'-'``.
    """
    if not needle:
        return False

    start = 0
    while True:
        pos = haystack.find(needle, start)
        if pos < 0:
            return False

        end_pos = pos + len(needle)

        left_ok = pos == 0 or not _is_ioc_word_char(haystack[pos - 1])
        right_ok = end_pos >= len(haystack) or not _is_ioc_word_char(haystack[end_pos])

        if left_ok and right_ok:
            return True

        # Advance past the first character of this match
        start = pos + 1


# ---------------------------------------------------------------------------
# CSV helpers
# ---------------------------------------------------------------------------


def _split_csv_fields(line: str) -> list[str]:
    """Split a CSV line handling double-quoted fields."""
    fields: list[str] = []
    current: list[str] = []
    in_quotes = False
    chars = iter(line)
    prev_quote = False

    for ch in chars:
        if in_quotes:
            if ch == '"':
                # Peek for escaped quote
                prev_quote = True
                in_quotes = False
            else:
                current.append(ch)
        elif prev_quote:
            prev_quote = False
            if ch == '"':
                current.append('"')
                in_quotes = True
            elif ch == ',':
                fields.append("".join(current).strip())
                current = []
            else:
                current.append(ch)
        elif ch == '"':
            in_quotes = True
        elif ch == ',':
            fields.append("".join(current).strip())
            current = []
        else:
            current.append(ch)

    if prev_quote:
        pass  # trailing quote already closed
    fields.append("".join(current).strip())
    return fields


_IOC_TYPE_STR_MAP: dict[str, IocType] = {
    "sha256": IocType.SHA256,
    "sha-256": IocType.SHA256,
    "sha1": IocType.SHA1,
    "sha-1": IocType.SHA1,
    "md5": IocType.MD5,
    "domain": IocType.DOMAIN,
    "domain-name": IocType.DOMAIN,
    "ipv4": IocType.IPV4,
    "ipv4-addr": IocType.IPV4,
    "ip": IocType.IPV4,
    "ipv6": IocType.IPV6,
    "ipv6-addr": IocType.IPV6,
    "url": IocType.URL,
}


def _parse_ioc_type_str(s: str) -> IocType | None:
    return _IOC_TYPE_STR_MAP.get(s.strip().lower())


def _parse_csv_line(line: str) -> IocEntry | None:
    fields = _split_csv_fields(line)
    if not fields:
        return None

    indicator = fields[0].strip()
    if not indicator:
        return None

    ioc_type: IocType | None = None
    if len(fields) > 1 and fields[1]:
        ioc_type = _parse_ioc_type_str(fields[1])
        if ioc_type is None:
            ioc_type = detect_ioc_type(indicator)
    else:
        ioc_type = detect_ioc_type(indicator)

    if ioc_type is None:
        return None

    description = fields[2] if len(fields) > 2 and fields[2] else None
    source = fields[3] if len(fields) > 3 and fields[3] else None

    return IocEntry(
        indicator=indicator,
        ioc_type=ioc_type,
        description=description,
        source=source,
    )


# ---------------------------------------------------------------------------
# STIX pattern parsing
# ---------------------------------------------------------------------------


def _stix_lhs_to_ioc_type(lhs: str) -> IocType | None:
    lower = lhs.lower()
    if "sha-256" in lower or "sha256" in lower:
        return IocType.SHA256
    if "sha-1" in lower or "sha1" in lower:
        return IocType.SHA1
    if "md5" in lower:
        return IocType.MD5
    if lower.startswith("domain-name"):
        return IocType.DOMAIN
    if lower.startswith("ipv4-addr"):
        return IocType.IPV4
    if lower.startswith("ipv6-addr"):
        return IocType.IPV6
    if lower.startswith("url"):
        return IocType.URL
    return None


def _parse_stix_pattern(pattern: str) -> tuple[str, IocType] | None:
    trimmed = pattern.strip()
    if not trimmed.startswith("[") or not trimmed.endswith("]"):
        return None

    inner = trimmed[1:-1]
    if "=" not in inner:
        return None

    lhs, rhs = inner.split("=", 1)
    lhs = lhs.strip()
    rhs = rhs.strip()

    if not rhs.startswith("'") or not rhs.endswith("'"):
        return None

    value = rhs[1:-1]
    if not value:
        return None

    ioc_type = _stix_lhs_to_ioc_type(lhs)
    if ioc_type is None:
        return None

    return (value, ioc_type)


# ---------------------------------------------------------------------------
# IocDatabase
# ---------------------------------------------------------------------------


class IocDatabase:
    """In-memory IOC database with indexed lookups."""

    def __init__(self) -> None:
        self._entries: list[IocEntry] = []
        self._hash_index: dict[str, list[IocEntry]] = {}
        self._domain_index: dict[str, list[IocEntry]] = {}
        self._ip_index: dict[str, list[IocEntry]] = {}
        self._url_index: dict[str, list[IocEntry]] = {}

    def add_entry(self, entry: IocEntry) -> None:
        """Add a single IOC entry and update indices."""
        indicator = entry.indicator.strip()
        if not indicator:
            return

        # Normalize indicator
        if indicator != entry.indicator:
            entry = IocEntry(
                indicator=indicator,
                ioc_type=entry.ioc_type,
                description=entry.description,
                source=entry.source,
            )

        self._entries.append(entry)
        key = indicator.lower()

        if entry.ioc_type in (IocType.SHA256, IocType.SHA1, IocType.MD5):
            self._hash_index.setdefault(key, []).append(entry)
        elif entry.ioc_type == IocType.DOMAIN:
            self._domain_index.setdefault(key, []).append(entry)
        elif entry.ioc_type in (IocType.IPV4, IocType.IPV6):
            self._ip_index.setdefault(key, []).append(entry)
        elif entry.ioc_type == IocType.URL:
            self._url_index.setdefault(key, []).append(entry)

    def __len__(self) -> int:
        return len(self._entries)

    def is_empty(self) -> bool:
        return len(self._entries) == 0

    def merge(self, other: IocDatabase) -> None:
        """Merge another database into this one."""
        for entry in other._entries:
            self.add_entry(entry)

    # -- Loaders -----------------------------------------------------------

    @classmethod
    def load_text_file(cls, path: str) -> IocDatabase:
        """Load IOCs from a plain-text file (one per line, ``#`` comments)."""
        try:
            with open(path) as f:
                content = f.read()
        except OSError as exc:
            raise IocError(f"failed to read {path}: {exc}") from exc

        db = cls()
        for line in content.splitlines():
            trimmed = line.strip()
            if not trimmed or trimmed.startswith("#"):
                continue
            ioc_type = detect_ioc_type(trimmed)
            if ioc_type is not None:
                db.add_entry(IocEntry(
                    indicator=trimmed,
                    ioc_type=ioc_type,
                    description=None,
                    source=None,
                ))
        return db

    @classmethod
    def load_csv_file(cls, path: str) -> IocDatabase:
        """Load IOCs from a CSV file.

        Expected columns: ``indicator, type, description, source``.
        """
        try:
            with open(path) as f:
                content = f.read()
        except OSError as exc:
            raise IocError(f"failed to read {path}: {exc}") from exc

        db = cls()
        lines = content.splitlines()
        if not lines:
            return db

        first = lines[0]
        first_lower = first.strip().lower()
        is_header = (
            first_lower.startswith("indicator,")
            or first_lower.startswith("indicator_type,")
            or first_lower == "indicator"
        )

        start_idx = 1 if is_header else 0
        for line in lines[start_idx:]:
            if not line.strip():
                continue
            entry = _parse_csv_line(line)
            if entry is not None:
                db.add_entry(entry)

        return db

    @classmethod
    def load_stix_bundle(cls, path: str) -> IocDatabase:
        """Load IOCs from a STIX 2.1 JSON bundle."""
        try:
            with open(path) as f:
                content = f.read()
        except OSError as exc:
            raise IocError(f"failed to read {path}: {exc}") from exc

        try:
            bundle = json.loads(content)
        except json.JSONDecodeError as exc:
            raise IocError(f"invalid JSON: {exc}") from exc

        objects = bundle.get("objects")
        if not isinstance(objects, list):
            raise IocError("STIX bundle missing 'objects' array")

        db = cls()
        for obj in objects:
            if not isinstance(obj, dict):
                continue

            sdo_type = obj.get("type", "")
            if sdo_type != "indicator":
                continue

            pattern = obj.get("pattern")
            if not isinstance(pattern, str):
                continue

            description = obj.get("description")
            source = obj.get("name")

            parsed = _parse_stix_pattern(pattern)
            if parsed is not None:
                indicator, ioc_type = parsed
                db.add_entry(IocEntry(
                    indicator=indicator,
                    ioc_type=ioc_type,
                    description=description,
                    source=source,
                ))

        return db

    # -- Matching ----------------------------------------------------------

    def match_event(self, event: TimelineEvent) -> IocMatch | None:
        """Match a single event against all IOCs. Returns accumulated matches or ``None``."""
        summary_lower = event.summary.lower()
        process_lower = (event.process or "").lower()
        raw_lower = ""
        if event.raw is not None:
            if isinstance(event.raw, str):
                raw_lower = event.raw.lower()
            else:
                try:
                    raw_lower = json.dumps(event.raw, default=str).lower()
                except (TypeError, ValueError, OverflowError, RecursionError):
                    # Ignore unserializable/circular payloads and continue
                    # scanning summary/process fields.
                    raw_lower = ""

        all_matched: list[IocEntry] = []
        match_field: str | None = None

        def _scan_index(
            index: dict[str, list[IocEntry]],
            matcher: object,
        ) -> None:
            nonlocal match_field
            for needle, entries in index.items():
                field = None
                if matcher(summary_lower, needle):  # type: ignore[operator]
                    field = "summary"
                elif matcher(process_lower, needle):  # type: ignore[operator]
                    field = "process"
                elif matcher(raw_lower, needle):  # type: ignore[operator]
                    field = "raw"
                if field is not None:
                    if match_field is None:
                        match_field = field
                    all_matched.extend(entries)

        # Hash index: plain substring match
        _scan_index(self._hash_index, lambda haystack, needle: needle in haystack)

        # Domain index: word-boundary match
        _scan_index(self._domain_index, contains_word_bounded)

        # IP index: word-boundary match
        _scan_index(self._ip_index, contains_word_bounded)

        # URL index: word-boundary match
        _scan_index(self._url_index, contains_word_bounded)

        if not all_matched:
            return None

        return IocMatch(
            event=event,
            matched_iocs=tuple(all_matched),
            match_field=match_field,  # type: ignore[arg-type]
        )

    def match_events(self, events: list[TimelineEvent]) -> list[IocMatch]:
        """Match multiple events. Returns all matches."""
        results: list[IocMatch] = []
        for event in events:
            m = self.match_event(event)
            if m is not None:
                results.append(m)
        return results


__all__ = [
    "detect_ioc_type",
    "contains_word_bounded",
    "IocDatabase",
]
