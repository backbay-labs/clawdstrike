"""Human-readable duration parsing.

Port of ``hush-core/src/duration.rs``.
"""

from __future__ import annotations

from datetime import timedelta

_SUFFIX_MAP: dict[str, str] = {
    "s": "seconds",
    "sec": "seconds",
    "secs": "seconds",
    "second": "seconds",
    "seconds": "seconds",
    "m": "minutes",
    "min": "minutes",
    "mins": "minutes",
    "minute": "minutes",
    "minutes": "minutes",
    "h": "hours",
    "hr": "hours",
    "hrs": "hours",
    "hour": "hours",
    "hours": "hours",
    "d": "days",
    "day": "days",
    "days": "days",
}


def parse_human_duration(s: str) -> timedelta | None:
    """Parse a human-readable duration such as ``30s``, ``5m``, ``1h``, or ``2d``.

    Returns ``None`` for invalid input.
    """
    s = s.strip()
    if not s:
        return None

    # Find boundary between digits and suffix
    digit_end = 0
    for i, ch in enumerate(s):
        if ch.isascii() and ch.isdigit():
            digit_end = i + 1
        else:
            break
    else:
        # All characters were digits (no suffix)
        if digit_end == len(s):
            return None

    if digit_end == 0:
        return None

    digits = s[:digit_end]
    suffix = s[digit_end:].strip().lower()

    if not suffix:
        return None

    try:
        value = int(digits)
    except ValueError:
        return None

    unit = _SUFFIX_MAP.get(suffix)
    if unit is None:
        return None

    try:
        if unit == "seconds":
            return timedelta(seconds=value)
        elif unit == "minutes":
            return timedelta(minutes=value)
        elif unit == "hours":
            return timedelta(hours=value)
        else:
            return timedelta(days=value)
    except OverflowError:
        return None
