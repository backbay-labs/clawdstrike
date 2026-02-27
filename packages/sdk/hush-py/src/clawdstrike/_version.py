"""Version parsing utilities."""

from __future__ import annotations


def parse_semver_strict(version: str) -> tuple[int, int, int] | None:
    """Parse a strict semver version string.

    Rejects leading zeros, non-numeric parts, and incomplete versions.
    """
    parts = version.split(".")
    if len(parts) != 3:
        return None

    out: list[int] = []
    for part in parts:
        if not part:
            return None
        if len(part) > 1 and part.startswith("0"):
            return None
        if not part.isdigit():
            return None
        out.append(int(part))

    return out[0], out[1], out[2]
