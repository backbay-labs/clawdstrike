"""Hash-chained JSONL audit log (tamper-evident).

Adapted from ``cyntra.trust.spine.audit.AuditLog`` in the Backbay platform
kernel.  Each entry carries ``prev_hash`` and ``hash`` fields forming a
SHA-256 hash chain.  The hash is computed over the canonical JSON (RFC 8785)
of the entry without the ``hash`` field.
"""

from __future__ import annotations

import hashlib
import json
import os
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any, Optional

import rfc8785


def _now_iso_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_hex_prefixed(data: bytes) -> str:
    return "0x" + hashlib.sha256(data).hexdigest()


def _canonical_bytes(obj: dict[str, Any]) -> bytes:
    """RFC 8785 canonical JSON bytes for hashing."""
    return rfc8785.dumps(obj)


class AuditLog:
    """Append-only JSONL audit log with hash-chaining for tamper evidence.

    Mirrors the Cyntra ``AuditLog`` interface.  Each entry contains:
      - ``ts``: ISO 8601 timestamp
      - ``prev_hash``: 0x-prefixed SHA-256 of the previous entry's canonical JSON (sans ``hash``)
      - ``hash``: 0x-prefixed SHA-256 of this entry's canonical JSON (sans ``hash``)
    """

    GENESIS_HASH = "0x" + "00" * 32

    def __init__(self, path: str) -> None:
        self._path = path
        self._last_hash = self._recover_last_hash()

    @classmethod
    def open(cls, path: str) -> "AuditLog":
        """Named constructor matching the Cyntra API."""
        return cls(path)

    def _recover_last_hash(self) -> str:
        """Read the last line of the log to recover the chain head hash."""
        if not os.path.exists(self._path):
            return self.GENESIS_HASH
        try:
            with open(self._path, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size == 0:
                    return self.GENESIS_HASH
                read_size = min(8192, size)
                f.seek(-read_size, 2)
                chunk = f.read()
            lines = [ln.strip() for ln in chunk.splitlines() if ln.strip()]
            if not lines:
                return self.GENESIS_HASH
            last_line = lines[-1].decode("utf-8")
            d = json.loads(last_line)
            return str(d.get("hash", self.GENESIS_HASH))
        except Exception:
            return self.GENESIS_HASH

    def append(self, event: dict[str, Any]) -> None:
        """Append an event, adding ``ts``, ``prev_hash``, and ``hash``."""
        record = dict(event)
        record.setdefault("ts", _now_iso_z())
        record["prev_hash"] = self._last_hash
        record.pop("hash", None)

        h = _sha256_hex_prefixed(_canonical_bytes(record))
        record["hash"] = h

        line = json.dumps(record, separators=(",", ":"), sort_keys=True)
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

        self._last_hash = h

    # Convenience wrappers

    def log_forward(
        self,
        envelope_hash: str,
        direction: str,
        source: Optional[str] = None,
        destination: Optional[str] = None,
    ) -> None:
        self.append({
            "kind": "forward",
            "envelope_hash": envelope_hash,
            "direction": direction,
            "source": source,
            "destination": destination,
        })

    def log_drop(self, envelope_hash: str, reason: str) -> None:
        self.append({
            "kind": "drop",
            "envelope_hash": envelope_hash,
            "reason": reason,
        })

    def log_fork(
        self,
        issuer: str,
        seq: int,
        existing_hash: str,
        new_hash: str,
    ) -> None:
        self.append({
            "kind": "fork",
            "issuer": issuer,
            "seq": seq,
            "existing_hash": existing_hash,
            "new_hash": new_hash,
        })

    def log_error(self, message: str) -> None:
        self.append({"kind": "error", "message": message})

    def log_gateway(
        self,
        envelope_hash: str,
        direction: str,
        nats_subject: Optional[str] = None,
    ) -> None:
        self.append({
            "kind": "gateway",
            "envelope_hash": envelope_hash,
            "direction": direction,
            "nats_subject": nats_subject,
        })

    def log_ingest(self, **fields: Any) -> None:
        self.append({"kind": "ingest", **fields})


def verify_chain(path: str) -> tuple[bool, int]:
    """Verify the hash chain of an audit log file.

    Returns ``(valid, line_count)``.  If the chain is broken, ``valid``
    is ``False`` and ``line_count`` is the index of the first bad entry.
    """
    if not os.path.exists(path):
        return True, 0

    prev_hash = AuditLog.GENESIS_HASH
    count = 0
    with open(path, "r") as f:
        for line_no, raw_line in enumerate(f):
            raw_line = raw_line.rstrip("\n")
            if not raw_line:
                continue
            try:
                entry = json.loads(raw_line)
            except json.JSONDecodeError:
                return False, line_no
            if entry.get("prev_hash") != prev_hash:
                return False, line_no
            # Recompute hash: canonical JSON of entry without 'hash'
            check = dict(entry)
            check.pop("hash", None)
            computed = _sha256_hex_prefixed(_canonical_bytes(check))
            stored_hash = entry.get("hash", "")
            if computed != stored_hash:
                return False, line_no
            prev_hash = stored_hash
            count += 1

    return True, count
