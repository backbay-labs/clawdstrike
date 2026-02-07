"""CBOR compact encoding and fragmentation for constrained links."""

from __future__ import annotations

import json
import os
import time
from typing import Any

import cbor2

CBOR_MAGIC = b"CB"
FRAGMENT_MAGIC = b"F1"
FRAGMENT_HEADER_SIZE = 10  # F1(2) + msg_id(4) + index(2) + total(2)
MAX_REASSEMBLY_BUFFER = 64
MAX_FRAGMENT_AGE_SECS = 300


def encode_envelope_cbor(envelope: dict[str, Any]) -> bytes:
    """Encode envelope as CBOR with magic prefix."""
    cbor_bytes = cbor2.dumps(envelope)
    return CBOR_MAGIC + cbor_bytes


def decode_envelope(data: bytes) -> dict[str, Any]:
    """Decode envelope from either CBOR or JSON."""
    if data[:2] == CBOR_MAGIC:
        return cbor2.loads(data[2:])
    if data[:2] == FRAGMENT_MAGIC:
        raise ValueError("Fragment received; use FragmentReassembler")
    return json.loads(data)


def fragment_envelope(
    data: bytes,
    mtu: int = 500,
    message_id: bytes | None = None,
) -> list[bytes]:
    """Fragment encoded data into MTU-sized chunks.

    Fragment header: ``F1`` + msg_id(4) + index(2) + total(2) = 10 bytes.
    """
    payload_size = mtu - FRAGMENT_HEADER_SIZE
    if payload_size <= 0:
        raise ValueError(f"MTU {mtu} too small for fragmentation")

    if len(data) <= mtu:
        return [data]

    if message_id is None:
        message_id = os.urandom(4)
    if len(message_id) != 4:
        raise ValueError("message_id must be exactly 4 bytes")

    total = (len(data) + payload_size - 1) // payload_size
    if total > 65535:
        raise ValueError("Data too large to fragment")

    fragments: list[bytes] = []
    for i in range(total):
        chunk = data[i * payload_size:(i + 1) * payload_size]
        header = (
            FRAGMENT_MAGIC
            + message_id
            + i.to_bytes(2, "big")
            + total.to_bytes(2, "big")
        )
        fragments.append(header + chunk)

    return fragments


def parse_fragment_header(data: bytes) -> tuple[bytes, int, int, bytes]:
    """Parse a fragment header, returning (msg_id, index, total, payload)."""
    if len(data) < FRAGMENT_HEADER_SIZE:
        raise ValueError("Fragment too short")
    if data[:2] != FRAGMENT_MAGIC:
        raise ValueError("Not a fragment")
    msg_id = data[2:6]
    index = int.from_bytes(data[6:8], "big")
    total = int.from_bytes(data[8:10], "big")
    payload = data[10:]
    return msg_id, index, total, payload


class FragmentReassembler:
    """Reassemble fragmented envelopes, enforcing buffer and age limits."""

    def __init__(
        self,
        max_pending: int = MAX_REASSEMBLY_BUFFER,
        max_age_secs: float = MAX_FRAGMENT_AGE_SECS,
    ) -> None:
        self._max_pending = max_pending
        self._max_age_secs = max_age_secs
        # msg_id -> {index -> payload, "total": int, "started": float}
        self._pending: dict[bytes, dict] = {}

    def add_fragment(self, data: bytes) -> bytes | None:
        """Add a fragment. Returns the reassembled data when complete, else ``None``."""
        msg_id, index, total, payload = parse_fragment_header(data)

        self._evict_stale()

        if msg_id not in self._pending:
            if len(self._pending) >= self._max_pending:
                # Drop oldest incomplete reassembly to make room
                oldest_key = min(
                    self._pending, key=lambda k: self._pending[k]["started"]
                )
                del self._pending[oldest_key]
            self._pending[msg_id] = {"total": total, "started": time.time()}

        entry = self._pending[msg_id]
        entry[index] = payload

        # Check if all fragments received (keys other than "total" and "started")
        received = sum(1 for k in entry if isinstance(k, int))
        if received == entry["total"]:
            parts = [entry[i] for i in range(entry["total"])]
            del self._pending[msg_id]
            return b"".join(parts)

        return None

    def _evict_stale(self) -> None:
        now = time.time()
        stale = [
            k for k, v in self._pending.items()
            if now - v["started"] > self._max_age_secs
        ]
        for k in stale:
            del self._pending[k]

    @property
    def pending_count(self) -> int:
        return len(self._pending)
