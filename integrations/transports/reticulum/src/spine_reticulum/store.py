"""SQLite-backed envelope store with dedup, monotonicity, and fork detection.

Adapted from ``cyntra.trust.spine.store.envelopes.EnvelopeStore`` in the
Backbay platform kernel.  The schema and ingestion logic mirror that
implementation so envelopes produced by either system are interoperable.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any, Optional


class ForkDetected(Exception):
    """Raised when two different envelopes share the same (issuer, seq)."""

    def __init__(self, issuer: str, seq: int,
                 existing_hash: str, new_hash: str) -> None:
        self.issuer = issuer
        self.seq = seq
        self.existing_hash = existing_hash
        self.new_hash = new_hash
        super().__init__(
            f"Fork detected for {issuer} at seq {seq}: "
            f"{existing_hash} vs {new_hash}"
        )


@dataclass
class EnvelopeIngestResult:
    """Result of an envelope insert attempt, mirroring Cyntra's pattern."""

    inserted: bool
    duplicate: bool
    fork_detected: bool
    out_of_order: bool
    extended_contiguous_chain: bool
    reason: str | None = None


class SpineStore:
    """SQLite-backed envelope store with dedup and contiguous chain tracking."""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._create_tables()

    def _create_tables(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS envelopes (
                envelope_hash TEXT PRIMARY KEY,
                issuer TEXT NOT NULL,
                seq INTEGER NOT NULL,
                prev_envelope_hash TEXT,
                issued_at TEXT NOT NULL,
                fact_schema TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                received_from TEXT,
                received_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE INDEX IF NOT EXISTS idx_issuer_seq
                ON envelopes(issuer, seq);
            CREATE INDEX IF NOT EXISTS idx_fact_schema
                ON envelopes(fact_schema);

            CREATE TABLE IF NOT EXISTS issuer_chain (
                issuer TEXT PRIMARY KEY,
                contiguous_seq INTEGER NOT NULL DEFAULT -1,
                contiguous_head_hash TEXT,
                fork_detected INTEGER NOT NULL DEFAULT 0,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def has_envelope(self, envelope_hash: str) -> bool:
        """Dedup check by envelope_hash."""
        cur = self._conn.execute(
            "SELECT 1 FROM envelopes WHERE envelope_hash = ?",
            (envelope_hash,),
        )
        return cur.fetchone() is not None

    def insert(
        self,
        envelope: dict[str, Any],
        received_from: str | None = None,
    ) -> EnvelopeIngestResult:
        """Insert envelope with Cyntra-compatible ingest semantics.

        Returns an ``EnvelopeIngestResult`` describing what happened.
        """
        env_hash = str(envelope.get("envelope_hash", ""))
        issuer = str(envelope.get("issuer", ""))
        seq = int(envelope.get("seq", -1))
        prev = envelope.get("prev_envelope_hash")
        issued_at = str(envelope.get("issued_at", ""))
        fact_schema = str(envelope.get("fact", {}).get("schema", ""))

        # Dedup
        existing = self._conn.execute(
            "SELECT 1 FROM envelopes WHERE envelope_hash = ?",
            (env_hash,),
        ).fetchone()
        if existing is not None:
            return EnvelopeIngestResult(
                inserted=False, duplicate=True, fork_detected=False,
                out_of_order=False, extended_contiguous_chain=False,
                reason="duplicate_envelope_hash",
            )

        # Fork detection
        fork_row = self._conn.execute(
            "SELECT envelope_hash FROM envelopes WHERE issuer = ? AND seq = ? LIMIT 1",
            (issuer, seq),
        ).fetchone()
        fork_detected = fork_row is not None

        # Insert
        self._conn.execute(
            """INSERT INTO envelopes
               (envelope_hash, issuer, seq, prev_envelope_hash,
                issued_at, fact_schema, raw_json, received_from)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (env_hash, issuer, seq, prev, issued_at, fact_schema,
             json.dumps(envelope, separators=(",", ":"), sort_keys=True),
             received_from),
        )

        # Chain tracking
        chain = self._conn.execute(
            "SELECT contiguous_seq, contiguous_head_hash, fork_detected "
            "FROM issuer_chain WHERE issuer = ?",
            (issuer,),
        ).fetchone()
        if chain is None:
            self._conn.execute(
                "INSERT INTO issuer_chain (issuer, contiguous_seq, contiguous_head_hash, fork_detected) "
                "VALUES (?, -1, NULL, 0)",
                (issuer,),
            )
            contiguous_seq = -1
            contiguous_head = None
            prior_fork = 0
        else:
            contiguous_seq = int(chain["contiguous_seq"])
            contiguous_head = chain["contiguous_head_hash"]
            prior_fork = int(chain["fork_detected"])

        out_of_order = True
        extended = False

        if seq == contiguous_seq + 1:
            if contiguous_seq == -1:
                if prev in (None, "", "null"):
                    out_of_order = False
                    extended = True
            else:
                if prev == contiguous_head:
                    out_of_order = False
                    extended = True

        if extended:
            self._conn.execute(
                "UPDATE issuer_chain SET contiguous_seq = ?, contiguous_head_hash = ?, "
                "updated_at = CURRENT_TIMESTAMP WHERE issuer = ?",
                (seq, env_hash, issuer),
            )

        if fork_detected or prior_fork:
            self._conn.execute(
                "UPDATE issuer_chain SET fork_detected = 1, updated_at = CURRENT_TIMESTAMP "
                "WHERE issuer = ?",
                (issuer,),
            )

        self._conn.commit()

        return EnvelopeIngestResult(
            inserted=True, duplicate=False, fork_detected=fork_detected,
            out_of_order=out_of_order, extended_contiguous_chain=extended,
            reason="ok",
        )

    def insert_envelope(self, envelope: dict[str, Any]) -> bool:
        """Simplified insert that returns True/False and raises ForkDetected.

        Convenience wrapper around ``insert()`` for backward compatibility.
        """
        result = self.insert(envelope)
        if result.duplicate:
            return False
        if result.fork_detected:
            # Find the conflicting hash for the exception
            existing = self._conn.execute(
                "SELECT envelope_hash FROM envelopes WHERE issuer = ? AND seq = ? "
                "AND envelope_hash != ? LIMIT 1",
                (envelope["issuer"], envelope["seq"], envelope["envelope_hash"]),
            ).fetchone()
            if existing is not None:
                raise ForkDetected(
                    envelope["issuer"], envelope["seq"],
                    str(existing["envelope_hash"]), envelope["envelope_hash"],
                )
        return result.inserted

    def get_head(self, issuer: str) -> Optional[dict]:
        """Return the latest ``{seq, envelope_hash}`` for *issuer*, or ``None``."""
        row = self._conn.execute(
            "SELECT contiguous_seq, contiguous_head_hash FROM issuer_chain WHERE issuer = ?",
            (issuer,),
        ).fetchone()
        if row is None or int(row["contiguous_seq"]) < 0 or row["contiguous_head_hash"] is None:
            return None
        return {"seq": int(row["contiguous_seq"]), "envelope_hash": str(row["contiguous_head_hash"])}

    def get_contiguous_head(self, issuer: str) -> tuple[int, str] | None:
        """Return ``(seq, head_hash)`` for *issuer*, or ``None``.

        Mirrors the Cyntra ``EnvelopeStore.get_contiguous_head`` API.
        """
        row = self._conn.execute(
            "SELECT contiguous_seq, contiguous_head_hash FROM issuer_chain WHERE issuer = ?",
            (issuer,),
        ).fetchone()
        if row is None or int(row["contiguous_seq"]) < 0 or row["contiguous_head_hash"] is None:
            return None
        return int(row["contiguous_seq"]), str(row["contiguous_head_hash"])

    def get_envelopes_range(
        self, issuer: str, from_seq: int, to_seq: int,
    ) -> list[dict]:
        """Retrieve envelopes for a sync response."""
        cur = self._conn.execute(
            """SELECT raw_json FROM envelopes
               WHERE issuer = ? AND seq >= ? AND seq <= ?
               ORDER BY seq ASC""",
            (issuer, from_seq, to_seq),
        )
        return [json.loads(row["raw_json"]) for row in cur.fetchall()]

    def count(self) -> int:
        """Return the total number of stored envelopes."""
        row = self._conn.execute("SELECT COUNT(*) AS c FROM envelopes").fetchone()
        return int(row["c"]) if row else 0

    def count_by_issuer(self, issuer: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS c FROM envelopes WHERE issuer = ?",
            (issuer,),
        ).fetchone()
        return int(row["c"]) if row else 0
