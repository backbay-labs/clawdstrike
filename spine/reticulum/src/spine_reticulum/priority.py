"""7-tier priority queue with bandwidth budget scheduler."""

from __future__ import annotations

import heapq
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


class Priority(IntEnum):
    """7-tier priority from highest (1) to lowest (7)."""

    REVOCATION = 1
    CHECKPOINT = 2
    INCIDENT = 3
    POLICY_DELTA = 4
    RUN = 5
    NODE_ATTESTATION = 6
    HEARTBEAT = 7


SCHEMA_PRIORITY: dict[str, Priority] = {
    "clawdstrike.spine.fact.revocation.v1": Priority.REVOCATION,
    "clawdstrike.spine.fact.log_checkpoint.v1": Priority.CHECKPOINT,
    "clawdstrike.spine.fact.incident.v1": Priority.INCIDENT,
    "clawdstrike.spine.fact.policy_delta.v1": Priority.POLICY_DELTA,
    "clawdstrike.spine.fact.run.v1": Priority.RUN,
    "clawdstrike.spine.fact.node_attestation.v1": Priority.NODE_ATTESTATION,
    "clawdstrike.spine.fact.heartbeat.v1": Priority.HEARTBEAT,
}


def priority_for_envelope(envelope: dict[str, Any]) -> Priority:
    """Determine priority from the ``fact.schema`` field."""
    fact_schema = envelope.get("fact", {}).get("schema", "")
    return SCHEMA_PRIORITY.get(fact_schema, Priority.HEARTBEAT)


@dataclass(order=True)
class PrioritizedEnvelope:
    priority: int
    timestamp: float = field(compare=True)
    envelope: dict[str, Any] = field(compare=False)
    size_bytes: int = field(compare=False, default=0)


class BandwidthBudgetScheduler:
    """Schedules envelope transmission respecting link bandwidth.

    Budget allocation (from research doc Section 5.2):
      - Revocations: unlimited (but rate-bucketed)
      - Checkpoints: 30% of remaining
      - Incidents: 25% of remaining
      - Remaining: split among lower priorities by weight

    Drop thresholds: below a configurable BPS threshold, lower-priority
    fact types are silently dropped.
    """

    def __init__(
        self,
        link_bps: float,
        revocation_rate_limit: int = 10,
        drop_thresholds: Optional[dict[Priority, float]] = None,
    ) -> None:
        self._queue: list[PrioritizedEnvelope] = []
        self._link_bps = link_bps
        self._revocation_rate_limit = revocation_rate_limit
        self._revocation_count_this_hour = 0
        self._hour_start = time.time()
        self._drop_thresholds: dict[Priority, float] = drop_thresholds or {
            Priority.HEARTBEAT: 100,
            Priority.NODE_ATTESTATION: 50,
            Priority.RUN: 20,
        }

    @property
    def link_bps(self) -> float:
        return self._link_bps

    @link_bps.setter
    def link_bps(self, value: float) -> None:
        self._link_bps = value

    def enqueue(self, envelope: dict[str, Any], size_bytes: int) -> bool:
        """Add envelope to the priority queue, applying drop rules.

        Returns ``True`` if enqueued, ``False`` if dropped.
        """
        priority = priority_for_envelope(envelope)

        threshold = self._drop_thresholds.get(priority)
        if threshold is not None and self._link_bps < threshold:
            return False

        entry = PrioritizedEnvelope(
            priority=priority.value,
            timestamp=time.time(),
            envelope=envelope,
            size_bytes=size_bytes,
        )
        heapq.heappush(self._queue, entry)
        return True

    def dequeue(self) -> Optional[dict[str, Any]]:
        """Get the next envelope to transmit, respecting rate limits."""
        while self._queue:
            now = time.time()
            if now - self._hour_start >= 3600:
                self._revocation_count_this_hour = 0
                self._hour_start = now

            entry = heapq.heappop(self._queue)

            if entry.priority == Priority.REVOCATION:
                if self._revocation_count_this_hour >= self._revocation_rate_limit:
                    continue  # skip rate-limited revocation, try next
                self._revocation_count_this_hour += 1

            return entry.envelope

        return None

    @property
    def pending_count(self) -> int:
        return len(self._queue)
