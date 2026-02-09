"""NATS bridge -- bidirectional Reticulum <-> NATS JetStream gateway."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import OrderedDict
from typing import Any, Callable, Optional

import nats
from nats.aio.client import Client as NATSClient

from .audit import AuditLog

logger = logging.getLogger(__name__)

NATS_SUBJECT_PREFIX = "clawdstrike.spine.envelope"
DEDUP_RING_SIZE = 4096


class DisclosurePolicy:
    """Governs which fact types may cross the Reticulum <-> NATS boundary."""

    def __init__(self, policy: dict[str, Any]) -> None:
        self._nats_to_ret = policy.get("nats_to_reticulum", {})
        self._ret_to_nats = policy.get("reticulum_to_nats", {})

    def allows_outbound(self, fact_schema: str) -> bool:
        """Check if fact type may cross NATS -> Reticulum."""
        return self._check(self._nats_to_ret, fact_schema)

    def allows_inbound(self, fact_schema: str) -> bool:
        """Check if fact type may cross Reticulum -> NATS."""
        return self._check(self._ret_to_nats, fact_schema)

    @staticmethod
    def _check(direction_policy: dict[str, Any], fact_schema: str) -> bool:
        blocked = direction_policy.get("blocked", [])
        allowed = direction_policy.get("allowed", [])

        for pattern in blocked:
            if pattern.endswith("*"):
                if fact_schema.startswith(pattern[:-1]):
                    return False
            elif fact_schema == pattern:
                return False

        if allowed:
            for pattern in allowed:
                if pattern.endswith("*"):
                    if fact_schema.startswith(pattern[:-1]):
                        return True
                elif fact_schema == pattern:
                    return True
            return False

        return True


class _DeduplicatorRing:
    """Bounded set that evicts the oldest entry when full."""

    def __init__(self, maxsize: int = DEDUP_RING_SIZE) -> None:
        self._data: OrderedDict[str, None] = OrderedDict()
        self._maxsize = maxsize

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def add(self, key: str) -> None:
        if key in self._data:
            self._data.move_to_end(key)
            return
        if len(self._data) >= self._maxsize:
            self._data.popitem(last=False)
        self._data[key] = None


class NATSBridge:
    """Bidirectional bridge between Reticulum and NATS.

    Reticulum -> NATS: verified envelopes from the radio mesh published to NATS.
    NATS -> Reticulum: envelopes from NATS forwarded to the radio mesh.
    """

    def __init__(
        self,
        nats_url: str,
        disclosure_policy: DisclosurePolicy,
        audit_log: AuditLog,
        on_outbound: Optional[Callable[[dict[str, Any]], None]] = None,
    ) -> None:
        self._nats_url = nats_url
        self._disclosure = disclosure_policy
        self._audit_log = audit_log
        self._on_outbound = on_outbound
        self._nc: Optional[NATSClient] = None
        self._seen = _DeduplicatorRing()

    async def connect(self) -> None:
        self._nc = await nats.connect(self._nats_url)
        js = self._nc.jetstream()
        await js.subscribe(
            f"{NATS_SUBJECT_PREFIX}.>",
            cb=self._on_nats_envelope,
        )
        logger.info("NATS bridge connected to %s", self._nats_url)

    async def close(self) -> None:
        if self._nc is not None:
            await self._nc.close()
            self._nc = None

    async def _on_nats_envelope(self, msg: Any) -> None:
        """Forward NATS envelope to Reticulum (outbound to field)."""
        try:
            envelope = json.loads(msg.data.decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            logger.warning("Invalid envelope on NATS subject %s", msg.subject)
            return

        env_hash = envelope.get("envelope_hash", "")
        if env_hash in self._seen:
            return

        fact_schema = envelope.get("fact", {}).get("schema", "")
        if not self._disclosure.allows_outbound(fact_schema):
            self._audit_log.log_drop(
                env_hash, reason=f"disclosure_blocked:{fact_schema}"
            )
            return

        self._seen.add(env_hash)
        self._audit_log.log_gateway(
            env_hash, direction="nats_to_reticulum",
            nats_subject=msg.subject,
        )
        if self._on_outbound is not None:
            self._on_outbound(envelope)

    def forward_to_nats(self, envelope: dict[str, Any]) -> None:
        """Forward a verified Reticulum envelope to NATS (inbound from field)."""
        if self._nc is None:
            logger.warning("NATS not connected; dropping envelope")
            return

        env_hash = envelope.get("envelope_hash", "")
        if env_hash in self._seen:
            return

        fact_schema = envelope.get("fact", {}).get("schema", "")
        if not self._disclosure.allows_inbound(fact_schema):
            self._audit_log.log_drop(
                env_hash, reason=f"disclosure_blocked_inbound:{fact_schema}"
            )
            return

        self._seen.add(env_hash)
        subject = f"{NATS_SUBJECT_PREFIX}.reticulum.{fact_schema}"
        data = json.dumps(envelope).encode()
        self._audit_log.log_gateway(
            env_hash, direction="reticulum_to_nats",
            nats_subject=subject,
        )
        asyncio.ensure_future(self._nc.publish(subject, data))
