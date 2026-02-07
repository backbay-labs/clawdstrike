"""Main Reticulum adapter -- bridges Spine signed envelopes to the Reticulum mesh.

Adapted from ``cyntra.trust.spine.reticulum.node.ReticulumAdapter`` in the
Backbay platform kernel.  This standalone version adds:
  - LXMF store-and-forward integration (priority 1-4 facts)
  - CBOR compact encoding for constrained links
  - Optional NATS JetStream bridge (gateway mode)

The adapter can run in two modes:
  1. **Node mode** (default): send/receive envelopes over Reticulum.
  2. **Gateway mode**: additionally bridge to NATS JetStream.
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import suppress
from typing import Any, Optional

from .audit import AuditLog
from .config import AdapterConfig, load_disclosure_policy
from .encoding import decode_envelope, encode_envelope_cbor
from .envelope import compute_envelope_hash, verify_envelope
from .gateway import DisclosurePolicy, NATSBridge
from .priority import BandwidthBudgetScheduler, Priority, priority_for_envelope
from .store import SpineStore

logger = logging.getLogger(__name__)


class ReticulumAdapter:
    """Spine-to-Reticulum bridge process.

    Lifecycle::

        adapter = ReticulumAdapter(config)
        await adapter.start()   # initialises RNS + LXMF + optional NATS
        adapter.send_envelope(envelope)
        await adapter.stop()
    """

    def __init__(self, config: AdapterConfig) -> None:
        self._config = config
        self._store = SpineStore(config.db_path)
        self._scheduler = BandwidthBudgetScheduler(
            link_bps=config.default_link_bps,
            revocation_rate_limit=config.revocation_rate_limit_per_hour,
            drop_thresholds=config.drop_thresholds,
        )
        self._audit_log = AuditLog(config.audit_log_path)
        self._nats_bridge: Optional[NATSBridge] = None

        # Lazy-imported RNS/LXMF objects (set during start())
        self._reticulum: Any = None
        self._identity: Any = None
        self._lxmf_router: Any = None
        self._lxmf_destination: Any = None
        self._peers: dict[str, Any] = {}
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Initialise the Reticulum stack, LXMF router, and optional NATS bridge."""
        import RNS  # type: ignore[import-untyped]
        import LXMF  # type: ignore[import-untyped]

        self._reticulum = RNS.Reticulum(self._config.reticulum_config_dir)

        identity_path = self._config.identity_path
        if identity_path and RNS.Identity.from_file(identity_path):
            self._identity = RNS.Identity.from_file(identity_path)
        else:
            self._identity = RNS.Identity()

        self._lxmf_router = LXMF.LXMRouter(
            identity=self._identity,
            storagepath=self._config.lxmf_storage_dir,
        )
        self._lxmf_destination = self._lxmf_router.register_delivery_identity(
            self._identity,
            display_name=self._config.node_name,
        )
        self._lxmf_router.register_delivery_callback(self._on_lxmf_delivery)

        if self._config.nats_url and self._config.disclosure_policy_path:
            raw_policy = load_disclosure_policy(self._config.disclosure_policy_path)
            disclosure = DisclosurePolicy(raw_policy)
            self._nats_bridge = NATSBridge(
                nats_url=self._config.nats_url,
                disclosure_policy=disclosure,
                audit_log=self._audit_log,
                on_outbound=self.send_envelope,
            )
            await self._nats_bridge.connect()

        self._running = True
        logger.info(
            "ReticulumAdapter started (node=%s, gateway=%s)",
            self._config.node_name,
            self._nats_bridge is not None,
        )

    async def stop(self) -> None:
        """Shut down the adapter gracefully."""
        self._running = False
        if self._nats_bridge is not None:
            with suppress(Exception):
                await self._nats_bridge.close()
        self._store.close()
        logger.info("ReticulumAdapter stopped")

    # ------------------------------------------------------------------
    # Inbound (from Reticulum / LXMF)
    # ------------------------------------------------------------------

    def _on_lxmf_delivery(self, message: Any) -> None:
        """Handle an incoming LXMF message containing a Spine envelope."""
        try:
            envelope = decode_envelope(message.content)
            source = str(getattr(message, "source_hash", "unknown"))
            self._process_inbound(envelope, source=source)
        except Exception as exc:
            self._audit_log.log_error(f"LXMF delivery error: {exc}")

    def _process_inbound(self, envelope: dict[str, Any], source: str) -> None:
        """Verify, store, audit, and optionally bridge an inbound envelope."""
        env_hash = envelope.get("envelope_hash", "unknown")

        # Hash verification
        try:
            computed = compute_envelope_hash(envelope)
            if computed != env_hash:
                self._audit_log.log_drop(env_hash, reason="invalid_envelope_hash")
                return
        except Exception:
            self._audit_log.log_drop(env_hash, reason="hash_computation_failed")
            return

        # Signature verification
        try:
            if not verify_envelope(envelope):
                self._audit_log.log_drop(env_hash, reason="invalid_signature")
                return
        except ValueError as exc:
            self._audit_log.log_drop(env_hash, reason=str(exc))
            return

        # Store
        result = self._store.insert(envelope, received_from=source)
        if result.duplicate:
            return

        fact_schema = str(envelope.get("fact", {}).get("schema", ""))
        self._audit_log.log_ingest(
            sender=source,
            envelope_hash=env_hash,
            issuer=envelope.get("issuer", ""),
            seq=envelope.get("seq", -1),
            fact_schema=fact_schema,
            out_of_order=result.out_of_order,
            fork_detected=result.fork_detected,
        )

        if result.fork_detected:
            logger.warning("Fork detected for issuer=%s seq=%s", envelope.get("issuer"), envelope.get("seq"))

        # Bridge to NATS if in gateway mode
        if self._nats_bridge is not None:
            self._nats_bridge.forward_to_nats(envelope)

    # ------------------------------------------------------------------
    # Outbound (to Reticulum)
    # ------------------------------------------------------------------

    def send_envelope(
        self,
        envelope: dict[str, Any],
        peer_destination: Any = None,
    ) -> None:
        """Send an envelope to a specific peer or broadcast to all."""
        priority = priority_for_envelope(envelope)
        encoded = encode_envelope_cbor(envelope)
        size_bytes = len(encoded)

        enqueued = self._scheduler.enqueue(envelope, size_bytes)
        if not enqueued:
            self._audit_log.log_drop(
                envelope.get("envelope_hash", "unknown"),
                reason="bandwidth_drop",
            )
            return

        next_env = self._scheduler.dequeue()
        if next_env is None:
            return

        next_priority = priority_for_envelope(next_env)
        next_encoded = encode_envelope_cbor(next_env)

        if next_priority <= Priority.POLICY_DELTA:
            self._send_via_lxmf(next_encoded, peer_destination)
        else:
            self._send_direct(next_encoded, peer_destination)

    def _send_via_lxmf(self, data: bytes, destination: Any = None) -> None:
        """Send via LXMF with delivery acknowledgement and store-and-forward."""
        if self._lxmf_router is None:
            return
        import LXMF  # type: ignore[import-untyped]

        targets = [destination] if destination else list(self._peers.values())
        for dest in targets:
            msg = LXMF.LXMessage(
                destination=dest,
                source=self._lxmf_destination,
                content=data,
                desired_method=LXMF.LXMessage.DIRECT,
            )
            msg.try_propagation_on_fail = True
            self._lxmf_router.handle_outbound(msg)

    def _send_direct(self, data: bytes, destination: Any = None) -> None:
        """Send via direct Reticulum packet (ephemeral, no store-and-forward)."""
        import RNS  # type: ignore[import-untyped]

        targets = [destination] if destination else list(self._peers.values())
        for dest in targets:
            with suppress(Exception):
                packet = RNS.Packet(dest, data)
                packet.send()

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def store(self) -> SpineStore:
        return self._store

    @property
    def audit_log(self) -> AuditLog:
        return self._audit_log

    @property
    def scheduler(self) -> BandwidthBudgetScheduler:
        return self._scheduler

    @property
    def running(self) -> bool:
        return self._running
