"""Watch mode — subscribe to NATS for live envelope events.

Feeds parsed spine envelopes through a CorrelationEngine and invokes
callbacks when correlation rules fire.

Requires the optional ``nats-py`` dependency (``pip install clawdstrike[hunt]``).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import datetime, timezone

from clawdstrike.hunt.correlate import CorrelationEngine
from clawdstrike.hunt.errors import WatchError
from clawdstrike.hunt.timeline import parse_envelope
from clawdstrike.hunt.types import (
    Alert,
    TimelineEvent,
    WatchConfig,
    WatchStats,
)

_NATS_SUBJECT = "clawdstrike.sdr.fact.>"


async def run_watch(
    config: WatchConfig,
    on_alert: Callable[[Alert], None],
    on_event: Callable[[TimelineEvent], None] | None = None,
) -> WatchStats:
    """Run a live watch session against a NATS server.

    Subscribes to ``clawdstrike.sdr.fact.>``, parses spine envelopes into
    timeline events, feeds them through a :class:`CorrelationEngine`, and
    invokes *on_alert* whenever a correlation rule fires.

    Args:
        config: Watch configuration (NATS URL, rules, etc.).
        on_alert: Called for every fired alert.
        on_event: Optional callback for every parsed event.

    Returns:
        Final watch statistics.

    Raises:
        WatchError: If the ``nats`` package is not installed.
    """
    try:
        import nats as nats_pkg  # type: ignore[import-untyped]
    except ImportError as exc:
        raise WatchError(
            "The 'nats-py' package is required for watch mode. "
            "Install it with: pip install clawdstrike[hunt]"
        ) from exc

    engine = CorrelationEngine(list(config.rules))
    events_processed = 0
    alerts_triggered = 0
    start_time = datetime.now(timezone.utc)

    nc = await nats_pkg.connect(
        config.nats_url,
        **({"user_credentials": config.nats_creds} if config.nats_creds else {}),
    )

    sub = await nc.subscribe(_NATS_SUBJECT)

    try:
        async for msg in sub.messages:
            try:
                envelope = json.loads(msg.data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            if not isinstance(envelope, dict):
                continue

            event = parse_envelope(envelope)
            if event is None:
                continue

            events_processed += 1
            if on_event is not None:
                on_event(event)

            alerts = engine.process_event(event, config.max_window)
            for alert in alerts:
                alerts_triggered += 1
                on_alert(alert)
    except asyncio.CancelledError:
        pass  # Graceful shutdown: stop consuming messages and proceed to flush
    finally:
        # Flush remaining partial windows on shutdown.
        remaining = engine.flush()
        for alert in remaining:
            alerts_triggered += 1
            on_alert(alert)

        await sub.unsubscribe()
        await nc.drain()

    return WatchStats(
        events_processed=events_processed,
        alerts_triggered=alerts_triggered,
        start_time=start_time,
    )
