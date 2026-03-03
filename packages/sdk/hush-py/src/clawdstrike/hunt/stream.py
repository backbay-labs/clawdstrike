"""Async streaming for Hunt SDK -- yields events and alerts from NATS."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import AsyncIterator, Union

from clawdstrike.hunt.correlate import CorrelationEngine
from clawdstrike.hunt.errors import WatchError
from clawdstrike.hunt.timeline import parse_envelope
from clawdstrike.hunt.types import Alert, TimelineEvent, WatchConfig

_NATS_SUBJECT = "clawdstrike.sdr.fact.>"


@dataclass(frozen=True)
class StreamAlertItem:
    """A stream item wrapping an alert."""

    type: str
    alert: Alert


@dataclass(frozen=True)
class StreamEventItem:
    """A stream item wrapping a timeline event."""

    type: str
    event: TimelineEvent


StreamItem = Union[StreamAlertItem, StreamEventItem]


async def stream(config: WatchConfig) -> AsyncIterator[Alert]:
    """Stream alerts from NATS as an async iterator.

    Subscribes to ``clawdstrike.sdr.fact.>``, parses spine envelopes into
    timeline events, feeds them through a :class:`CorrelationEngine`, and
    yields alerts when correlation rules fire.

    Args:
        config: Watch configuration (NATS URL, rules, etc.).

    Yields:
        Alerts from the correlation engine.

    Raises:
        WatchError: If the ``nats-py`` package is not installed.
    """
    try:
        import nats as nats_mod  # type: ignore[import-untyped]
    except ImportError as exc:
        raise WatchError(
            "The 'nats-py' package is required for streaming. "
            "Install it with: pip install nats-py"
        ) from exc

    engine = CorrelationEngine(list(config.rules))
    nc = await nats_mod.connect(
        config.nats_url,
        **({"user_credentials": config.nats_creds} if config.nats_creds else {}),
    )
    sub = await nc.subscribe(_NATS_SUBJECT)

    try:
        async for msg in sub.messages:
            try:
                envelope = json.loads(msg.data.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(envelope, dict):
                continue

            event = parse_envelope(envelope)
            if event is None:
                continue

            alerts = engine.process_event(event, config.max_window)
            for alert in alerts:
                yield alert
    finally:
        await nc.drain()


async def stream_all(config: WatchConfig) -> AsyncIterator[StreamItem]:
    """Stream all items (events and alerts) from NATS as an async iterator.

    Like :func:`stream`, but yields both events and alerts as tagged
    :class:`StreamItem` objects.

    Args:
        config: Watch configuration (NATS URL, rules, etc.).

    Yields:
        :class:`StreamEventItem` for each parsed event and
        :class:`StreamAlertItem` for each fired alert.

    Raises:
        WatchError: If the ``nats-py`` package is not installed.
    """
    try:
        import nats as nats_mod  # type: ignore[import-untyped]
    except ImportError as exc:
        raise WatchError(
            "The 'nats-py' package is required for streaming. "
            "Install it with: pip install nats-py"
        ) from exc

    engine = CorrelationEngine(list(config.rules))
    nc = await nats_mod.connect(
        config.nats_url,
        **({"user_credentials": config.nats_creds} if config.nats_creds else {}),
    )
    sub = await nc.subscribe(_NATS_SUBJECT)

    try:
        async for msg in sub.messages:
            try:
                envelope = json.loads(msg.data.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(envelope, dict):
                continue

            event = parse_envelope(envelope)
            if event is None:
                continue

            yield StreamEventItem(type="event", event=event)

            alerts = engine.process_event(event, config.max_window)
            for alert in alerts:
                yield StreamAlertItem(type="alert", alert=alert)
    finally:
        await nc.drain()


__all__ = [
    "stream",
    "stream_all",
    "StreamItem",
    "StreamAlertItem",
    "StreamEventItem",
]
