"""Decorator-based guarding for Hunt SDK.

Wraps functions with correlation-based security checks.
"""

from __future__ import annotations

import functools
import inspect
from datetime import datetime, timezone

from clawdstrike.hunt.correlate import CorrelationEngine
from clawdstrike.hunt.errors import HuntAlertError
from clawdstrike.hunt.types import (
    Alert,
    CorrelationRule,
    EventSourceType,
    NormalizedVerdict,
    TimelineEvent,
    TimelineEventKind,
)


def guarded(
    rules: list[CorrelationRule], *, on_alert: str = "deny"
):
    """Decorator that wraps a function with correlation-based guarding.

    Parameters
    ----------
    rules:
        Correlation rules to evaluate on each call.
    on_alert:
        ``"deny"`` (default) raises :class:`HuntAlertError`.
        ``"log"`` silently collects alerts on the wrapper's ``.alerts`` list.
    """
    if on_alert not in ("deny", "log"):
        raise ValueError("on_alert must be 'deny' or 'log'")

    engine = CorrelationEngine(rules)
    collected_alerts: list[Alert] = []

    def decorator(fn):
        def _make_event() -> TimelineEvent:
            return TimelineEvent(
                timestamp=datetime.now(tz=timezone.utc),
                source=EventSourceType.RECEIPT,
                kind=TimelineEventKind.GUARD_DECISION,
                verdict=NormalizedVerdict.ALLOW,
                summary=f"guarded call: {fn.__name__}",
                action_type="function_call",
                process=fn.__name__,
            )

        def _handle_alerts(alerts: list[Alert]) -> None:
            if alerts:
                if on_alert == "deny":
                    raise HuntAlertError(f"Alert triggered: {alerts[0].title}")
                collected_alerts.extend(alerts)

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                event = _make_event()
                alerts = engine.process_event(event)
                _handle_alerts(alerts)
                return await fn(*args, **kwargs)

            async_wrapper.alerts = collected_alerts  # type: ignore[attr-defined]
            return async_wrapper
        else:

            @functools.wraps(fn)
            def sync_wrapper(*args, **kwargs):
                event = _make_event()
                alerts = engine.process_event(event)
                _handle_alerts(alerts)
                return fn(*args, **kwargs)

            sync_wrapper.alerts = collected_alerts  # type: ignore[attr-defined]
            return sync_wrapper

    return decorator


__all__ = ["guarded"]
