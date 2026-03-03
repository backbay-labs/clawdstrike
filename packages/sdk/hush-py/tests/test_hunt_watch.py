"""Tests for clawdstrike.hunt.watch module."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from clawdstrike.hunt.errors import WatchError
from clawdstrike.hunt.types import (
    EventSourceType,
    NormalizedVerdict,
    TimelineEvent,
    TimelineEventKind,
    WatchConfig,
)


class TestRunWatch:
    """Tests for run_watch function."""

    def test_import_succeeds(self) -> None:
        """Verify the module and function are importable."""
        from clawdstrike.hunt.watch import run_watch

        assert callable(run_watch)

    @pytest.mark.asyncio
    async def test_raises_without_nats(self) -> None:
        """run_watch should raise WatchError if nats-py is not installed."""
        # nats-py is an optional dependency and likely not installed in test env.
        try:
            import nats  # noqa: F401

            pytest.skip("nats-py is installed; cannot test missing-package path")
        except ImportError:
            pass  # nats-py not installed, proceed to test the missing-package error path

        from clawdstrike.hunt.watch import run_watch

        config = WatchConfig(
            nats_url="nats://localhost:4222",
            rules=(),
            max_window=__import__("datetime").timedelta(seconds=60),
        )

        with pytest.raises(WatchError, match="nats-py"):
            await run_watch(config, on_alert=lambda _: None)

    @pytest.mark.asyncio
    async def test_passes_max_window_into_event_time_processing(self, monkeypatch) -> None:
        import clawdstrike.hunt.watch as watch_mod

        fake_event = TimelineEvent(
            timestamp=datetime(2025, 1, 1, tzinfo=timezone.utc),
            source=EventSourceType.RECEIPT,
            kind=TimelineEventKind.PROCESS_EXEC,
            verdict=NormalizedVerdict.ALLOW,
            summary="ok",
        )

        class FakeSub:
            def __init__(self) -> None:
                self.messages = self._iter()

            async def _iter(self):
                payload = json.dumps({"type": "event"}).encode("utf-8")
                yield SimpleNamespace(data=payload)

            async def unsubscribe(self) -> None:
                return None

        class FakeNC:
            def __init__(self) -> None:
                self.sub = FakeSub()

            async def subscribe(self, _subject: str):
                return self.sub

            async def drain(self) -> None:
                return None

        async def fake_connect(*_args, **_kwargs):
            return FakeNC()

        engine_calls: list[tuple[TimelineEvent, timedelta | None]] = []

        class FakeEngine:
            def __init__(self, _rules) -> None:
                pass

            def process_event(
                self,
                event: TimelineEvent,
                max_window: timedelta | None = None,
            ) -> list:
                engine_calls.append((event, max_window))
                return []

            def flush(self) -> list:
                return []

        monkeypatch.setitem(sys.modules, "nats", SimpleNamespace(connect=fake_connect))
        monkeypatch.setattr(watch_mod, "CorrelationEngine", FakeEngine)
        monkeypatch.setattr(watch_mod, "parse_envelope", lambda _envelope: fake_event)

        config = WatchConfig(
            nats_url="nats://localhost:4222",
            rules=(),
            max_window=timedelta(seconds=30),
        )
        stats = await watch_mod.run_watch(config, on_alert=lambda _: None)

        assert stats.events_processed == 1
        assert engine_calls == [(fake_event, timedelta(seconds=30))]
