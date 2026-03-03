"""Tests for clawdstrike.hunt.stream module."""

from __future__ import annotations

import inspect
import json
import sys
from datetime import datetime, timedelta, timezone

import pytest

from clawdstrike.hunt.errors import WatchError
from clawdstrike.hunt.stream import StreamAlertItem, StreamEventItem, stream, stream_all
from clawdstrike.hunt.types import (
    Alert,
    EventSourceType,
    NormalizedVerdict,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
    WatchConfig,
)


def _make_event() -> TimelineEvent:
    return TimelineEvent(
        timestamp=datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        source=EventSourceType.TETRAGON,
        kind=TimelineEventKind.PROCESS_EXEC,
        verdict=NormalizedVerdict.ALLOW,
        summary="ls executed",
    )


def _make_alert() -> Alert:
    return Alert(
        rule_name="test-rule",
        severity=RuleSeverity.HIGH,
        title="Test Alert",
        triggered_at=datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        evidence=(_make_event(),),
        description="test description",
    )


def _make_config() -> WatchConfig:
    return WatchConfig(
        nats_url="nats://localhost:4222",
        rules=(),
        max_window=timedelta(seconds=60),
    )


class TestStream:
    """Tests for the stream function."""

    def test_import_succeeds(self) -> None:
        """Verify the module and function are importable."""
        assert callable(stream)

    @pytest.mark.asyncio
    async def test_raises_without_nats(self) -> None:
        """stream should raise WatchError if nats-py is not installed."""
        try:
            import nats  # noqa: F401

            pytest.skip("nats-py is installed; cannot test missing-package path")
        except ImportError:
            pass  # nats-py not installed, expected

        config = _make_config()
        with pytest.raises(WatchError, match="nats-py"):
            async for _ in stream(config):
                pass

    def test_stream_is_async_generator_function(self) -> None:
        """stream should be an async generator function."""
        assert inspect.isasyncgenfunction(stream)

    @pytest.mark.asyncio
    async def test_stream_passes_max_window_to_process_event(self, monkeypatch) -> None:
        import clawdstrike.hunt.stream as stream_mod

        fake_event = _make_event()
        engine_calls: list[tuple[TimelineEvent, timedelta | None]] = []
        evict_calls = 0

        class _FakeEngine:
            def __init__(self, _rules) -> None:
                pass

            def process_event(
                self,
                event: TimelineEvent,
                max_window: timedelta | None = None,
            ) -> list[Alert]:
                engine_calls.append((event, max_window))
                return []

            def evict(self, _max_window: timedelta | None = None) -> None:
                nonlocal evict_calls
                evict_calls += 1

        class _FakeMsg:
            def __init__(self, data: bytes) -> None:
                self.data = data

        class _FakeSub:
            def __init__(self, items: list[bytes]) -> None:
                async def _iter():
                    for item in items:
                        yield _FakeMsg(item)
                self.messages = _iter()

        class _FakeNc:
            async def subscribe(self, _subject: str):
                return _FakeSub([json.dumps({"kind": "event"}).encode()])

            async def drain(self) -> None:
                return None

        class _FakeNats:
            @staticmethod
            async def connect(*_args, **_kwargs):
                return _FakeNc()

        monkeypatch.setitem(sys.modules, "nats", _FakeNats)
        monkeypatch.setattr(stream_mod, "CorrelationEngine", _FakeEngine)
        monkeypatch.setattr(stream_mod, "parse_envelope", lambda _env: fake_event)

        async for _ in stream_mod.stream(_make_config()):
            pass

        assert engine_calls == [(fake_event, timedelta(seconds=60))]
        assert evict_calls == 0


class TestStreamAll:
    """Tests for the stream_all function."""

    def test_import_succeeds(self) -> None:
        """Verify the module and function are importable."""
        assert callable(stream_all)

    @pytest.mark.asyncio
    async def test_raises_without_nats(self) -> None:
        """stream_all should raise WatchError if nats-py is not installed."""
        try:
            import nats  # noqa: F401

            pytest.skip("nats-py is installed; cannot test missing-package path")
        except ImportError:
            pass  # nats-py not installed, expected

        config = _make_config()
        with pytest.raises(WatchError, match="nats-py"):
            async for _ in stream_all(config):
                pass

    def test_stream_all_is_async_generator_function(self) -> None:
        """stream_all should be an async generator function."""
        assert inspect.isasyncgenfunction(stream_all)

    @pytest.mark.asyncio
    async def test_stream_all_passes_max_window_to_process_event(self, monkeypatch) -> None:
        import clawdstrike.hunt.stream as stream_mod

        fake_event = _make_event()
        engine_calls: list[tuple[TimelineEvent, timedelta | None]] = []
        evict_calls = 0

        class _FakeEngine:
            def __init__(self, _rules) -> None:
                pass

            def process_event(
                self,
                event: TimelineEvent,
                max_window: timedelta | None = None,
            ) -> list[Alert]:
                engine_calls.append((event, max_window))
                return []

            def evict(self, _max_window: timedelta | None = None) -> None:
                nonlocal evict_calls
                evict_calls += 1

        class _FakeMsg:
            def __init__(self, data: bytes) -> None:
                self.data = data

        class _FakeSub:
            def __init__(self, items: list[bytes]) -> None:
                async def _iter():
                    for item in items:
                        yield _FakeMsg(item)
                self.messages = _iter()

        class _FakeNc:
            async def subscribe(self, _subject: str):
                return _FakeSub([json.dumps({"kind": "event"}).encode()])

            async def drain(self) -> None:
                return None

        class _FakeNats:
            @staticmethod
            async def connect(*_args, **_kwargs):
                return _FakeNc()

        monkeypatch.setitem(sys.modules, "nats", _FakeNats)
        monkeypatch.setattr(stream_mod, "CorrelationEngine", _FakeEngine)
        monkeypatch.setattr(stream_mod, "parse_envelope", lambda _env: fake_event)

        items = []
        async for item in stream_mod.stream_all(_make_config()):
            items.append(item)

        assert len(items) == 1
        assert items[0].type == "event"
        assert engine_calls == [(fake_event, timedelta(seconds=60))]
        assert evict_calls == 0

    @pytest.mark.asyncio
    async def test_stream_all_skips_non_object_json_payloads(self, monkeypatch) -> None:
        """Valid JSON payloads that are not objects should be ignored safely."""
        valid_envelope = {
            "issued_at": "2025-01-15T10:00:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.receipt.v1",
                "decision": "allow",
                "guard": "test",
            },
        }
        payloads = [
            b'"not-an-object"',
            json.dumps(valid_envelope).encode(),
        ]

        class _FakeMsg:
            def __init__(self, data: bytes) -> None:
                self.data = data

        class _FakeSub:
            def __init__(self, items: list[bytes]) -> None:
                async def _iter():
                    for item in items:
                        yield _FakeMsg(item)
                self.messages = _iter()

        class _FakeNc:
            async def subscribe(self, _subject: str):
                return _FakeSub(payloads)

            async def drain(self) -> None:
                return None

        class _FakeNats:
            @staticmethod
            async def connect(*_args, **_kwargs):
                return _FakeNc()

        monkeypatch.setitem(sys.modules, "nats", _FakeNats)

        items = []
        async for item in stream_all(_make_config()):
            items.append(item)

        assert len(items) == 1
        assert items[0].type == "event"


class TestStreamItems:
    """Tests for StreamAlertItem and StreamEventItem dataclasses."""

    def test_stream_alert_item_construction(self) -> None:
        alert = _make_alert()
        item = StreamAlertItem(type="alert", alert=alert)
        assert item.type == "alert"
        assert item.alert.rule_name == "test-rule"

    def test_stream_event_item_construction(self) -> None:
        event = _make_event()
        item = StreamEventItem(type="event", event=event)
        assert item.type == "event"
        assert item.event.summary == "ls executed"

    def test_stream_items_are_frozen(self) -> None:
        event = _make_event()
        item = StreamEventItem(type="event", event=event)
        with pytest.raises(AttributeError):
            item.type = "alert"  # type: ignore[misc]
