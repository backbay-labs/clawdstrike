"""Tests for clawdstrike.hunt.decorator — guarded function wrapper."""

from __future__ import annotations

import asyncio

import pytest

from clawdstrike.hunt.correlate import parse_rule
from clawdstrike.hunt.decorator import guarded
from clawdstrike.hunt.errors import HuntAlertError
from clawdstrike.hunt.types import CorrelationRule


MATCHING_RULE_YAML = """\
schema: clawdstrike.hunt.correlation.v1
name: "Guard Call Alert"
severity: high
description: "Fires on any guarded function call"
window: 5m
conditions:
  - source: receipt
    action_type: function_call
    bind: fn_call
output:
  title: "Guarded function invoked"
  evidence:
    - fn_call
"""

NON_MATCHING_RULE_YAML = """\
schema: clawdstrike.hunt.correlation.v1
name: "Non-matching rule"
severity: low
description: "Does not match guarded calls"
window: 5m
conditions:
  - source: tetragon
    action_type: process
    verdict: deny
    bind: proc
output:
  title: "Process denied"
  evidence:
    - proc
"""


def _matching_rule() -> CorrelationRule:
    return parse_rule(MATCHING_RULE_YAML)


def _non_matching_rule() -> CorrelationRule:
    return parse_rule(NON_MATCHING_RULE_YAML)


class TestGuardedSync:
    def test_sync_function_runs_normally_when_no_alert(self) -> None:
        @guarded(rules=[_non_matching_rule()])
        def add(a: int, b: int) -> int:
            return a + b

        assert add(2, 3) == 5

    def test_raises_hunt_alert_error_in_deny_mode(self) -> None:
        @guarded(rules=[_matching_rule()], on_alert="deny")
        def do_something() -> int:
            return 42

        with pytest.raises(HuntAlertError, match="Alert triggered"):
            do_something()

    def test_collects_alerts_in_log_mode(self) -> None:
        @guarded(rules=[_matching_rule()], on_alert="log")
        def do_something() -> int:
            return 42

        result = do_something()
        assert result == 42
        assert len(do_something.alerts) > 0
        assert do_something.alerts[0].title == "Guarded function invoked"

    def test_alerts_property_returns_collected_alerts(self) -> None:
        @guarded(rules=[_matching_rule()], on_alert="log")
        def do_something() -> int:
            return 1

        assert len(do_something.alerts) == 0
        do_something()
        assert len(do_something.alerts) > 0

    def test_function_name_preserved(self) -> None:
        @guarded(rules=[])
        def my_function() -> int:
            return 1

        assert my_function.__name__ == "my_function"

    def test_arguments_passed_through(self) -> None:
        @guarded(rules=[_non_matching_rule()])
        def concat(a: str, b: str) -> str:
            return a + b

        assert concat("hello", " world") == "hello world"

    def test_return_value_preserved(self) -> None:
        @guarded(rules=[_non_matching_rule()])
        def get_obj() -> dict:
            return {"key": "value"}

        assert get_obj() == {"key": "value"}

    def test_defaults_to_deny_mode(self) -> None:
        @guarded(rules=[_matching_rule()])
        def do_something() -> int:
            return 42

        with pytest.raises(HuntAlertError):
            do_something()


class TestGuardedAsync:
    def test_async_function_runs_normally_when_no_alert(self) -> None:
        @guarded(rules=[_non_matching_rule()])
        async def async_add(a: int, b: int) -> int:
            return a + b

        result = asyncio.run(async_add(2, 3))
        assert result == 5

    def test_async_return_value_preserved(self) -> None:
        @guarded(rules=[_non_matching_rule()])
        async def get_obj_async() -> dict:
            return {"key": "value"}

        result = asyncio.run(get_obj_async())
        assert result == {"key": "value"}


class TestGuardedValidation:
    def test_invalid_on_alert_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="on_alert must be"):
            @guarded(rules=[], on_alert="invalid")
            def noop() -> None:
                pass
