"""Tests for Decision aggregation."""

from clawdstrike.types import Decision, DecisionStatus
from clawdstrike.guards.base import GuardResult, Severity


class TestDecision:
    def test_empty_results_is_allow(self) -> None:
        d = Decision.from_guard_results([])
        assert d.status == DecisionStatus.ALLOW
        assert d.allowed is True
        assert d.denied is False

    def test_all_allow(self) -> None:
        results = [
            GuardResult.allow("guard_a"),
            GuardResult.allow("guard_b"),
        ]
        d = Decision.from_guard_results(results)
        assert d.status == DecisionStatus.ALLOW
        assert d.allowed is True

    def test_single_deny(self) -> None:
        results = [
            GuardResult.allow("guard_a"),
            GuardResult.block("guard_b", Severity.ERROR, "blocked"),
        ]
        d = Decision.from_guard_results(results)
        assert d.status == DecisionStatus.DENY
        assert d.denied is True
        assert d.guard == "guard_b"
        assert d.message == "blocked"

    def test_multi_deny_highest_severity_wins(self) -> None:
        results = [
            GuardResult.block("guard_a", Severity.WARNING, "warn block"),
            GuardResult.block("guard_b", Severity.CRITICAL, "critical block"),
        ]
        d = Decision.from_guard_results(results)
        assert d.status == DecisionStatus.DENY
        assert d.guard == "guard_b"
        assert d.severity == Severity.CRITICAL

    def test_warn_only(self) -> None:
        results = [
            GuardResult.allow("guard_a"),
            GuardResult.warn("guard_b", "suspicious activity"),
        ]
        d = Decision.from_guard_results(results)
        assert d.status == DecisionStatus.WARN
        assert d.allowed is True
        assert d.denied is False
        assert d.guard == "guard_b"

    def test_per_guard_results_preserved(self) -> None:
        results = [
            GuardResult.allow("guard_a"),
            GuardResult.block("guard_b", Severity.ERROR, "blocked"),
        ]
        d = Decision.from_guard_results(results)
        assert len(d.per_guard) == 2
