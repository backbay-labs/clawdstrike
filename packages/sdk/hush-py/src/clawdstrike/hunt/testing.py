"""Rule testing framework for hunt correlation rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from clawdstrike.hunt.correlate import correlate, load_rules_from_files, parse_rule
from clawdstrike.hunt.types import (
    Alert,
    CorrelationRule,
    EventSourceType,
    NormalizedVerdict,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
)


@dataclass(frozen=True)
class TestResult:
    """Result of testing a correlation rule against given events."""

    passed: bool
    alerts: tuple[Alert, ...]
    events_processed: int
    mismatches: tuple[str, ...]


def event(**overrides) -> TimelineEvent:  # type: ignore[no-untyped-def]
    """Create a test event with sensible defaults.

    Any keyword arguments override the default field values.
    """
    defaults = {
        "timestamp": datetime.now(tz=timezone.utc),
        "source": EventSourceType.RECEIPT,
        "kind": TimelineEventKind.GUARD_DECISION,
        "verdict": NormalizedVerdict.ALLOW,
        "summary": "test event",
    }
    defaults.update(overrides)
    return TimelineEvent(**defaults)


def test_rule(
    rule_or_path: CorrelationRule | str,
    *,
    given: list[TimelineEvent],
    expect_alerts: int | None = None,
    expect_severity: RuleSeverity | None = None,
    expect_rule_name: str | None = None,
) -> TestResult:
    """Test a correlation rule against given events.

    *rule_or_path* may be a :class:`CorrelationRule`, a YAML string
    (detected by containing a newline), or a file path.
    """
    if isinstance(rule_or_path, str):
        if "\n" in rule_or_path:
            rule = parse_rule(rule_or_path)
        else:
            rules = load_rules_from_files([rule_or_path])
            rule = rules[0]
    else:
        rule = rule_or_path

    alerts = correlate([rule], given)
    mismatches: list[str] = []

    if expect_alerts is not None and len(alerts) != expect_alerts:
        mismatches.append(f"expected {expect_alerts} alerts, got {len(alerts)}")

    if expect_severity is not None:
        for alert in alerts:
            if alert.severity != expect_severity:
                mismatches.append(
                    f"expected severity '{expect_severity.value}', got '{alert.severity.value}'"
                )

    if expect_rule_name is not None:
        for alert in alerts:
            if alert.rule_name != expect_rule_name:
                mismatches.append(
                    f"expected rule name '{expect_rule_name}', got '{alert.rule_name}'"
                )

    return TestResult(
        passed=len(mismatches) == 0,
        alerts=tuple(alerts),
        events_processed=len(given),
        mismatches=tuple(mismatches),
    )


__all__ = [
    "TestResult",
    "event",
    "test_rule",
]
