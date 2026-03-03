"""Correlation rule parsing, validation, and sliding-window engine.

Port of ``hunt-correlate/src/rules.rs`` and ``hunt-correlate/src/engine.rs``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import yaml

from clawdstrike.hunt.duration import parse_human_duration
from clawdstrike.hunt.errors import CorrelationError
from clawdstrike.hunt.types import (
    Alert,
    CorrelationRule,
    NormalizedVerdict,
    RuleCondition,
    RuleOutput,
    RuleSeverity,
    TimelineEvent,
)

SUPPORTED_SCHEMA = "clawdstrike.hunt.correlation.v1"

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

_VERDICT_MAP: dict[str, NormalizedVerdict] = {
    "allow": NormalizedVerdict.ALLOW,
    "deny": NormalizedVerdict.DENY,
    "warn": NormalizedVerdict.WARN,
    "none": NormalizedVerdict.NONE,
    "forwarded": NormalizedVerdict.FORWARDED,
    "dropped": NormalizedVerdict.DROPPED,
}

_SEVERITY_MAP: dict[str, RuleSeverity] = {
    "low": RuleSeverity.LOW,
    "medium": RuleSeverity.MEDIUM,
    "high": RuleSeverity.HIGH,
    "critical": RuleSeverity.CRITICAL,
}


def _parse_source(val: Any, condition_index: int) -> tuple[str, ...]:
    if isinstance(val, str) and val.strip():
        return (val,)
    if isinstance(val, list):
        if val and all(isinstance(s, str) and s.strip() for s in val):
            return tuple(val)
    raise CorrelationError(
        f"condition {condition_index} has invalid 'source' "
        "(expected string or list of strings)"
    )


def _parse_optional_condition_str(
    condition: dict[str, Any],
    field: str,
    condition_index: int,
) -> str | None:
    value = condition.get(field)
    if value is None:
        return None
    if isinstance(value, str):
        return value
    raise CorrelationError(
        f"condition {condition_index} has invalid '{field}' (expected string)"
    )


def _desugar_sequence(items: list[dict]) -> list[dict]:
    """Transform a sequence shorthand into standard condition dicts.

    Each item auto-wires its ``after`` to the previous item's ``bind``
    unless explicitly overridden.
    """
    if not items:
        raise CorrelationError("sequence must have at least one item")

    conditions: list[dict] = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise CorrelationError(f"sequence item {i} must be a mapping")
        bind = item.get("bind")
        if not isinstance(bind, str) or not bind.strip():
            raise CorrelationError(
                f"sequence item {i} has invalid 'bind' (expected string)"
            )
        cond = dict(item)
        if "after" not in cond or cond["after"] is None:
            if i > 0:
                cond["after"] = items[i - 1]["bind"]
            else:
                cond.pop("after", None)
        conditions.append(cond)
    return conditions


def parse_rule(yaml_str: str) -> CorrelationRule:
    """Parse and validate a correlation rule from a YAML string."""
    try:
        raw = yaml.safe_load(yaml_str)
    except yaml.YAMLError as exc:
        raise CorrelationError(f"YAML parse error: {exc}") from exc

    if not isinstance(raw, dict):
        raise CorrelationError("rule must be a YAML mapping")

    severity_str = str(raw.get("severity", "low")).lower()
    severity = _SEVERITY_MAP.get(severity_str)
    if severity is None:
        raise CorrelationError(f"invalid severity: {severity_str}")

    window_str = str(raw.get("window", ""))
    window = parse_human_duration(window_str)
    if window is None:
        raise CorrelationError(f"invalid duration: {window_str}")
    if window <= timedelta(0):
        raise CorrelationError("window must be a positive duration")

    has_sequence = "sequence" in raw and raw["sequence"] is not None
    has_conditions = "conditions" in raw and raw["conditions"] is not None

    if has_sequence and has_conditions:
        raise CorrelationError("'sequence' and 'conditions' are mutually exclusive")

    if has_sequence:
        raw_seq = raw["sequence"]
        if not isinstance(raw_seq, list):
            raise CorrelationError("sequence must be a list")
        raw_conditions = _desugar_sequence(raw_seq)
    else:
        raw_conditions = raw.get("conditions", [])

    if not isinstance(raw_conditions, list):
        raise CorrelationError("conditions must be a list")

    conditions: list[RuleCondition] = []
    for idx, rc in enumerate(raw_conditions):
        if not isinstance(rc, dict):
            raise CorrelationError(f"condition {idx} must be a mapping")
        bind = rc.get("bind")
        if not isinstance(bind, str) or not bind.strip():
            raise CorrelationError(
                f"condition {idx} has invalid 'bind' (expected string)"
            )
        source = _parse_source(rc.get("source"), idx)
        within: timedelta | None = None
        if "within" in rc and rc["within"] is not None:
            within = parse_human_duration(str(rc["within"]))
            if within is None:
                raise CorrelationError(f"invalid duration: {rc['within']}")
            if within <= timedelta(0):
                raise CorrelationError("'within' must be a positive duration")

        conditions.append(
            RuleCondition(
                bind=bind,
                source=source,
                action_type=_parse_optional_condition_str(rc, "action_type", idx),
                verdict=_parse_optional_condition_str(rc, "verdict", idx),
                target_pattern=_parse_optional_condition_str(rc, "target_pattern", idx),
                not_target_pattern=_parse_optional_condition_str(
                    rc,
                    "not_target_pattern",
                    idx,
                ),
                after=_parse_optional_condition_str(rc, "after", idx),
                within=within,
            )
        )

    raw_output = raw.get("output", {})
    if not isinstance(raw_output, dict):
        raise CorrelationError("output must be a mapping")

    output = RuleOutput(
        title=str(raw_output.get("title", "")),
        evidence=tuple(str(e) for e in raw_output.get("evidence", [])),
    )

    rule = CorrelationRule(
        schema=str(raw.get("schema", "")),
        name=str(raw.get("name", "")),
        severity=severity,
        description=str(raw.get("description", "")),
        window=window,
        conditions=tuple(conditions),
        output=output,
    )

    validate_rule(rule)
    return rule


def validate_rule(rule: CorrelationRule) -> None:
    """Validate a parsed correlation rule, raising :class:`CorrelationError` on failure."""
    if rule.schema != SUPPORTED_SCHEMA:
        raise CorrelationError(
            f"unsupported schema '{rule.schema}', expected '{SUPPORTED_SCHEMA}'"
        )

    if not rule.conditions:
        raise CorrelationError("rule must have at least one condition")

    known_binds: list[str] = []

    for i, cond in enumerate(rule.conditions):
        if cond.after is not None:
            if cond.after not in known_binds:
                raise CorrelationError(
                    f"condition {i} references unknown bind '{cond.after}' in 'after'"
                )

        if cond.within is not None and cond.after is None:
            raise CorrelationError(
                f"condition {i} has 'within' but no 'after'; "
                "'within' only makes sense with 'after'"
            )

        if cond.within is not None and cond.within > rule.window:
            raise CorrelationError(
                f"condition {i} 'within' ({cond.within}) exceeds global window ({rule.window})"
            )

        if cond.bind in known_binds:
            raise CorrelationError(
                f"condition {i} reuses bind name '{cond.bind}'; bind names must be unique"
            )

        known_binds.append(cond.bind)

    for ev in rule.output.evidence:
        if ev not in known_binds:
            raise CorrelationError(
                f"output evidence references unknown bind '{ev}'"
            )


def load_rules_from_files(paths: list[str]) -> list[CorrelationRule]:
    """Load and validate correlation rules from YAML files."""
    rules: list[CorrelationRule] = []
    for path in paths:
        try:
            with open(path) as f:
                content = f.read()
        except OSError as exc:
            raise CorrelationError(f"failed to read {path}: {exc}") from exc
        rules.append(parse_rule(content))
    return rules


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------


@dataclass
class _CompiledPatterns:
    target: re.Pattern[str] | None = None
    not_target: re.Pattern[str] | None = None


# ---------------------------------------------------------------------------
# Window state
# ---------------------------------------------------------------------------


@dataclass
class _WindowState:
    started_at: datetime
    bound_events: dict[str, list[TimelineEvent]]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def _condition_matches(
    cond: RuleCondition,
    cp: _CompiledPatterns,
    event: TimelineEvent,
) -> bool:
    """Check if a single condition matches a timeline event."""
    # Source check
    event_source_str = event.source.value.lower()
    if not any(s.lower() == event_source_str for s in cond.source):
        return False

    # Action type (case-insensitive)
    if cond.action_type is not None:
        if event.action_type is None:
            return False
        if event.action_type.lower() != cond.action_type.lower():
            return False

    # Verdict
    if cond.verdict is not None:
        expected = _VERDICT_MAP.get(cond.verdict.lower())
        if expected is None:
            return False
        if event.verdict != expected:
            return False

    # Target pattern
    if cp.target is not None:
        if not cp.target.search(event.summary):
            return False

    # Not target pattern
    if cp.not_target is not None:
        if cp.not_target.search(event.summary):
            return False

    return True


def _all_conditions_met(rule: CorrelationRule, ws: _WindowState) -> bool:
    return all(
        cond.bind in ws.bound_events and len(ws.bound_events[cond.bind]) > 0
        for cond in rule.conditions
    )


def _build_alert(rule: CorrelationRule, ws: _WindowState) -> Alert:
    evidence: list[TimelineEvent] = []
    for bind_name in rule.output.evidence:
        evts = ws.bound_events.get(bind_name)
        if evts is not None:
            evidence.extend(evts)

    triggered_at = max((e.timestamp for e in evidence), default=datetime.now(tz=timezone.utc))

    return Alert(
        rule_name=rule.name,
        severity=rule.severity,
        title=rule.output.title,
        triggered_at=triggered_at,
        evidence=tuple(evidence),
        description=rule.description,
    )


class CorrelationEngine:
    """Sliding-window correlation engine that evaluates events against rules."""

    def __init__(self, rules: list[CorrelationRule]) -> None:
        self._rules = tuple(rules)
        self._patterns: dict[tuple[int, int], _CompiledPatterns] = {}
        self._windows: dict[int, list[_WindowState]] = {}

        for ri, rule in enumerate(self._rules):
            for ci, cond in enumerate(rule.conditions):
                target = None
                not_target = None
                if cond.target_pattern is not None:
                    try:
                        target = re.compile(cond.target_pattern)
                    except re.error as exc:
                        raise CorrelationError(
                            f"rule '{rule.name}' condition {ci}: {exc}"
                        ) from exc
                if cond.not_target_pattern is not None:
                    try:
                        not_target = re.compile(cond.not_target_pattern)
                    except re.error as exc:
                        raise CorrelationError(
                            f"rule '{rule.name}' condition {ci} not_target: {exc}"
                        ) from exc
                self._patterns[(ri, ci)] = _CompiledPatterns(target=target, not_target=not_target)

    @property
    def rules(self) -> tuple[CorrelationRule, ...]:
        return self._rules

    def process_event(
        self,
        event: TimelineEvent,
        max_window: timedelta | None = None,
    ) -> list[Alert]:
        """Process a single event. Returns alerts generated."""
        if max_window is not None:
            self._evict_expired_at_capped(event.timestamp, max_window)
        else:
            self._evict_expired_at(event.timestamp)

        alerts: list[Alert] = []
        for ri in range(len(self._rules)):
            alerts.extend(self._evaluate_rule(ri, event))
        return alerts

    def evict(self, max_window: timedelta | None = None) -> None:
        """Evict expired windows, optionally capping at *max_window*."""
        if max_window is not None:
            self._evict_expired_capped(max_window)
        else:
            self._evict_expired()

    def _evict_expired_at(self, now: datetime) -> None:
        """Remove windows older than their rule's window duration."""
        to_remove: list[int] = []
        for ri, windows in self._windows.items():
            window_dur = self._rules[ri].window
            self._windows[ri] = [
                ws for ws in windows
                if (now - ws.started_at) <= window_dur
            ]
            if not self._windows[ri]:
                to_remove.append(ri)
        for ri in to_remove:
            del self._windows[ri]

    def _evict_expired(self) -> None:
        """Evict expired windows using wall-clock time."""
        self._evict_expired_at(datetime.now(tz=timezone.utc))

    def _evict_expired_at_capped(self, now: datetime, max_window: timedelta) -> None:
        """Evict using the shorter of each rule window and *max_window* at a specific time."""
        to_remove: list[int] = []
        for ri, windows in self._windows.items():
            rule_dur = self._rules[ri].window
            effective = min(max_window, rule_dur)
            self._windows[ri] = [
                ws for ws in windows
                if (now - ws.started_at) <= effective
            ]
            if not self._windows[ri]:
                to_remove.append(ri)
        for ri in to_remove:
            del self._windows[ri]

    def _evict_expired_capped(self, max_window: timedelta) -> None:
        """Evict windows using the shorter of rule window and *max_window*."""
        self._evict_expired_at_capped(datetime.now(tz=timezone.utc), max_window)

    def flush(self, as_of: datetime | None = None) -> list[Alert]:
        """Flush all windows, returning alerts for fully-matched ones.

        When *as_of* is provided, eviction uses that timestamp instead of
        wall-clock time — critical for deterministic replay of historical data.
        """
        if as_of is not None:
            self._evict_expired_at(as_of)
        else:
            self._evict_expired()
        alerts: list[Alert] = []
        for ri, windows in list(self._windows.items()):
            rule = self._rules[ri]
            for ws in windows:
                if _all_conditions_met(rule, ws):
                    alerts.append(_build_alert(rule, ws))
        self._windows.clear()
        return alerts

    def _evaluate_rule(self, ri: int, event: TimelineEvent) -> list[Alert]:
        rule = self._rules[ri]

        # Snapshot pre-existing window count
        pre_existing_count = len(self._windows.get(ri, []))
        dependent_advanced = [False] * pre_existing_count

        for ci, cond in enumerate(rule.conditions):
            cp = self._patterns.get((ri, ci))
            if cp is None:
                continue

            if not _condition_matches(cond, cp, event):
                continue

            if cond.after is None:
                # Root condition: create new window
                ws = _WindowState(
                    started_at=event.timestamp,
                    bound_events={cond.bind: [event]},
                )
                self._windows.setdefault(ri, []).append(ws)
            else:
                # Dependent condition: advance existing windows
                if pre_existing_count == 0:
                    continue

                windows = self._windows.get(ri)
                if windows is None:
                    continue

                for wi in range(min(pre_existing_count, len(windows))):
                    ws = windows[wi]

                    # Single event advances at most one dependent per window
                    if wi < len(dependent_advanced) and dependent_advanced[wi]:
                        continue

                    # Skip if already bound
                    if cond.bind in ws.bound_events:
                        continue

                    # Check prerequisite
                    after_events = ws.bound_events.get(cond.after)
                    if not after_events:
                        continue

                    # Time ordering: event must be >= prerequisite timestamp
                    # Use the last event from the prerequisite bind.
                    after_event = after_events[-1]
                    elapsed = event.timestamp - after_event.timestamp
                    if elapsed < timedelta(0):
                        continue

                    # Within constraint
                    if cond.within is not None and elapsed > cond.within:
                        continue

                    # Bind event
                    ws.bound_events.setdefault(cond.bind, []).append(event)
                    if wi < len(dependent_advanced):
                        dependent_advanced[wi] = True

        # Check for fully matched windows
        alerts: list[Alert] = []
        windows = self._windows.get(ri)
        if windows is not None:
            completed: list[int] = []
            for wi, ws in enumerate(windows):
                if _all_conditions_met(rule, ws):
                    alerts.append(_build_alert(rule, ws))
                    completed.append(wi)

            for wi in reversed(completed):
                windows.pop(wi)
            if not windows:
                self._windows.pop(ri, None)

        return alerts


def correlate(rules: list[CorrelationRule], events: list[TimelineEvent]) -> list[Alert]:
    """High-level correlation: create an engine, process all events, flush, and return alerts."""
    engine = CorrelationEngine(rules)
    alerts: list[Alert] = []
    for event in events:
        alerts.extend(engine.process_event(event))
    # Use last event's timestamp for deterministic replay instead of wall-clock.
    as_of = events[-1].timestamp if events else None
    alerts.extend(engine.flush(as_of=as_of))
    return alerts


__all__ = [
    "SUPPORTED_SCHEMA",
    "parse_rule",
    "validate_rule",
    "load_rules_from_files",
    "CorrelationEngine",
    "correlate",
]
