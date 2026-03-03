"""Shared types for the hunt subpackage."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any


class EventSourceType(str, Enum):
    """Source system for events."""

    TETRAGON = "tetragon"
    HUBBLE = "hubble"
    RECEIPT = "receipt"
    SCAN = "scan"


class TimelineEventKind(str, Enum):
    """Classification of timeline events."""

    PROCESS_EXEC = "process_exec"
    PROCESS_EXIT = "process_exit"
    PROCESS_KPROBE = "process_kprobe"
    NETWORK_FLOW = "network_flow"
    GUARD_DECISION = "guard_decision"
    SCAN_RESULT = "scan_result"


class NormalizedVerdict(str, Enum):
    """Normalized verdict across all event sources."""

    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    NONE = "none"
    FORWARDED = "forwarded"
    DROPPED = "dropped"


class QueryVerdict(str, Enum):
    """Verdict filter for queries.

    .. deprecated::
        Use :class:`NormalizedVerdict` instead. Will be removed in a future release.
    """

    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    FORWARDED = "forwarded"
    DROPPED = "dropped"


class RuleSeverity(str, Enum):
    """Severity level for correlation rules."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IocType(str, Enum):
    """Type of indicator of compromise."""

    SHA256 = "sha256"
    SHA1 = "sha1"
    MD5 = "md5"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    URL = "url"


@dataclass(frozen=True)
class TimelineEvent:
    """A single event in the reconstructed timeline."""

    timestamp: datetime
    source: EventSourceType
    kind: TimelineEventKind
    verdict: NormalizedVerdict
    summary: str
    severity: str | None = None
    process: str | None = None
    namespace: str | None = None
    pod: str | None = None
    action_type: str | None = None
    signature_valid: bool | None = None
    raw: Any | None = None


@dataclass(frozen=True)
class HuntQuery:
    """Structured query over historical events."""

    sources: tuple[EventSourceType, ...] = ()
    verdict: NormalizedVerdict | None = None
    start: datetime | None = None
    end: datetime | None = None
    action_type: str | None = None
    process: str | None = None
    namespace: str | None = None
    pod: str | None = None
    limit: int = 100
    entity: str | None = None


@dataclass(frozen=True)
class RuleCondition:
    """A single condition within a correlation rule."""

    bind: str
    source: tuple[str, ...] = ()
    action_type: str | None = None
    verdict: str | None = None
    target_pattern: str | None = None
    not_target_pattern: str | None = None
    after: str | None = None
    within: timedelta | None = None


@dataclass(frozen=True)
class RuleOutput:
    """Output specification for a correlation rule."""

    title: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class CorrelationRule:
    """A correlation rule definition."""

    schema: str
    name: str
    severity: RuleSeverity
    description: str
    window: timedelta
    conditions: tuple[RuleCondition, ...]
    output: RuleOutput


@dataclass(frozen=True)
class Alert:
    """An alert triggered by a correlation rule."""

    rule_name: str
    severity: RuleSeverity
    title: str
    triggered_at: datetime
    evidence: tuple[TimelineEvent, ...]
    description: str


@dataclass(frozen=True)
class IocEntry:
    """An indicator of compromise entry."""

    indicator: str
    ioc_type: IocType
    description: str | None = None
    source: str | None = None


@dataclass(frozen=True)
class IocMatch:
    """A match between an event and IOC entries."""

    event: TimelineEvent
    matched_iocs: tuple[IocEntry, ...]
    match_field: str


@dataclass(frozen=True)
class EvidenceItem:
    """A single piece of evidence in a hunt report."""

    index: int
    source_type: str
    timestamp: datetime
    summary: str
    data: dict[str, Any]


@dataclass(frozen=True)
class HuntReport:
    """A hunt report with evidence and cryptographic proofs."""

    title: str
    generated_at: datetime
    evidence: tuple[EvidenceItem, ...]
    merkle_root: str
    merkle_proofs: tuple[str, ...]
    signature: str | None = None
    signer: str | None = None


@dataclass(frozen=True)
class WatchConfig:
    """Configuration for the watch subscription mode."""

    nats_url: str
    rules: tuple[CorrelationRule, ...]
    max_window: timedelta
    nats_creds: str | None = None


@dataclass(frozen=True)
class WatchStats:
    """Runtime statistics for a watch session."""

    events_processed: int
    alerts_triggered: int
    start_time: datetime
