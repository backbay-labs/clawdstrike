"""Clawdstrike Hunt — threat hunting and timeline analysis."""

from __future__ import annotations

from clawdstrike.hunt.errors import (
    CorrelationError,
    ExportError,
    HuntAlertError,
    HuntError,
    IocError,
    IoError,
    ParseError,
    PlaybookError,
    QueryError,
    ReportError,
    WatchError,
)
from clawdstrike.hunt.correlate import (
    CorrelationEngine,
    correlate,
    load_rules_from_files,
    parse_rule,
    validate_rule,
)
from clawdstrike.hunt.ioc import (
    IocDatabase,
    detect_ioc_type,
)
from clawdstrike.hunt.local import default_local_dirs, hunt, query_local_files
from clawdstrike.hunt.query import (
    matches_query,
    parse_query_verdict,
)
from clawdstrike.hunt.report import (
    build_report,
    collect_evidence,
    evidence_from_alert,
    evidence_from_events,
    evidence_from_ioc_matches,
    sign_report,
    verify_report,
)
from clawdstrike.hunt.testing import TestResult, event, test_rule
from clawdstrike.hunt.replay import ReplayResult, replay
from clawdstrike.hunt.decorator import guarded
from clawdstrike.hunt.dataframe import (
    alerts_to_dataframe,
    display_timeline,
    to_dataframe,
    to_polars,
)
from clawdstrike.hunt.playbook import Playbook, PlaybookResult
from clawdstrike.hunt.mitre import (
    MitreTechnique,
    coverage_matrix,
    map_alert_to_mitre,
    map_event_to_mitre,
)
from clawdstrike.hunt.anomaly import (
    Baseline,
    BaselineData,
    ScoredEvent,
    score_anomalies,
)
from clawdstrike.hunt.export import to_csv, to_jsonl, to_stix
from clawdstrike.hunt.stream import StreamAlertItem, StreamEventItem
from clawdstrike.hunt.timeline import merge_timeline, parse_envelope
from clawdstrike.hunt.types import (
    Alert,
    CorrelationRule,
    EventSourceType,
    EvidenceItem,
    HuntQuery,
    HuntReport,
    IocEntry,
    IocMatch,
    IocType,
    NormalizedVerdict,
    QueryVerdict,
    RuleCondition,
    RuleOutput,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
    WatchConfig,
    WatchStats,
)

__all__ = [
    # errors
    "HuntError",
    "QueryError",
    "ParseError",
    "IoError",
    "CorrelationError",
    "IocError",
    "WatchError",
    "ReportError",
    # types / enums
    "EventSourceType",
    "TimelineEventKind",
    "NormalizedVerdict",
    "QueryVerdict",
    "RuleSeverity",
    "IocType",
    "TimelineEvent",
    "HuntQuery",
    "RuleCondition",
    "RuleOutput",
    "CorrelationRule",
    "Alert",
    "IocEntry",
    "IocMatch",
    "EvidenceItem",
    "HuntReport",
    "WatchConfig",
    "WatchStats",
    # query
    "parse_query_verdict",
    "matches_query",
    # timeline
    "parse_envelope",
    "merge_timeline",
    # local
    "default_local_dirs",
    "query_local_files",
    "hunt",
    # correlate
    "CorrelationEngine",
    "correlate",
    "parse_rule",
    "validate_rule",
    "load_rules_from_files",
    # ioc
    "IocDatabase",
    "detect_ioc_type",
    # report
    "build_report",
    "sign_report",
    "verify_report",
    "evidence_from_alert",
    "evidence_from_events",
    "evidence_from_ioc_matches",
    "collect_evidence",
    # testing
    "test_rule",
    "event",
    "TestResult",
    # replay
    "replay",
    "ReplayResult",
    # decorator
    "guarded",
    "HuntAlertError",
    "PlaybookError",
    # dataframe
    "to_dataframe",
    "to_polars",
    "alerts_to_dataframe",
    "display_timeline",
    # playbook
    "Playbook",
    "PlaybookResult",
    # mitre
    "MitreTechnique",
    "map_event_to_mitre",
    "map_alert_to_mitre",
    "coverage_matrix",
    # anomaly
    "ScoredEvent",
    "BaselineData",
    "Baseline",
    "score_anomalies",
    # export (eager — no optional deps for to_stix/to_csv/to_jsonl)
    "ExportError",
    "to_stix",
    "to_csv",
    "to_jsonl",
    # stream items (eager)
    "StreamAlertItem",
    "StreamEventItem",
    # watch / stream / export adapters (lazy import — requires optional deps)
    "run_watch",
    "stream",
    "stream_all",
    "WebhookAdapter",
    "SplunkHECAdapter",
    "ElasticAdapter",
    "ExportAdapter",
]


def __getattr__(name: str):  # type: ignore[no-untyped-def]
    """Lazy imports for modules requiring optional dependencies."""
    if name == "run_watch":
        from clawdstrike.hunt.watch import run_watch

        return run_watch
    if name == "stream":
        from clawdstrike.hunt.stream import stream

        return stream
    if name == "stream_all":
        from clawdstrike.hunt.stream import stream_all

        return stream_all
    if name == "WebhookAdapter":
        from clawdstrike.hunt.export import WebhookAdapter

        return WebhookAdapter
    if name == "SplunkHECAdapter":
        from clawdstrike.hunt.export import SplunkHECAdapter

        return SplunkHECAdapter
    if name == "ElasticAdapter":
        from clawdstrike.hunt.export import ElasticAdapter

        return ElasticAdapter
    if name == "ExportAdapter":
        from clawdstrike.hunt.export import ExportAdapter

        return ExportAdapter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
