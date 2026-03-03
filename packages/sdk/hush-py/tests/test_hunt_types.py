"""Tests for clawdstrike.hunt.types."""

from datetime import datetime, timedelta, timezone

from clawdstrike.hunt.types import (
    Alert,
    CorrelationRule,
    EventSourceType,
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


class TestEventSourceType:
    def test_values(self) -> None:
        assert EventSourceType.TETRAGON == "tetragon"
        assert EventSourceType.HUBBLE == "hubble"
        assert EventSourceType.RECEIPT == "receipt"
        assert EventSourceType.SCAN == "scan"

    def test_is_str(self) -> None:
        assert isinstance(EventSourceType.TETRAGON, str)


class TestTimelineEventKind:
    def test_values(self) -> None:
        assert TimelineEventKind.PROCESS_EXEC == "process_exec"
        assert TimelineEventKind.PROCESS_EXIT == "process_exit"
        assert TimelineEventKind.PROCESS_KPROBE == "process_kprobe"
        assert TimelineEventKind.NETWORK_FLOW == "network_flow"
        assert TimelineEventKind.GUARD_DECISION == "guard_decision"
        assert TimelineEventKind.SCAN_RESULT == "scan_result"


class TestNormalizedVerdict:
    def test_values(self) -> None:
        assert NormalizedVerdict.ALLOW == "allow"
        assert NormalizedVerdict.DENY == "deny"
        assert NormalizedVerdict.WARN == "warn"
        assert NormalizedVerdict.NONE == "none"
        assert NormalizedVerdict.FORWARDED == "forwarded"
        assert NormalizedVerdict.DROPPED == "dropped"


class TestQueryVerdict:
    def test_values(self) -> None:
        assert QueryVerdict.ALLOW == "allow"
        assert QueryVerdict.DENY == "deny"
        assert QueryVerdict.WARN == "warn"
        assert QueryVerdict.FORWARDED == "forwarded"
        assert QueryVerdict.DROPPED == "dropped"


class TestRuleSeverity:
    def test_values(self) -> None:
        assert RuleSeverity.LOW == "low"
        assert RuleSeverity.MEDIUM == "medium"
        assert RuleSeverity.HIGH == "high"
        assert RuleSeverity.CRITICAL == "critical"


class TestIocType:
    def test_values(self) -> None:
        assert IocType.SHA256 == "sha256"
        assert IocType.SHA1 == "sha1"
        assert IocType.MD5 == "md5"
        assert IocType.DOMAIN == "domain"
        assert IocType.IPV4 == "ipv4"
        assert IocType.IPV6 == "ipv6"
        assert IocType.URL == "url"


class TestTimelineEvent:
    def test_creation(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = TimelineEvent(
            timestamp=ts,
            source=EventSourceType.TETRAGON,
            kind=TimelineEventKind.PROCESS_EXEC,
            verdict=NormalizedVerdict.ALLOW,
            summary="process_exec /usr/bin/curl",
        )
        assert event.timestamp == ts
        assert event.source == EventSourceType.TETRAGON
        assert event.kind == TimelineEventKind.PROCESS_EXEC
        assert event.verdict == NormalizedVerdict.ALLOW
        assert event.summary == "process_exec /usr/bin/curl"
        assert event.severity is None
        assert event.process is None
        assert event.raw is None

    def test_frozen(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = TimelineEvent(
            timestamp=ts,
            source=EventSourceType.TETRAGON,
            kind=TimelineEventKind.PROCESS_EXEC,
            verdict=NormalizedVerdict.ALLOW,
            summary="test",
        )
        try:
            event.summary = "changed"  # type: ignore[misc]
            assert False, "should not be mutable"
        except AttributeError:
            pass


class TestHuntQuery:
    def test_defaults(self) -> None:
        q = HuntQuery()
        assert q.sources == ()
        assert q.verdict is None
        assert q.start is None
        assert q.end is None
        assert q.limit == 100
        assert q.entity is None

    def test_creation(self) -> None:
        q = HuntQuery(
            sources=(EventSourceType.TETRAGON,),
            verdict=NormalizedVerdict.DENY,
            limit=50,
        )
        assert q.sources == (EventSourceType.TETRAGON,)
        assert q.verdict == NormalizedVerdict.DENY
        assert q.limit == 50


class TestCorrelationRule:
    def test_creation(self) -> None:
        rule = CorrelationRule(
            schema="v1",
            name="test-rule",
            severity=RuleSeverity.HIGH,
            description="Test rule",
            window=timedelta(minutes=5),
            conditions=(
                RuleCondition(bind="a"),
            ),
            output=RuleOutput(title="Alert", evidence=("a",)),
        )
        assert rule.name == "test-rule"
        assert rule.severity == RuleSeverity.HIGH
        assert rule.window == timedelta(minutes=5)


class TestAlert:
    def test_creation(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        alert = Alert(
            rule_name="test",
            severity=RuleSeverity.CRITICAL,
            title="Test Alert",
            triggered_at=ts,
            evidence=(),
            description="desc",
        )
        assert alert.rule_name == "test"
        assert alert.evidence == ()


class TestIocEntry:
    def test_creation(self) -> None:
        entry = IocEntry(
            indicator="evil.com",
            ioc_type=IocType.DOMAIN,
            description="Known bad domain",
        )
        assert entry.indicator == "evil.com"
        assert entry.ioc_type == IocType.DOMAIN


class TestIocMatch:
    def test_creation(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        event = TimelineEvent(
            timestamp=ts,
            source=EventSourceType.HUBBLE,
            kind=TimelineEventKind.NETWORK_FLOW,
            verdict=NormalizedVerdict.FORWARDED,
            summary="test",
        )
        entry = IocEntry(indicator="evil.com", ioc_type=IocType.DOMAIN)
        match = IocMatch(event=event, matched_iocs=(entry,), match_field="summary")
        assert match.match_field == "summary"


class TestHuntReport:
    def test_creation(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        report = HuntReport(
            title="Report",
            generated_at=ts,
            evidence=(),
            merkle_root="abc",
            merkle_proofs=(),
        )
        assert report.title == "Report"
        assert report.signature is None


class TestWatchConfig:
    def test_creation(self) -> None:
        cfg = WatchConfig(
            nats_url="nats://localhost:4222",
            rules=(),
            max_window=timedelta(minutes=10),
        )
        assert cfg.nats_url == "nats://localhost:4222"


class TestWatchStats:
    def test_creation(self) -> None:
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        stats = WatchStats(
            events_processed=100,
            alerts_triggered=5,
            start_time=ts,
        )
        assert stats.events_processed == 100
