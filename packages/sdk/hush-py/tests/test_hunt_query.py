"""Tests for clawdstrike.hunt.query."""

from datetime import datetime, timezone

from clawdstrike.hunt.query import (
    all_event_sources,
    effective_sources,
    matches_query,
    parse_event_source,
    parse_event_source_list,
    parse_query_verdict,
    stream_name,
    subject_filter,
)
from clawdstrike.hunt.types import (
    EventSourceType,
    HuntQuery,
    NormalizedVerdict,
    TimelineEvent,
    TimelineEventKind,
)


def _make_event() -> TimelineEvent:
    return TimelineEvent(
        timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        source=EventSourceType.TETRAGON,
        kind=TimelineEventKind.PROCESS_EXEC,
        verdict=NormalizedVerdict.ALLOW,
        summary="process_exec /usr/bin/curl",
        process="/usr/bin/curl",
        namespace="default",
        pod="agent-pod-abc123",
        action_type="process",
    )


class TestParseEventSource:
    def test_tetragon(self) -> None:
        assert parse_event_source("tetragon") == EventSourceType.TETRAGON

    def test_hubble_uppercase(self) -> None:
        assert parse_event_source("HUBBLE") == EventSourceType.HUBBLE

    def test_receipt(self) -> None:
        assert parse_event_source("Receipt") == EventSourceType.RECEIPT

    def test_receipts_alias(self) -> None:
        assert parse_event_source("receipts") == EventSourceType.RECEIPT

    def test_scan(self) -> None:
        assert parse_event_source("scan") == EventSourceType.SCAN

    def test_scans_alias(self) -> None:
        assert parse_event_source("scans") == EventSourceType.SCAN

    def test_unknown(self) -> None:
        assert parse_event_source("unknown") is None


class TestParseEventSourceList:
    def test_comma_separated(self) -> None:
        sources = parse_event_source_list("tetragon, hubble")
        assert sources == [EventSourceType.TETRAGON, EventSourceType.HUBBLE]

    def test_single(self) -> None:
        sources = parse_event_source_list("SCAN")
        assert sources == [EventSourceType.SCAN]

    def test_empty(self) -> None:
        sources = parse_event_source_list("")
        assert sources == []


class TestStreamName:
    def test_tetragon(self) -> None:
        assert stream_name(EventSourceType.TETRAGON) == "CLAWDSTRIKE_TETRAGON"

    def test_hubble(self) -> None:
        assert stream_name(EventSourceType.HUBBLE) == "CLAWDSTRIKE_HUBBLE"

    def test_receipt(self) -> None:
        assert stream_name(EventSourceType.RECEIPT) == "CLAWDSTRIKE_RECEIPTS"

    def test_scan(self) -> None:
        assert stream_name(EventSourceType.SCAN) == "CLAWDSTRIKE_SCANS"


class TestSubjectFilter:
    def test_tetragon(self) -> None:
        assert subject_filter(EventSourceType.TETRAGON) == "clawdstrike.sdr.fact.tetragon_event.>"

    def test_hubble(self) -> None:
        assert subject_filter(EventSourceType.HUBBLE) == "clawdstrike.sdr.fact.hubble_flow.>"

    def test_receipt(self) -> None:
        assert subject_filter(EventSourceType.RECEIPT) == "clawdstrike.sdr.fact.receipt.>"

    def test_scan(self) -> None:
        assert subject_filter(EventSourceType.SCAN) == "clawdstrike.sdr.fact.scan.>"


class TestAllEventSources:
    def test_returns_all_four(self) -> None:
        sources = all_event_sources()
        assert len(sources) == 4
        assert EventSourceType.TETRAGON in sources
        assert EventSourceType.HUBBLE in sources
        assert EventSourceType.RECEIPT in sources
        assert EventSourceType.SCAN in sources


class TestParseQueryVerdict:
    def test_allow(self) -> None:
        assert parse_query_verdict("allow") == NormalizedVerdict.ALLOW

    def test_allowed(self) -> None:
        assert parse_query_verdict("ALLOWED") == NormalizedVerdict.ALLOW

    def test_pass(self) -> None:
        assert parse_query_verdict("pass") == NormalizedVerdict.ALLOW

    def test_passed(self) -> None:
        assert parse_query_verdict("passed") == NormalizedVerdict.ALLOW

    def test_deny(self) -> None:
        assert parse_query_verdict("deny") == NormalizedVerdict.DENY

    def test_denied(self) -> None:
        assert parse_query_verdict("DENIED") == NormalizedVerdict.DENY

    def test_block(self) -> None:
        assert parse_query_verdict("block") == NormalizedVerdict.DENY

    def test_blocked(self) -> None:
        assert parse_query_verdict("blocked") == NormalizedVerdict.DENY

    def test_warn(self) -> None:
        assert parse_query_verdict("warn") == NormalizedVerdict.WARN

    def test_warned(self) -> None:
        assert parse_query_verdict("warned") == NormalizedVerdict.WARN

    def test_warning(self) -> None:
        assert parse_query_verdict("warning") == NormalizedVerdict.WARN

    def test_forwarded(self) -> None:
        assert parse_query_verdict("forwarded") == NormalizedVerdict.FORWARDED

    def test_forward(self) -> None:
        assert parse_query_verdict("forward") == NormalizedVerdict.FORWARDED

    def test_dropped(self) -> None:
        assert parse_query_verdict("dropped") == NormalizedVerdict.DROPPED

    def test_drop(self) -> None:
        assert parse_query_verdict("drop") == NormalizedVerdict.DROPPED

    def test_unknown(self) -> None:
        assert parse_query_verdict("unknown") is None


class TestEffectiveSources:
    def test_empty_returns_all(self) -> None:
        q = HuntQuery()
        assert effective_sources(q) == all_event_sources()

    def test_specified(self) -> None:
        q = HuntQuery(sources=(EventSourceType.TETRAGON,))
        assert effective_sources(q) == [EventSourceType.TETRAGON]

    def test_deduplicates_preserving_order(self) -> None:
        q = HuntQuery(
            sources=(
                EventSourceType.RECEIPT,
                EventSourceType.RECEIPT,
                EventSourceType.HUBBLE,
                EventSourceType.RECEIPT,
                EventSourceType.HUBBLE,
            )
        )
        assert effective_sources(q) == [EventSourceType.RECEIPT, EventSourceType.HUBBLE]


class TestMatchesQuery:
    def test_default_matches_all(self) -> None:
        assert matches_query(HuntQuery(), _make_event())

    def test_source_filter_miss(self) -> None:
        q = HuntQuery(sources=(EventSourceType.HUBBLE,))
        assert not matches_query(q, _make_event())

    def test_source_filter_hit(self) -> None:
        q = HuntQuery(sources=(EventSourceType.TETRAGON,))
        assert matches_query(q, _make_event())

    def test_verdict_filter_miss(self) -> None:
        q = HuntQuery(verdict=NormalizedVerdict.DENY)
        assert not matches_query(q, _make_event())

    def test_verdict_filter_hit(self) -> None:
        q = HuntQuery(verdict=NormalizedVerdict.ALLOW)
        assert matches_query(q, _make_event())

    def test_forwarded_verdict(self) -> None:
        event = TimelineEvent(
            timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
            source=EventSourceType.HUBBLE,
            kind=TimelineEventKind.NETWORK_FLOW,
            verdict=NormalizedVerdict.FORWARDED,
            summary="test",
        )
        q = HuntQuery(verdict=NormalizedVerdict.FORWARDED)
        assert matches_query(q, event)
        q2 = HuntQuery(verdict=NormalizedVerdict.ALLOW)
        assert not matches_query(q2, event)

    def test_dropped_verdict(self) -> None:
        event = TimelineEvent(
            timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
            source=EventSourceType.HUBBLE,
            kind=TimelineEventKind.NETWORK_FLOW,
            verdict=NormalizedVerdict.DROPPED,
            summary="test",
        )
        q = HuntQuery(verdict=NormalizedVerdict.DROPPED)
        assert matches_query(q, event)
        q2 = HuntQuery(verdict=NormalizedVerdict.DENY)
        assert not matches_query(q2, event)

    def test_time_range_start_miss(self) -> None:
        q = HuntQuery(start=datetime(2025, 6, 15, 13, 0, 0, tzinfo=timezone.utc))
        assert not matches_query(q, _make_event())

    def test_time_range_end_miss(self) -> None:
        q = HuntQuery(end=datetime(2025, 6, 15, 11, 0, 0, tzinfo=timezone.utc))
        assert not matches_query(q, _make_event())

    def test_time_range_hit(self) -> None:
        q = HuntQuery(
            start=datetime(2025, 6, 15, 11, 0, 0, tzinfo=timezone.utc),
            end=datetime(2025, 6, 15, 13, 0, 0, tzinfo=timezone.utc),
        )
        assert matches_query(q, _make_event())

    def test_time_range_naive_datetimes_are_normalized(self) -> None:
        q = HuntQuery(
            start=datetime(2025, 6, 15, 11, 0, 0),
            end=datetime(2025, 6, 15, 13, 0, 0),
        )
        assert matches_query(q, _make_event())

    def test_action_type_case_insensitive(self) -> None:
        q = HuntQuery(action_type="PROCESS")
        assert matches_query(q, _make_event())

    def test_process_contains(self) -> None:
        q = HuntQuery(process="curl")
        assert matches_query(q, _make_event())

    def test_process_no_match(self) -> None:
        q = HuntQuery(process="wget")
        assert not matches_query(q, _make_event())

    def test_namespace_case_insensitive(self) -> None:
        q = HuntQuery(namespace="DEFAULT")
        assert matches_query(q, _make_event())

    def test_namespace_miss(self) -> None:
        q = HuntQuery(namespace="kube-system")
        assert not matches_query(q, _make_event())

    def test_pod_contains(self) -> None:
        q = HuntQuery(pod="agent-pod")
        assert matches_query(q, _make_event())

    def test_combined_predicates(self) -> None:
        q = HuntQuery(
            sources=(EventSourceType.TETRAGON,),
            verdict=NormalizedVerdict.ALLOW,
            process="curl",
            namespace="default",
        )
        assert matches_query(q, _make_event())

    def test_missing_optional_field(self) -> None:
        event = TimelineEvent(
            timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
            source=EventSourceType.TETRAGON,
            kind=TimelineEventKind.PROCESS_EXEC,
            verdict=NormalizedVerdict.ALLOW,
            summary="test",
            process=None,
        )
        q = HuntQuery(process="curl")
        assert not matches_query(q, event)

    def test_entity_matches_pod(self) -> None:
        q = HuntQuery(entity="agent-pod")
        assert matches_query(q, _make_event())

    def test_entity_matches_namespace(self) -> None:
        q = HuntQuery(entity="default")
        assert matches_query(q, _make_event())

    def test_entity_no_match(self) -> None:
        q = HuntQuery(entity="nonexistent")
        assert not matches_query(q, _make_event())
