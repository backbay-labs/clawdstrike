"""Tests for clawdstrike.hunt.timeline."""

from datetime import datetime, timezone

from clawdstrike.hunt.timeline import merge_timeline, parse_envelope
from clawdstrike.hunt.types import (
    EventSourceType,
    NormalizedVerdict,
    TimelineEvent,
    TimelineEventKind,
)


class TestParseTetragonEnvelope:
    def test_process_exec(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:00:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1",
                "event_type": "PROCESS_EXEC",
                "process": {
                    "binary": "/usr/bin/curl",
                    "pod": {
                        "namespace": "default",
                        "name": "agent-pod-abc123",
                    },
                },
                "severity": "info",
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.source == EventSourceType.TETRAGON
        assert event.kind == TimelineEventKind.PROCESS_EXEC
        assert event.verdict == NormalizedVerdict.NONE
        assert event.process == "/usr/bin/curl"
        assert event.namespace == "default"
        assert event.pod == "agent-pod-abc123"
        assert event.severity == "info"
        assert event.summary == "process_exec /usr/bin/curl"
        assert event.action_type == "process"
        assert event.raw is not None

    def test_process_exit(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:01:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1",
                "event_type": "PROCESS_EXIT",
                "process": {
                    "binary": "/usr/bin/ls",
                },
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.kind == TimelineEventKind.PROCESS_EXIT
        assert event.summary == "process_exit /usr/bin/ls"

    def test_process_kprobe(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:02:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1",
                "event_type": "PROCESS_KPROBE",
                "process": {
                    "binary": "/usr/bin/cat",
                },
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.kind == TimelineEventKind.PROCESS_KPROBE

    def test_unknown_event_type_defaults_to_exec(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:03:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1",
                "event_type": "UNKNOWN",
                "process": {
                    "binary": "/bin/sh",
                },
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.kind == TimelineEventKind.PROCESS_EXEC


class TestParseHubbleEnvelope:
    def test_forwarded(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:05:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
                "verdict": "FORWARDED",
                "traffic_direction": "EGRESS",
                "summary": "TCP 10.0.0.1:8080 -> 10.0.0.2:443",
                "source": {
                    "namespace": "production",
                    "pod_name": "web-server-xyz",
                },
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.source == EventSourceType.HUBBLE
        assert event.kind == TimelineEventKind.NETWORK_FLOW
        assert event.verdict == NormalizedVerdict.FORWARDED
        assert event.namespace == "production"
        assert event.pod == "web-server-xyz"
        assert "egress" in event.summary

    def test_dropped(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:06:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
                "verdict": "DROPPED",
                "traffic_direction": "INGRESS",
                "summary": "blocked connection",
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.verdict == NormalizedVerdict.DROPPED

    def test_egress_action_type(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:05:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
                "verdict": "FORWARDED",
                "traffic_direction": "EGRESS",
                "summary": "flow",
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.action_type == "egress"

    def test_ingress_action_type(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:05:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
                "verdict": "FORWARDED",
                "traffic_direction": "INGRESS",
                "summary": "flow",
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.action_type == "ingress"

    def test_unknown_direction_falls_back_to_network(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:05:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
                "verdict": "FORWARDED",
                "traffic_direction": "UNKNOWN",
                "summary": "flow",
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.action_type == "network"


class TestParseReceiptEnvelope:
    def test_deny(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:10:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.receipt.v1",
                "decision": "deny",
                "guard": "ForbiddenPathGuard",
                "action_type": "file",
                "severity": "critical",
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.source == EventSourceType.RECEIPT
        assert event.kind == TimelineEventKind.GUARD_DECISION
        assert event.verdict == NormalizedVerdict.DENY
        assert event.action_type == "file"
        assert event.severity == "critical"
        assert "ForbiddenPathGuard" in event.summary

    def test_preserves_source_metadata(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:10:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.receipt.v1",
                "decision": "deny",
                "guard": "ForbiddenPathGuard",
                "action_type": "file",
                "source": {
                    "namespace": "prod",
                    "pod_name": "agent-worker-1",
                },
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.namespace == "prod"
        assert event.pod == "agent-worker-1"

    def test_allow_decision(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:10:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.receipt.v1",
                "decision": "allow",
                "guard": "TestGuard",
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.verdict == NormalizedVerdict.ALLOW


class TestParseScanEnvelope:
    def test_fail(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:15:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.scan.v1",
                "scan_type": "vulnerability",
                "status": "fail",
                "severity": "high",
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.source == EventSourceType.SCAN
        assert event.kind == TimelineEventKind.SCAN_RESULT
        assert event.verdict == NormalizedVerdict.DENY
        assert event.severity == "high"
        assert "vulnerability" in event.summary

    def test_pass(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:15:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.scan.v1",
                "scan_type": "malware",
                "status": "pass",
            },
        }
        event = parse_envelope(envelope)
        assert event is not None
        assert event.verdict == NormalizedVerdict.ALLOW


class TestParseEnvelopeEdgeCases:
    def test_unknown_schema_returns_none(self) -> None:
        envelope = {
            "issued_at": "2025-06-15T12:00:00Z",
            "fact": {"schema": "unknown.schema.v1"},
        }
        assert parse_envelope(envelope) is None

    def test_missing_fact_returns_none(self) -> None:
        envelope = {"issued_at": "2025-06-15T12:00:00Z"}
        assert parse_envelope(envelope) is None

    def test_missing_timestamp_returns_none(self) -> None:
        envelope = {
            "fact": {
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1",
                "event_type": "PROCESS_EXEC",
                "process": {"binary": "/bin/sh"},
            }
        }
        assert parse_envelope(envelope) is None

    def test_invalid_timestamp_returns_none(self) -> None:
        envelope = {
            "issued_at": "not-a-timestamp",
            "fact": {
                "schema": "clawdstrike.sdr.fact.tetragon_event.v1",
                "event_type": "PROCESS_EXEC",
                "process": {"binary": "/bin/sh"},
            },
        }
        assert parse_envelope(envelope) is None


class TestMergeTimeline:
    def test_sorts_by_timestamp(self) -> None:
        ts1 = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts2 = datetime(2025, 6, 15, 14, 0, 0, tzinfo=timezone.utc)
        ts3 = datetime(2025, 6, 15, 16, 0, 0, tzinfo=timezone.utc)

        events = [
            TimelineEvent(
                timestamp=ts2,
                source=EventSourceType.TETRAGON,
                kind=TimelineEventKind.PROCESS_EXEC,
                verdict=NormalizedVerdict.NONE,
                summary="second",
            ),
            TimelineEvent(
                timestamp=ts1,
                source=EventSourceType.HUBBLE,
                kind=TimelineEventKind.NETWORK_FLOW,
                verdict=NormalizedVerdict.FORWARDED,
                summary="first",
            ),
            TimelineEvent(
                timestamp=ts3,
                source=EventSourceType.RECEIPT,
                kind=TimelineEventKind.GUARD_DECISION,
                verdict=NormalizedVerdict.DENY,
                summary="third",
            ),
        ]

        merged = merge_timeline(events)
        assert len(merged) == 3
        assert merged[0].summary == "first"
        assert merged[1].summary == "second"
        assert merged[2].summary == "third"

    def test_empty(self) -> None:
        assert merge_timeline([]) == []
