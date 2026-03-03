"""Tests for clawdstrike.hunt.report — build, sign/verify, evidence helpers."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from clawdstrike.core import generate_keypair
from clawdstrike.hunt.errors import ReportError
from clawdstrike.hunt.report import (
    _evidence_to_dict,
    build_report,
    collect_evidence,
    evidence_from_alert,
    evidence_from_events,
    evidence_from_ioc_matches,
    sign_report,
    verify_report,
)
from clawdstrike.hunt.types import (
    Alert,
    EventSourceType,
    EvidenceItem,
    IocEntry,
    IocMatch,
    IocType,
    NormalizedVerdict,
    RuleSeverity,
    TimelineEvent,
    TimelineEventKind,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def _sample_items() -> list[EvidenceItem]:
    return [
        EvidenceItem(
            index=0,
            source_type="alert",
            timestamp=_TS,
            summary="Suspicious file access",
            data={"rule": "exfil", "severity": "high"},
        ),
        EvidenceItem(
            index=1,
            source_type="event",
            timestamp=_TS,
            summary="read /etc/passwd",
            data={"path": "/etc/passwd"},
        ),
        EvidenceItem(
            index=2,
            source_type="ioc_match",
            timestamp=_TS,
            summary="IOC match: evil.com",
            data={"domain": "evil.com"},
        ),
    ]


def _make_event(summary: str, ts: datetime = _TS) -> TimelineEvent:
    return TimelineEvent(
        timestamp=ts,
        source=EventSourceType.RECEIPT,
        kind=TimelineEventKind.GUARD_DECISION,
        verdict=NormalizedVerdict.DENY,
        summary=summary,
        action_type="file",
        severity="high",
    )


# ---------------------------------------------------------------------------
# build_report
# ---------------------------------------------------------------------------


class TestBuildReport:
    def test_build_with_sample_evidence(self) -> None:
        items = _sample_items()
        report = build_report("Test Report", items)
        assert report.title == "Test Report"
        assert len(report.evidence) == 3
        assert report.merkle_root
        assert len(report.merkle_proofs) == 3
        assert report.signature is None
        assert report.signer is None

    def test_build_single_item(self) -> None:
        items = [EvidenceItem(
            index=0,
            source_type="event",
            timestamp=_TS,
            summary="single event",
            data={"key": "value"},
        )]
        report = build_report("Single", items)
        assert len(report.evidence) == 1
        assert report.merkle_root
        assert verify_report(report)

    def test_build_empty_items_errors(self) -> None:
        with pytest.raises(ReportError, match="no evidence"):
            build_report("Empty", [])


# ---------------------------------------------------------------------------
# Sign / verify round-trip
# ---------------------------------------------------------------------------


class TestSignVerify:
    def test_sign_and_verify_roundtrip(self) -> None:
        items = _sample_items()
        report = build_report("Signed Report", items)
        priv, pub = generate_keypair()

        signed = sign_report(report, priv.hex())
        assert signed.signature is not None
        assert signed.signer is not None
        assert verify_report(signed)

    def test_unsigned_report_verifies(self) -> None:
        items = _sample_items()
        report = build_report("Unsigned", items)
        assert verify_report(report)

    def test_tampered_signature_fails(self) -> None:
        items = _sample_items()
        report = build_report("Tampered", items)
        priv, pub = generate_keypair()

        signed = sign_report(report, priv.hex())
        sig = signed.signature
        assert sig is not None

        # Flip first character
        chars = list(sig)
        chars[0] = "b" if chars[0] == "a" else "a"
        tampered_sig = "".join(chars)

        from clawdstrike.hunt.types import HuntReport
        tampered = HuntReport(
            title=signed.title,
            generated_at=signed.generated_at,
            evidence=signed.evidence,
            merkle_root=signed.merkle_root,
            merkle_proofs=signed.merkle_proofs,
            signature=tampered_sig,
            signer=signed.signer,
        )

        result = verify_report(tampered)
        assert not result

    def test_signature_without_signer_fails(self) -> None:
        items = _sample_items()
        report = build_report("Missing Signer", items)
        priv, pub = generate_keypair()
        signed = sign_report(report, priv.hex())

        from clawdstrike.hunt.types import HuntReport
        broken = HuntReport(
            title=signed.title,
            generated_at=signed.generated_at,
            evidence=signed.evidence,
            merkle_root=signed.merkle_root,
            merkle_proofs=signed.merkle_proofs,
            signature=signed.signature,
            signer=None,
        )
        assert not verify_report(broken)

    def test_signer_without_signature_fails(self) -> None:
        items = _sample_items()
        report = build_report("Missing Signature", items)
        priv, pub = generate_keypair()

        from clawdstrike.hunt.types import HuntReport
        broken = HuntReport(
            title=report.title,
            generated_at=report.generated_at,
            evidence=report.evidence,
            merkle_root=report.merkle_root,
            merkle_proofs=report.merkle_proofs,
            signature=None,
            signer=pub.hex(),
        )
        assert not verify_report(broken)

    def test_malformed_proof_json_shape_fails(self) -> None:
        report = build_report("Proof Shape", _sample_items())

        from clawdstrike.hunt.types import HuntReport
        malformed = HuntReport(
            title=report.title,
            generated_at=report.generated_at,
            evidence=report.evidence,
            merkle_root=report.merkle_root,
            merkle_proofs=("[]",) + report.merkle_proofs[1:],
            signature=report.signature,
            signer=report.signer,
        )
        assert not verify_report(malformed)


# ---------------------------------------------------------------------------
# Evidence helpers
# ---------------------------------------------------------------------------


class TestEvidenceHelpers:
    def test_evidence_from_alert(self) -> None:
        event = _make_event("read /etc/passwd")
        alert = Alert(
            rule_name="exfil_rule",
            severity=RuleSeverity.HIGH,
            title="Data exfiltration",
            triggered_at=_TS,
            evidence=(event,),
            description="Test alert",
        )
        items = evidence_from_alert(alert, 0)
        assert len(items) == 2
        assert items[0].source_type == "alert"
        assert items[0].index == 0
        assert "exfil_rule" in items[0].summary
        assert items[0].data["ruleName"] == "exfil_rule"
        assert items[0].data["triggeredAt"] == "2025-06-15T12:00:00.000Z"
        assert items[1].source_type == "event"
        assert items[1].index == 1
        assert items[1].data["actionType"] == "file"
        assert items[1].data["timestamp"] == "2025-06-15T12:00:00.000Z"

    def test_evidence_from_events(self) -> None:
        ts2 = datetime(2025, 6, 15, 12, 1, 0, tzinfo=timezone.utc)
        events = [_make_event("event one"), _make_event("event two", ts2)]
        items = evidence_from_events(events, 5)
        assert len(items) == 2
        assert items[0].index == 5
        assert items[1].index == 6
        assert "event one" in items[0].summary
        assert items[0].data["timestamp"] == "2025-06-15T12:00:00.000Z"
        assert items[1].data["timestamp"] == "2025-06-15T12:01:00.000Z"
        assert items[0].data["actionType"] == "file"

    def test_evidence_from_ioc_matches(self) -> None:
        event = TimelineEvent(
            timestamp=_TS,
            source=EventSourceType.TETRAGON,
            kind=TimelineEventKind.PROCESS_EXEC,
            verdict=NormalizedVerdict.NONE,
            summary="curl evil.com",
            process="curl",
        )
        ioc_match = IocMatch(
            event=event,
            matched_iocs=(IocEntry(
                indicator="evil.com",
                ioc_type=IocType.DOMAIN,
                description="C2 domain",
                source=None,
            ),),
            match_field="summary",
        )
        items = evidence_from_ioc_matches([ioc_match], 10)
        assert len(items) == 1
        assert items[0].index == 10
        assert items[0].source_type == "ioc_match"
        assert "evil.com" in items[0].summary
        assert items[0].data["matchField"] == "summary"
        assert items[0].data["matchedIocs"][0]["iocType"] == "domain"
        assert items[0].data["event"]["source"] == "tetragon"

    def test_evidence_to_dict_uses_cross_sdk_field_names(self) -> None:
        item = EvidenceItem(
            index=3,
            source_type="event",
            timestamp=_TS,
            summary="sample",
            data={"k": "v"},
        )

        serialized = _evidence_to_dict(item)
        assert "sourceType" in serialized
        assert "source_type" not in serialized
        assert serialized["sourceType"] == "event"
        assert serialized["timestamp"] == "2025-06-15T12:00:00.000Z"

    def test_full_pipeline(self) -> None:
        event = _make_event("read /etc/shadow")
        alert = Alert(
            rule_name="shadow_access",
            severity=RuleSeverity.CRITICAL,
            title="Shadow file read",
            triggered_at=_TS,
            evidence=(event,),
            description="Shadow file access detected",
        )
        items = evidence_from_alert(alert, 0)
        report = build_report("Full Pipeline", items)
        assert verify_report(report)

        priv, pub = generate_keypair()
        signed = sign_report(report, priv.hex())
        assert verify_report(signed)


class TestCollectEvidence:
    def test_auto_indexes_across_mixed_sources(self) -> None:
        event1 = _make_event("read /etc/passwd")
        event2 = _make_event("egress to evil.com")
        alert = Alert(
            rule_name="test_rule",
            severity=RuleSeverity.HIGH,
            title="Test alert",
            triggered_at=_TS,
            evidence=(event1,),
            description="desc",
        )
        ioc_match = IocMatch(
            event=event2,
            matched_iocs=(IocEntry(
                indicator="evil.com",
                ioc_type=IocType.DOMAIN,
            ),),
            match_field="summary",
        )

        items = collect_evidence(alert, [event2], [ioc_match])

        # Alert produces 2 items (alert + 1 evidence event)
        # Events produces 1 item
        # IOC matches produces 1 item
        assert len(items) == 4
        assert items[0].index == 0
        assert items[1].index == 1
        assert items[2].index == 2
        assert items[3].index == 3
        assert items[0].source_type == "alert"
        assert items[2].source_type == "event"
        assert items[3].source_type == "ioc_match"

    def test_handles_empty_input(self) -> None:
        items = collect_evidence()
        assert len(items) == 0
