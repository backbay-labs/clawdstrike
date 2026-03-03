"""Evidence report generation with Merkle-anchored integrity proofs.

Port of ``hunt-correlate/src/report.rs``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from clawdstrike.canonical import canonicalize
from clawdstrike.core import sign_message, verify_signature
from clawdstrike.hunt.errors import ReportError
from clawdstrike.hunt.types import (
    Alert,
    EvidenceItem,
    HuntReport,
    IocEntry,
    IocMatch,
    TimelineEvent,
)
from clawdstrike.merkle import MerkleTree, hash_leaf


def _evidence_to_dict(item: EvidenceItem) -> dict:
    """Serialize an evidence item to a plain dict for canonical JSON."""
    ts_str = _to_iso8601_z(item.timestamp)

    return {
        "index": item.index,
        "sourceType": item.source_type,
        "timestamp": ts_str,
        "summary": item.summary,
        "data": item.data,
    }


def _to_iso8601_z(dt: datetime) -> str:
    """Format datetimes like JS Date.toISOString() for cross-SDK parity."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _event_to_data(event: TimelineEvent) -> dict:
    """Serialize a timeline event to the TypeScript evidence data shape."""
    return {
        "timestamp": _to_iso8601_z(event.timestamp),
        "source": event.source.value,
        "kind": event.kind.value,
        "verdict": event.verdict.value,
        "severity": event.severity,
        "summary": event.summary,
        "process": event.process,
        "namespace": event.namespace,
        "pod": event.pod,
        "actionType": event.action_type,
        "signatureValid": event.signature_valid,
        "raw": event.raw,
    }


def _ioc_entry_to_data(entry: IocEntry) -> dict:
    """Serialize an IOC entry to the TypeScript match data shape."""
    out = {
        "indicator": entry.indicator,
        "iocType": entry.ioc_type.value,
    }
    if entry.description is not None:
        out["description"] = entry.description
    if entry.source is not None:
        out["source"] = entry.source
    return out


def build_report(title: str, items: list[EvidenceItem]) -> HuntReport:
    """Build a hunt report from evidence items.

    Each item is serialized to canonical JSON (RFC 8785), hashed, and included
    in a Merkle tree.
    """
    if not items:
        raise ReportError("no evidence items provided")

    # Build canonical JSON bytes for each item
    leaf_data: list[bytes] = []
    for item in items:
        d = _evidence_to_dict(item)
        canonical_str = canonicalize(d)
        leaf_data.append(canonical_str.encode("utf-8"))

    # Hash leaves and build tree
    leaf_hashes = [hash_leaf(data) for data in leaf_data]
    tree = MerkleTree.from_hashes(leaf_hashes)
    root = tree.root

    # Generate inclusion proofs as JSON strings
    proofs: list[str] = []
    for i in range(len(items)):
        proof = tree.inclusion_proof(i)
        proof_dict = {
            "treeSize": proof.tree_size,
            "leafIndex": proof.leaf_index,
            "auditPath": [p.hex() for p in proof.audit_path],
        }
        proofs.append(json.dumps(proof_dict, separators=(",", ":")))

    return HuntReport(
        title=title,
        generated_at=datetime.now(tz=timezone.utc),
        evidence=tuple(items),
        merkle_root=root.hex(),
        merkle_proofs=tuple(proofs),
        signature=None,
        signer=None,
    )


def sign_report(report: HuntReport, signing_key_hex: str) -> HuntReport:
    """Sign a report's Merkle root. Returns a new :class:`HuntReport` with signature set."""
    try:
        key_bytes = bytes.fromhex(signing_key_hex)
    except ValueError as exc:
        raise ReportError(f"invalid signing key hex: {exc}") from exc

    root_bytes = bytes.fromhex(report.merkle_root)
    sig = sign_message(root_bytes, key_bytes)

    # Derive public key from the signing key seed.
    # pynacl is a required dependency of clawdstrike (see pyproject.toml).
    from nacl.signing import SigningKey as _SigningKey

    pub_hex = bytes(_SigningKey(key_bytes).verify_key).hex()

    return HuntReport(
        title=report.title,
        generated_at=report.generated_at,
        evidence=report.evidence,
        merkle_root=report.merkle_root,
        merkle_proofs=report.merkle_proofs,
        signature=sig.hex(),
        signer=pub_hex,
    )


def verify_report(report: HuntReport) -> bool:
    """Verify a report's signature and Merkle proofs.

    Returns ``True`` if all checks pass.
    """
    try:
        root_bytes = bytes.fromhex(report.merkle_root)
    except ValueError:
        return False

    # Verify signature if present
    sig = report.signature
    signer = report.signer
    if (sig is not None) != (signer is not None):
        return False

    if sig is not None and signer is not None:
        try:
            sig_bytes = bytes.fromhex(sig)
            pub_bytes = bytes.fromhex(signer)
        except ValueError:
            return False
        if not verify_signature(root_bytes, sig_bytes, pub_bytes):
            return False

    # Verify Merkle proofs
    if len(report.merkle_proofs) != len(report.evidence):
        return False

    for i, item in enumerate(report.evidence):
        d = _evidence_to_dict(item)
        canonical_str = canonicalize(d)
        leaf_hash = hash_leaf(canonical_str.encode("utf-8"))

        try:
            proof_dict = json.loads(report.merkle_proofs[i])
        except (json.JSONDecodeError, IndexError):
            return False
        if not isinstance(proof_dict, dict):
            return False

        from clawdstrike.merkle import MerkleProof
        try:
            audit_path = [bytes.fromhex(h) for h in proof_dict.get("auditPath", [])]
        except (TypeError, ValueError):
            return False

        proof = MerkleProof(
            tree_size=proof_dict.get("treeSize", 0),
            leaf_index=proof_dict.get("leafIndex", 0),
            audit_path=audit_path,
        )

        if not proof.verify(leaf_hash, root_bytes):
            return False

    return True


# ---------------------------------------------------------------------------
# Evidence conversion helpers
# ---------------------------------------------------------------------------


def evidence_from_alert(alert: Alert, start_index: int = 0) -> list[EvidenceItem]:
    """Convert an alert and its evidence events into :class:`EvidenceItem` list."""
    items: list[EvidenceItem] = []

    items.append(EvidenceItem(
        index=start_index,
        source_type="alert",
        timestamp=alert.triggered_at,
        summary=f"[{alert.severity.value}] {alert.rule_name}: {alert.title}",
        data={
            "ruleName": alert.rule_name,
            "severity": alert.severity.value,
            "title": alert.title,
            "triggeredAt": _to_iso8601_z(alert.triggered_at),
            "description": alert.description,
        },
    ))

    for i, event in enumerate(alert.evidence):
        items.append(EvidenceItem(
            index=start_index + 1 + i,
            source_type="event",
            timestamp=event.timestamp,
            summary=f"[{event.source.value}] {event.summary}",
            data=_event_to_data(event),
        ))

    return items


def evidence_from_events(
    events: list[TimelineEvent], start_index: int = 0
) -> list[EvidenceItem]:
    """Convert timeline events into :class:`EvidenceItem` list."""
    return [
        EvidenceItem(
            index=start_index + i,
            source_type="event",
            timestamp=event.timestamp,
            summary=f"[{event.source.value}] {event.summary}",
            data=_event_to_data(event),
        )
        for i, event in enumerate(events)
    ]


def evidence_from_ioc_matches(
    matches: list[IocMatch], start_index: int = 0
) -> list[EvidenceItem]:
    """Convert IOC matches into :class:`EvidenceItem` list."""
    items: list[EvidenceItem] = []
    for i, m in enumerate(matches):
        ioc_names = [e.indicator for e in m.matched_iocs]
        items.append(EvidenceItem(
            index=start_index + i,
            source_type="ioc_match",
            timestamp=m.event.timestamp,
            summary=f"IOC match in {m.match_field}: {', '.join(ioc_names)} ({m.event.summary})",
            data={
                "event": _event_to_data(m.event),
                "matchedIocs": [_ioc_entry_to_data(e) for e in m.matched_iocs],
                "matchField": m.match_field,
            },
        ))
    return items


def collect_evidence(
    *items: Alert | list[TimelineEvent] | list[IocMatch],
) -> list[EvidenceItem]:
    """Collect evidence from mixed sources with auto-indexing.

    Accepts any combination of :class:`Alert`, ``list[TimelineEvent]``, or
    ``list[IocMatch]`` items and returns a flat list of evidence items with
    sequential indices.
    """
    result: list[EvidenceItem] = []
    next_index = 0

    for item in items:
        if isinstance(item, Alert):
            evidence = evidence_from_alert(item, next_index)
            result.extend(evidence)
            next_index += len(evidence)
        elif isinstance(item, list) and item and isinstance(item[0], IocMatch):
            evidence = evidence_from_ioc_matches(item, next_index)  # type: ignore[arg-type]
            result.extend(evidence)
            next_index += len(evidence)
        elif isinstance(item, list):
            evidence = evidence_from_events(item, next_index)  # type: ignore[arg-type]
            result.extend(evidence)
            next_index += len(evidence)

    return result


__all__ = [
    "build_report",
    "sign_report",
    "verify_report",
    "evidence_from_alert",
    "evidence_from_events",
    "evidence_from_ioc_matches",
    "collect_evidence",
]
