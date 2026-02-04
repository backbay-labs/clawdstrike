"""Tests for hush.receipt types (schema-compatible with Rust hush-core)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawdstrike.core import generate_keypair
from clawdstrike.receipt import (
    RECEIPT_SCHEMA_VERSION,
    PublicKeySet,
    Receipt,
    SignedReceipt,
    Verdict,
    validate_receipt_version,
)


def test_validate_receipt_version_matches_vectors():
    repo_root = Path(__file__).resolve().parents[3]
    cases_path = repo_root / "fixtures" / "receipts" / "version_cases.json"
    cases = json.loads(cases_path.read_text(encoding="utf-8"))

    for c in cases:
        if c["supported"]:
            validate_receipt_version(c["version"])
        else:
            with pytest.raises(ValueError, match=c.get("error_contains", "Invalid receipt version")):
                validate_receipt_version(c["version"])


def test_receipt_canonical_json_and_hashes():
    receipt = Receipt(
        version=RECEIPT_SCHEMA_VERSION,
        receipt_id="test-receipt-001",
        timestamp="2026-01-01T00:00:00Z",
        content_hash="0x" + "00" * 32,
        verdict=Verdict(passed=True, gate_id="unit-test"),
        provenance=None,
        metadata=None,
    )

    canonical = receipt.to_canonical_json()
    assert '"version":"1.0.0"' in canonical
    assert canonical.count(" ") == 0
    assert receipt.hash_sha256().startswith("0x")
    assert receipt.hash_keccak256().startswith("0x")


def test_receipt_fails_closed_on_unknown_fields():
    with pytest.raises(ValueError, match="Unknown receipt field"):
        Receipt.from_dict(
            {
                "version": RECEIPT_SCHEMA_VERSION,
                "timestamp": "2026-01-01T00:00:00Z",
                "content_hash": "0x" + "00" * 32,
                "verdict": {"passed": True},
                "extra_field": 1,
            }
        )


def test_signed_receipt_sign_and_verify():
    receipt = Receipt(
        version=RECEIPT_SCHEMA_VERSION,
        receipt_id=None,
        timestamp="2026-01-01T00:00:00Z",
        content_hash="0x" + "11" * 32,
        verdict=Verdict(passed=True, gate_id="gate"),
        provenance=None,
        metadata=None,
    )

    private_key, public_key = generate_keypair()
    signed = SignedReceipt.sign(receipt, private_key)

    result = signed.verify(PublicKeySet(signer=public_key.hex()))
    assert result.valid is True
    assert result.signer_valid is True
    assert result.errors == []


def test_signed_receipt_rejects_tampering():
    receipt = Receipt(
        version=RECEIPT_SCHEMA_VERSION,
        receipt_id=None,
        timestamp="2026-01-01T00:00:00Z",
        content_hash="0x" + "11" * 32,
        verdict=Verdict(passed=True),
        provenance=None,
        metadata=None,
    )

    private_key, public_key = generate_keypair()
    signed = SignedReceipt.sign(receipt, private_key)

    tampered = SignedReceipt(
        receipt=Receipt(
            version=RECEIPT_SCHEMA_VERSION,
            receipt_id=None,
            timestamp="2026-01-01T00:00:00Z",
            content_hash="0x" + "11" * 32,
            verdict=Verdict(passed=False),
            provenance=None,
            metadata=None,
        ),
        signatures=signed.signatures,
    )

    result = tampered.verify(PublicKeySet(signer=public_key.hex()))
    assert result.valid is False
    assert result.signer_valid is False

