"""Tests for hush.receipt types."""

import json
import pytest
from hush.receipt import Receipt, SignedReceipt
from hush.core import generate_keypair


class TestReceipt:
    def test_create_receipt(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={"task": "test"},
        )
        assert receipt.id == "run-123"
        assert receipt.event_count == 42

    def test_receipt_to_json(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={},
        )
        json_str = receipt.to_json()
        data = json.loads(json_str)
        assert data["id"] == "run-123"
        assert data["event_count"] == 42

    def test_receipt_from_json(self) -> None:
        json_str = json.dumps({
            "id": "run-456",
            "artifact_root": "0x" + "cd" * 32,
            "event_count": 100,
            "metadata": {"key": "value"},
        })
        receipt = Receipt.from_json(json_str)
        assert receipt.id == "run-456"
        assert receipt.event_count == 100
        assert receipt.metadata["key"] == "value"

    def test_receipt_hash(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={},
        )
        hash1 = receipt.hash()
        hash2 = receipt.hash()
        assert hash1 == hash2
        assert len(hash1) == 32


class TestSignedReceipt:
    def test_sign_and_verify(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={},
        )
        private_key, public_key = generate_keypair()

        signed = SignedReceipt.sign(receipt, private_key, public_key)

        assert signed.receipt == receipt
        assert len(signed.signature) == 64
        assert signed.public_key == public_key
        assert signed.verify() is True

    def test_verify_tampered_receipt(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={},
        )
        private_key, public_key = generate_keypair()

        signed = SignedReceipt.sign(receipt, private_key, public_key)

        # Tamper with the receipt
        signed.receipt.event_count = 999

        assert signed.verify() is False

    def test_signed_receipt_serialization(self) -> None:
        receipt = Receipt(
            id="run-123",
            artifact_root="0x" + "ab" * 32,
            event_count=42,
            metadata={},
        )
        private_key, public_key = generate_keypair()

        signed = SignedReceipt.sign(receipt, private_key, public_key)
        json_str = signed.to_json()

        restored = SignedReceipt.from_json(json_str)
        assert restored.receipt.id == "run-123"
        assert restored.verify() is True
