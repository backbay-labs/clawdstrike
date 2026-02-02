"""Integration tests for hush SDK."""

import pytest
from hush import (
    Policy,
    PolicyEngine,
    PublicKeySet,
    Receipt,
    SignedReceipt,
    GuardAction,
    GuardContext,
    Verdict,
    generate_keypair,
    sha256,
)


class TestFullWorkflow:
    def test_policy_guard_workflow(self, sample_policy_yaml: str) -> None:
        """Test complete policy loading and guard evaluation workflow."""
        # Load policy
        policy = Policy.from_yaml(sample_policy_yaml)
        engine = PolicyEngine(policy)
        context = GuardContext(cwd="/app", session_id="test-session")

        # Test various actions
        assert engine.is_allowed(
            GuardAction.file_access("/app/src/main.py"),
            context,
        )

        assert not engine.is_allowed(
            GuardAction.file_access("/home/user/.ssh/id_rsa"),
            context,
        )

        assert engine.is_allowed(
            GuardAction.network_egress("api.example.com", 443),
            context,
        )

        assert not engine.is_allowed(
            GuardAction.network_egress("unknown.com", 443),
            context,
        )

    def test_receipt_signing_workflow(self) -> None:
        """Test complete receipt creation and verification workflow."""
        # Create a receipt
        receipt = Receipt(
            version="1.0.0",
            receipt_id="run-integration-test",
            timestamp="2026-01-01T00:00:00Z",
            content_hash="0x" + "ab" * 32,
            verdict=Verdict(passed=True, gate_id="integration"),
            provenance=None,
            metadata={
                "task": "integration-test",
                "passed": True,
            },
        )

        # Sign it
        private_key, public_key = generate_keypair()
        signed = SignedReceipt.sign(receipt, private_key)

        # Verify
        assert signed.verify(PublicKeySet(signer=public_key.hex())).valid is True

        # Serialize and restore
        json_str = signed.to_json()
        restored = SignedReceipt.from_json(json_str)

        # Verify restored receipt
        assert restored.verify(PublicKeySet(signer=public_key.hex())).valid is True
        assert restored.receipt.receipt_id == "run-integration-test"
        assert restored.receipt.metadata["passed"] is True

    def test_hash_consistency(self) -> None:
        """Test that hashing is consistent."""
        data = b"test data for hashing"

        hash1 = sha256(data)
        hash2 = sha256(data)

        assert hash1 == hash2

        # Receipt hashing should be deterministic
        receipt = Receipt(
            version="1.0.0",
            receipt_id="test",
            timestamp="2026-01-01T00:00:00Z",
            content_hash="0x" + "00" * 32,
            verdict=Verdict(passed=True),
            provenance=None,
            metadata=None,
        )

        hash1 = receipt.hash_sha256()
        hash2 = receipt.hash_sha256()

        assert hash1 == hash2


class TestVersionInfo:
    def test_version_available(self) -> None:
        import hush
        assert hush.__version__ == "0.1.0"
