"""Integration tests for hush SDK."""

import pytest
from clawdstrike import (
    __version__,
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
        import os
        from importlib.metadata import PackageNotFoundError, version
        import re

        mode = os.getenv("CLAWDSTRIKE_PY_PACKAGE_MODE", "auto").strip().lower()
        if mode not in {"auto", "source", "installed"}:
            raise AssertionError(
                "CLAWDSTRIKE_PY_PACKAGE_MODE must be one of: auto, source, installed"
            )

        assert re.fullmatch(r"\d+\.\d+\.\d+", __version__) is not None

        if mode == "source":
            return

        try:
            installed_version = version("clawdstrike")
        except PackageNotFoundError:
            if mode == "installed":
                raise AssertionError(
                    "Installed package metadata not found for clawdstrike in installed mode"
                )
            return

        # In source mode the checkout may not match an installed wheel version.
        if mode == "auto" and __version__ != installed_version:
            pytest.skip("Source checkout version differs from installed package metadata")

        # Keep the public module version aligned with installed package metadata.
        assert __version__ == installed_version
