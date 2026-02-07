"""Tests for the hash-chained JSONL audit log."""

from __future__ import annotations

import json
import os

import pytest

from spine_reticulum.audit import AuditLog, verify_chain


@pytest.fixture()
def audit_path(tmp_path) -> str:
    return str(tmp_path / "audit.jsonl")


class TestAuditLog:
    def test_log_forward(self, audit_path: str) -> None:
        log = AuditLog(audit_path)
        log.log_forward("0xabc", direction="inbound", source="peer1")
        assert os.path.exists(audit_path)
        with open(audit_path) as f:
            entry = json.loads(f.readline())
        assert entry["kind"] == "forward"
        assert entry["envelope_hash"] == "0xabc"
        assert entry["direction"] == "inbound"
        assert "prev_hash" in entry
        assert "hash" in entry
        assert "ts" in entry
        assert entry["prev_hash"] == AuditLog.GENESIS_HASH

    def test_log_drop(self, audit_path: str) -> None:
        log = AuditLog(audit_path)
        log.log_drop("0xdef", reason="bad_sig")
        with open(audit_path) as f:
            entry = json.loads(f.readline())
        assert entry["kind"] == "drop"
        assert entry["reason"] == "bad_sig"
        assert entry["hash"].startswith("0x")

    def test_log_fork(self, audit_path: str) -> None:
        log = AuditLog(audit_path)
        log.log_fork("issuer1", 5, "0xold", "0xnew")
        with open(audit_path) as f:
            entry = json.loads(f.readline())
        assert entry["kind"] == "fork"
        assert entry["seq"] == 5

    def test_log_error(self, audit_path: str) -> None:
        log = AuditLog(audit_path)
        log.log_error("something broke")
        with open(audit_path) as f:
            entry = json.loads(f.readline())
        assert entry["kind"] == "error"
        assert entry["message"] == "something broke"

    def test_log_gateway(self, audit_path: str) -> None:
        log = AuditLog(audit_path)
        log.log_gateway("0xgw", direction="nats_inbound", nats_subject="spine.env.1")
        with open(audit_path) as f:
            entry = json.loads(f.readline())
        assert entry["kind"] == "gateway"
        assert entry["envelope_hash"] == "0xgw"
        assert entry["nats_subject"] == "spine.env.1"

    def test_log_ingest(self, audit_path: str) -> None:
        log = AuditLog(audit_path)
        log.log_ingest(sender="peer1", envelope_hash="0xing", issuer="iss1", seq=3)
        with open(audit_path) as f:
            entry = json.loads(f.readline())
        assert entry["kind"] == "ingest"
        assert entry["sender"] == "peer1"
        assert entry["seq"] == 3

    def test_open_class_method(self, audit_path: str) -> None:
        log = AuditLog.open(audit_path)
        log.log_error("test open")
        with open(audit_path) as f:
            entry = json.loads(f.readline())
        assert entry["kind"] == "error"


class TestHashChain:
    def test_chain_integrity(self, audit_path: str) -> None:
        log = AuditLog(audit_path)
        log.log_forward("0x1", direction="inbound")
        log.log_forward("0x2", direction="outbound")
        log.log_drop("0x3", reason="test")

        valid, count = verify_chain(audit_path)
        assert valid is True
        assert count == 3

    def test_hash_chain_links(self, audit_path: str) -> None:
        """Each entry's prev_hash should be the previous entry's hash."""
        log = AuditLog(audit_path)
        log.log_forward("0x1", direction="inbound")
        log.log_forward("0x2", direction="outbound")

        with open(audit_path) as f:
            lines = f.readlines()
        e1 = json.loads(lines[0])
        e2 = json.loads(lines[1])
        assert e1["prev_hash"] == AuditLog.GENESIS_HASH
        assert e2["prev_hash"] == e1["hash"]

    def test_tamper_detection(self, audit_path: str) -> None:
        log = AuditLog(audit_path)
        log.log_forward("0x1", direction="inbound")
        log.log_forward("0x2", direction="outbound")
        log.log_forward("0x3", direction="inbound")

        # Tamper with the second line
        with open(audit_path, "r") as f:
            lines = f.readlines()
        entry = json.loads(lines[1])
        entry["envelope_hash"] = "0xtampered"
        lines[1] = json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n"
        with open(audit_path, "w") as f:
            f.writelines(lines)

        valid, bad_line = verify_chain(audit_path)
        assert valid is False
        # The tampered entry will fail hash verification
        assert bad_line >= 1

    def test_empty_log_is_valid(self, audit_path: str) -> None:
        valid, count = verify_chain(audit_path)
        assert valid is True
        assert count == 0

    def test_recovery_after_restart(self, audit_path: str) -> None:
        """A new AuditLog instance recovers the chain head from the file."""
        log1 = AuditLog(audit_path)
        log1.log_forward("0x1", direction="inbound")
        log1.log_forward("0x2", direction="outbound")

        # Simulate restart: create a new instance
        log2 = AuditLog(audit_path)
        log2.log_forward("0x3", direction="inbound")

        valid, count = verify_chain(audit_path)
        assert valid is True
        assert count == 3
