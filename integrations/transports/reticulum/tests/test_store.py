"""Tests for SQLite envelope store with dedup, monotonicity, and fork detection."""

from __future__ import annotations

import pytest

from spine_reticulum.store import EnvelopeIngestResult, ForkDetected, SpineStore


def _make_envelope(
    issuer: str = "aegis:ed25519:" + "aa" * 32,
    seq: int = 0,
    envelope_hash: str = "0x" + "bb" * 32,
    prev_envelope_hash: str | None = None,
    fact_schema: str = "clawdstrike.spine.fact.heartbeat.v1",
) -> dict:
    return {
        "schema": "aegis.spine.envelope.v1",
        "issuer": issuer,
        "seq": seq,
        "prev_envelope_hash": prev_envelope_hash,
        "issued_at": "2026-01-01T00:00:00Z",
        "fact": {"schema": fact_schema},
        "envelope_hash": envelope_hash,
        "signature": "0x" + "cc" * 64,
    }


@pytest.fixture()
def store(tmp_path):
    db = str(tmp_path / "test.db")
    s = SpineStore(db)
    yield s
    s.close()


class TestInsertAndDedup:
    def test_insert_first_envelope(self, store: SpineStore) -> None:
        env = _make_envelope(seq=0, envelope_hash="0x" + "01" * 32)
        result = store.insert(env)
        assert result.inserted is True
        assert result.duplicate is False
        assert store.count() == 1

    def test_dedup_by_hash(self, store: SpineStore) -> None:
        env = _make_envelope(seq=0, envelope_hash="0x" + "01" * 32)
        r1 = store.insert(env)
        r2 = store.insert(env)
        assert r1.inserted is True
        assert r2.duplicate is True
        assert store.count() == 1

    def test_has_envelope(self, store: SpineStore) -> None:
        env = _make_envelope(seq=0, envelope_hash="0x" + "01" * 32)
        assert store.has_envelope(env["envelope_hash"]) is False
        store.insert(env)
        assert store.has_envelope(env["envelope_hash"]) is True

    def test_insert_envelope_convenience(self, store: SpineStore) -> None:
        env = _make_envelope(seq=0, envelope_hash="0x" + "01" * 32)
        assert store.insert_envelope(env) is True
        assert store.insert_envelope(env) is False


class TestContiguousChain:
    def test_first_envelope_extends_chain(self, store: SpineStore) -> None:
        issuer = "aegis:ed25519:" + "aa" * 32
        env = _make_envelope(issuer=issuer, seq=0, envelope_hash="0x" + "01" * 32)
        result = store.insert(env)
        assert result.extended_contiguous_chain is True
        assert result.out_of_order is False
        head = store.get_contiguous_head(issuer)
        assert head is not None
        assert head[0] == 0

    def test_sequential_envelopes_extend_chain(self, store: SpineStore) -> None:
        issuer = "aegis:ed25519:" + "aa" * 32
        env0 = _make_envelope(issuer=issuer, seq=0, envelope_hash="0x" + "01" * 32)
        env1 = _make_envelope(issuer=issuer, seq=1, envelope_hash="0x" + "02" * 32,
                              prev_envelope_hash="0x" + "01" * 32)
        store.insert(env0)
        result = store.insert(env1)
        assert result.extended_contiguous_chain is True
        assert result.out_of_order is False
        head = store.get_contiguous_head(issuer)
        assert head is not None
        assert head[0] == 1

    def test_out_of_order_detected(self, store: SpineStore) -> None:
        issuer = "aegis:ed25519:" + "aa" * 32
        env2 = _make_envelope(issuer=issuer, seq=2, envelope_hash="0x" + "02" * 32)
        result = store.insert(env2)
        assert result.out_of_order is True
        assert result.extended_contiguous_chain is False


class TestForkDetection:
    def test_fork_detected_via_insert(self, store: SpineStore) -> None:
        issuer = "aegis:ed25519:" + "aa" * 32
        env_a = _make_envelope(issuer=issuer, seq=0, envelope_hash="0x" + "a1" * 32)
        env_b = _make_envelope(issuer=issuer, seq=0, envelope_hash="0x" + "b2" * 32)
        r1 = store.insert(env_a)
        assert r1.fork_detected is False
        r2 = store.insert(env_b)
        assert r2.fork_detected is True

    def test_fork_raises_via_insert_envelope(self, store: SpineStore) -> None:
        issuer = "aegis:ed25519:" + "aa" * 32
        env_a = _make_envelope(issuer=issuer, seq=0, envelope_hash="0x" + "a1" * 32)
        env_b = _make_envelope(issuer=issuer, seq=0, envelope_hash="0x" + "b2" * 32)
        store.insert_envelope(env_a)
        with pytest.raises(ForkDetected) as exc_info:
            store.insert_envelope(env_b)
        assert exc_info.value.seq == 0
        assert exc_info.value.issuer == issuer


class TestHeadTracking:
    def test_head_updated(self, store: SpineStore) -> None:
        issuer = "aegis:ed25519:" + "aa" * 32
        env0 = _make_envelope(issuer=issuer, seq=0, envelope_hash="0x" + "01" * 32)
        env1 = _make_envelope(issuer=issuer, seq=1, envelope_hash="0x" + "02" * 32,
                              prev_envelope_hash="0x" + "01" * 32)
        store.insert(env0)
        head = store.get_head(issuer)
        assert head is not None
        assert head["seq"] == 0

        store.insert(env1)
        head = store.get_head(issuer)
        assert head is not None
        assert head["seq"] == 1

    def test_head_none_for_unknown_issuer(self, store: SpineStore) -> None:
        assert store.get_head("aegis:ed25519:" + "ff" * 32) is None
        assert store.get_contiguous_head("aegis:ed25519:" + "ff" * 32) is None


class TestRangeQuery:
    def test_get_envelopes_range(self, store: SpineStore) -> None:
        issuer = "aegis:ed25519:" + "aa" * 32
        prev = None
        for i in range(5):
            env = _make_envelope(
                issuer=issuer, seq=i,
                envelope_hash=f"0x{i:064x}",
                prev_envelope_hash=prev,
            )
            store.insert(env)
            prev = env["envelope_hash"]

        result = store.get_envelopes_range(issuer, 1, 3)
        assert len(result) == 3
        seqs = [e["seq"] for e in result]
        assert seqs == [1, 2, 3]
