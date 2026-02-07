"""Tests for CBOR encoding and fragmentation."""

from __future__ import annotations

import json

from spine_reticulum.encoding import (
    CBOR_MAGIC,
    FRAGMENT_MAGIC,
    FragmentReassembler,
    decode_envelope,
    encode_envelope_cbor,
    fragment_envelope,
    parse_fragment_header,
)


class TestCborEncoding:
    def test_roundtrip(self) -> None:
        envelope = {"schema": "test", "seq": 1, "data": "hello"}
        encoded = encode_envelope_cbor(envelope)
        assert encoded[:2] == CBOR_MAGIC
        decoded = decode_envelope(encoded)
        assert decoded == envelope

    def test_smaller_than_json(self) -> None:
        envelope = {
            "schema": "aegis.spine.envelope.v1",
            "issuer": "aegis:ed25519:" + "aa" * 32,
            "seq": 42,
            "fact": {"schema": "clawdstrike.spine.fact.heartbeat.v1"},
            "envelope_hash": "0x" + "bb" * 32,
            "signature": "0x" + "cc" * 64,
        }
        cbor_bytes = encode_envelope_cbor(envelope)
        json_bytes = json.dumps(envelope).encode()
        # CBOR should be at least 20% smaller
        assert len(cbor_bytes) < len(json_bytes) * 0.95

    def test_decode_json_fallback(self) -> None:
        envelope = {"schema": "test", "seq": 1}
        json_bytes = json.dumps(envelope).encode()
        decoded = decode_envelope(json_bytes)
        assert decoded == envelope


class TestFragmentation:
    def test_no_fragmentation_when_small(self) -> None:
        data = b"small payload"
        frags = fragment_envelope(data, mtu=500)
        assert len(frags) == 1
        assert frags[0] == data

    def test_fragment_and_reassemble(self) -> None:
        data = b"x" * 2000
        msg_id = b"\x01\x02\x03\x04"
        frags = fragment_envelope(data, mtu=500, message_id=msg_id)
        assert len(frags) > 1
        for f in frags:
            assert len(f) <= 500

        # Reassemble
        reassembler = FragmentReassembler()
        result = None
        for f in frags:
            result = reassembler.add_fragment(f)
        assert result is not None
        assert result == data

    def test_fragment_header_parsing(self) -> None:
        data = b"x" * 2000
        msg_id = b"\xaa\xbb\xcc\xdd"
        frags = fragment_envelope(data, mtu=500, message_id=msg_id)
        mid, idx, total, payload = parse_fragment_header(frags[0])
        assert mid == msg_id
        assert idx == 0
        assert total == len(frags)
        assert len(payload) > 0

    def test_out_of_order_reassembly(self) -> None:
        data = b"y" * 1500
        msg_id = b"\x10\x20\x30\x40"
        frags = fragment_envelope(data, mtu=500, message_id=msg_id)
        # Deliver in reverse order
        reassembler = FragmentReassembler()
        result = None
        for f in reversed(frags):
            result = reassembler.add_fragment(f)
        assert result is not None
        assert result == data

    def test_mtu_too_small_raises(self) -> None:
        try:
            fragment_envelope(b"data", mtu=5)
            assert False, "Should have raised ValueError"
        except ValueError as exc:
            assert "too small" in str(exc)

    def test_reassembler_evicts_stale(self) -> None:
        reassembler = FragmentReassembler(max_age_secs=0)
        data = b"z" * 2000
        frags = fragment_envelope(data, mtu=500, message_id=b"\x01\x02\x03\x04")
        # Add first fragment, then evict by age
        reassembler.add_fragment(frags[0])
        assert reassembler.pending_count == 1
        # Adding a fragment from a different message triggers eviction
        import time
        time.sleep(0.01)
        data2 = b"w" * 2000
        frags2 = fragment_envelope(data2, mtu=500, message_id=b"\x05\x06\x07\x08")
        reassembler.add_fragment(frags2[0])
        # Old reassembly should be evicted
        assert reassembler.pending_count == 1

    def test_reassembler_max_pending(self) -> None:
        reassembler = FragmentReassembler(max_pending=2)
        # Start 3 reassemblies; the oldest should be evicted
        for i in range(3):
            msg_id = i.to_bytes(4, "big")
            data = b"a" * 2000
            frags = fragment_envelope(data, mtu=500, message_id=msg_id)
            reassembler.add_fragment(frags[0])
        assert reassembler.pending_count == 2
