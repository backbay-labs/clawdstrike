"""Tests for envelope encode/decode/verify (cross-language determinism)."""

from __future__ import annotations

import json

import rfc8785
from nacl.signing import SigningKey

from spine_reticulum.envelope import (
    build_signed_envelope,
    canonical_bytes_for_envelope,
    canonical_bytes_without_signature,
    canonical_json_bytes,
    compute_envelope_hash,
    issuer_from_public_key_hex,
    parse_issuer,
    sign_canonical,
    verify_envelope,
    verify_signature_by_issuer,
)


def _make_signing_key() -> SigningKey:
    """Deterministic test key (seed = 32 zero bytes)."""
    return SigningKey(b"\x00" * 32)


class TestCanonicalJson:
    """Verify RFC 8785 canonical JSON determinism."""

    def test_key_ordering(self) -> None:
        data = {"z": 1, "a": 2}
        result = canonical_json_bytes(data)
        assert json.loads(result) == data
        assert result.index(b'"a"') < result.index(b'"z"')

    def test_nested_key_ordering(self) -> None:
        data = {"nested": {"b": 1, "a": 2}}
        result = canonical_json_bytes(data)
        parsed = json.loads(result)
        assert parsed == data
        assert result.index(b'"a"') < result.index(b'"b"')

    def test_numbers(self) -> None:
        data = {"numbers": [1, 2.0, -3, 0]}
        result = canonical_json_bytes(data)
        parsed = json.loads(result)
        assert parsed["numbers"] == [1, 2.0, -3, 0]

    def test_null_and_bool(self) -> None:
        data = {"null_field": None, "bool": True}
        result = canonical_json_bytes(data)
        parsed = json.loads(result)
        assert parsed["null_field"] is None
        assert parsed["bool"] is True

    def test_unicode(self) -> None:
        data = {"text": "caf\u00e9"}
        result = canonical_json_bytes(data)
        parsed = json.loads(result)
        assert parsed["text"] == "caf\u00e9"

    def test_deterministic(self) -> None:
        data = {"x": 1, "a": [True, None, "hello"]}
        b1 = canonical_json_bytes(data)
        b2 = canonical_json_bytes(data)
        assert b1 == b2


class TestEnvelopeHash:
    def test_hash_is_0x_prefixed_sha256(self) -> None:
        unsigned = {"schema": "test", "seq": 1}
        h = compute_envelope_hash(unsigned)
        assert h.startswith("0x")
        assert len(h) == 66  # 0x + 64 hex chars

    def test_hash_determinism(self) -> None:
        unsigned = {"schema": "test", "seq": 1, "issuer": "aegis:ed25519:" + "ab" * 32}
        h1 = compute_envelope_hash(unsigned)
        h2 = compute_envelope_hash(unsigned)
        assert h1 == h2

    def test_hash_changes_on_mutation(self) -> None:
        unsigned = {"schema": "test", "seq": 1}
        h1 = compute_envelope_hash(unsigned)
        unsigned["seq"] = 2
        h2 = compute_envelope_hash(unsigned)
        assert h1 != h2


class TestIssuer:
    def test_issuer_from_public_key(self) -> None:
        sk = _make_signing_key()
        pk_hex = sk.verify_key.encode().hex()
        issuer = issuer_from_public_key_hex(pk_hex)
        assert issuer.startswith("aegis:ed25519:")
        assert parse_issuer(issuer) == pk_hex

    def test_parse_issuer_invalid(self) -> None:
        try:
            parse_issuer("bad:format:key")
            assert False, "Should have raised ValueError"
        except ValueError as exc:
            assert "Unsupported issuer format" in str(exc)


class TestVerifyEnvelope:
    def test_roundtrip(self) -> None:
        """Build and verify an envelope (self-signed roundtrip)."""
        sk = _make_signing_key()
        envelope = build_signed_envelope(
            sk,
            seq=1,
            prev_envelope_hash=None,
            issued_at="2026-01-01T00:00:00Z",
            fact={"schema": "clawdstrike.spine.fact.revocation.v1", "data": {}},
        )
        assert envelope["signature"].startswith("0x")
        assert verify_envelope(envelope) is True

    def test_tampered_fact(self) -> None:
        sk = _make_signing_key()
        envelope = build_signed_envelope(
            sk,
            seq=1,
            prev_envelope_hash=None,
            issued_at="2026-01-01T00:00:00Z",
            fact={"schema": "clawdstrike.spine.fact.revocation.v1", "data": {}},
        )
        envelope["fact"]["data"] = {"tampered": True}
        try:
            verify_envelope(envelope)
            assert False, "Should have raised ValueError"
        except ValueError as exc:
            assert "Hash mismatch" in str(exc)

    def test_tampered_signature(self) -> None:
        sk = _make_signing_key()
        envelope = build_signed_envelope(
            sk,
            seq=1,
            prev_envelope_hash=None,
            issued_at="2026-01-01T00:00:00Z",
            fact={"schema": "clawdstrike.spine.fact.heartbeat.v1"},
        )
        sig = envelope["signature"]
        flipped = sig[:4] + ("0" if sig[4] != "0" else "1") + sig[5:]
        envelope["signature"] = flipped
        assert verify_envelope(envelope) is False

    def test_wrong_key_returns_hash_mismatch(self) -> None:
        sk1 = SigningKey(b"\x00" * 32)
        sk2 = SigningKey(b"\x01" * 32)
        envelope = build_signed_envelope(
            sk1,
            seq=1,
            prev_envelope_hash=None,
            issued_at="2026-01-01T00:00:00Z",
            fact={"schema": "clawdstrike.spine.fact.heartbeat.v1"},
        )
        pubkey2_hex = sk2.verify_key.encode().hex()
        envelope["issuer"] = f"aegis:ed25519:{pubkey2_hex}"
        try:
            verify_envelope(envelope)
            assert False, "Should have raised ValueError due to hash mismatch"
        except ValueError:
            pass

    def test_invalid_issuer_format(self) -> None:
        sk = _make_signing_key()
        envelope = build_signed_envelope(
            sk, seq=1, prev_envelope_hash=None,
            issued_at="2026-01-01T00:00:00Z",
            fact={"schema": "test"},
        )
        envelope["issuer"] = "bad:format:key"
        try:
            verify_envelope(envelope)
            assert False, "Should have raised ValueError"
        except ValueError as exc:
            assert "Unsupported issuer format" in str(exc)

    def test_build_with_capability_token(self) -> None:
        sk = _make_signing_key()
        envelope = build_signed_envelope(
            sk,
            seq=42,
            prev_envelope_hash="0x" + "ab" * 32,
            issued_at="2026-01-01T00:00:00Z",
            capability_token={"scope": "test"},
            fact={"schema": "clawdstrike.spine.fact.run.v1"},
        )
        assert envelope["capability_token"] == {"scope": "test"}
        assert envelope["seq"] == 42
        assert verify_envelope(envelope) is True


class TestVerifySignatureByIssuer:
    def test_signed_head_announcement(self) -> None:
        sk = _make_signing_key()
        pk_hex = sk.verify_key.encode().hex()
        issuer = issuer_from_public_key_hex(pk_hex)

        ha = {
            "schema": "aegis.spine.head_announcement.v1",
            "issuer": issuer,
            "seq": 5,
            "head_hash": "0x" + "aa" * 32,
            "sent_at": "2026-01-01T00:00:00Z",
        }
        ha["signature"] = sign_canonical(sk, canonical_bytes_without_signature(ha))
        assert verify_signature_by_issuer(ha) is True

    def test_tampered_head_announcement(self) -> None:
        sk = _make_signing_key()
        pk_hex = sk.verify_key.encode().hex()
        issuer = issuer_from_public_key_hex(pk_hex)

        ha = {
            "schema": "aegis.spine.head_announcement.v1",
            "issuer": issuer,
            "seq": 5,
            "head_hash": "0x" + "aa" * 32,
            "sent_at": "2026-01-01T00:00:00Z",
        }
        ha["signature"] = sign_canonical(sk, canonical_bytes_without_signature(ha))
        ha["seq"] = 99
        assert verify_signature_by_issuer(ha) is False
