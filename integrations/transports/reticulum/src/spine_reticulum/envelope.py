"""Spine envelope encode/decode/verify -- Python port of crates/spine/src/envelope.rs.

Uses RFC 8785 canonical JSON (JCS) for deterministic serialization and
PyNaCl (libsodium) for Ed25519 signature verification.  These choices
ensure byte-identical output and compatible signatures with the Rust
hush-core implementation.

Adapted from ``cyntra.trust.spine.crypto`` in the Backbay platform kernel.
"""

from __future__ import annotations

import hashlib
from typing import Any

import rfc8785
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

ENVELOPE_SCHEMA_V1 = "aegis.spine.envelope.v1"
ISSUER_PREFIX = "aegis:ed25519:"
PUBKEY_HEX_LEN = 64


def _strip_0x(s: str) -> str:
    return s[2:] if s.startswith("0x") else s


def canonical_json_bytes(value: dict[str, Any]) -> bytes:
    """RFC 8785 canonical JSON encoding."""
    return rfc8785.dumps(value)


def sha256_hex_prefixed(data: bytes) -> str:
    """0x-prefixed SHA-256 hex digest."""
    return "0x" + hashlib.sha256(data).hexdigest()


def canonical_bytes_for_envelope(envelope_obj: dict[str, Any]) -> bytes:
    """Canonical bytes used by Spine v1 for envelope hashing/signing.

    Strips both ``signature`` and ``envelope_hash`` before canonicalizing.
    """
    unsigned = {k: v for k, v in envelope_obj.items()
                if k not in ("envelope_hash", "signature")}
    return canonical_json_bytes(unsigned)


def canonical_bytes_without_signature(obj: dict[str, Any]) -> bytes:
    """Canonical bytes for signing objects that only exclude ``signature``."""
    stripped = {k: v for k, v in obj.items() if k != "signature"}
    return canonical_json_bytes(stripped)


def compute_envelope_hash(envelope_obj: dict[str, Any]) -> str:
    """Compute 0x-prefixed SHA-256 hash of canonical JSON (unsigned envelope)."""
    return sha256_hex_prefixed(canonical_bytes_for_envelope(envelope_obj))


def issuer_from_public_key_hex(public_key_hex: str) -> str:
    """Build an issuer string from a public key hex (with or without 0x prefix)."""
    return f"{ISSUER_PREFIX}{_strip_0x(public_key_hex).lower()}"


def parse_issuer(issuer: str) -> str:
    """Return the Ed25519 public key hex (no 0x) from an issuer string."""
    if not issuer.startswith(ISSUER_PREFIX):
        raise ValueError(f"Unsupported issuer format: {issuer}")
    pk = issuer[len(ISSUER_PREFIX):].lower()
    if len(pk) != PUBKEY_HEX_LEN:
        raise ValueError(f"Invalid pubkey length: {len(pk)}")
    return pk


def verify_envelope(envelope: dict[str, Any]) -> bool:
    """Verify envelope hash integrity and Ed25519 signature.

    Strips ``envelope_hash`` and ``signature``, recomputes canonical bytes,
    checks hash match, then verifies the Ed25519 signature against the
    issuer public key.

    Raises ``ValueError`` on structural problems (bad issuer format, hash
    mismatch).  Returns ``False`` if the signature is invalid.
    """
    issuer = envelope.get("issuer", "")
    sig_hex = envelope.get("signature", "")
    claimed_hash = envelope.get("envelope_hash", "")

    pub_hex = parse_issuer(issuer)

    computed_hash = compute_envelope_hash(envelope)
    if computed_hash != claimed_hash:
        raise ValueError(
            f"Hash mismatch: expected {claimed_hash}, computed {computed_hash}"
        )

    canonical = canonical_bytes_for_envelope(envelope)
    vk = VerifyKey(bytes.fromhex(pub_hex))
    try:
        vk.verify(canonical, bytes.fromhex(_strip_0x(sig_hex)))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def verify_signature_by_issuer(obj: dict[str, Any]) -> bool:
    """Verify a Spine object signature against its ``issuer`` field.

    Used for head announcements and other signed objects that carry an
    ``issuer`` and ``signature`` but no ``envelope_hash``.
    """
    try:
        pub_hex = parse_issuer(obj.get("issuer", ""))
        vk = VerifyKey(bytes.fromhex(pub_hex))
        sig_hex = _strip_0x(str(obj.get("signature", "")))
        vk.verify(canonical_bytes_without_signature(obj), bytes.fromhex(sig_hex))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def sign_canonical(signing_key: SigningKey, data: bytes) -> str:
    """Sign data with Ed25519 and return 0x-prefixed hex signature."""
    return "0x" + signing_key.sign(data).signature.hex()


def build_signed_envelope(
    signing_key: SigningKey,
    *,
    schema: str = ENVELOPE_SCHEMA_V1,
    seq: int,
    prev_envelope_hash: str | None,
    issued_at: str,
    capability_token: dict[str, Any] | None = None,
    fact: dict[str, Any],
) -> dict[str, Any]:
    """Build and sign a new envelope (useful for tests and the adapter itself).

    The ``signing_key`` is a PyNaCl ``SigningKey``.  The issuer is derived
    from its verify (public) key.  Signature is 0x-prefixed hex, matching
    the Cyntra/Spine convention.
    """
    pubkey_hex = signing_key.verify_key.encode().hex()
    issuer = issuer_from_public_key_hex(pubkey_hex)

    unsigned: dict[str, Any] = {
        "schema": schema,
        "issuer": issuer,
        "seq": seq,
        "prev_envelope_hash": prev_envelope_hash,
        "issued_at": issued_at,
        "fact": fact,
    }
    if capability_token is not None:
        unsigned["capability_token"] = capability_token

    envelope_hash = compute_envelope_hash(unsigned)
    signature = sign_canonical(signing_key, canonical_bytes_for_envelope(unsigned))

    return {
        **unsigned,
        "envelope_hash": envelope_hash,
        "signature": signature,
    }
