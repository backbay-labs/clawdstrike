"""Cryptographic primitives with native-first dispatch.

When the native Rust backend (hush_native) is available, crypto operations
are delegated to it for performance and consistency with the Rust engine.
Otherwise falls back to pure Python implementations using PyNaCl/pycryptodome.
"""

from __future__ import annotations

import hashlib

from Crypto.Hash import keccak as keccak_hash
from nacl.exceptions import BadSignatureError, CryptoError
from nacl.signing import SigningKey, VerifyKey

from clawdstrike.native import (
    NATIVE_AVAILABLE,
    keccak256_native,
    sha256_native,
    verify_ed25519_native,
)

# New native crypto functions (may be None if native module is old)
_generate_keypair_native = None
_sign_message_native = None
if NATIVE_AVAILABLE:
    try:
        import hush_native as _hn

        _generate_keypair_native = getattr(_hn, "generate_keypair_native", None)
        _sign_message_native = getattr(_hn, "sign_message_native", None)
        del _hn
    except ImportError:
        pass


def sha256(data: bytes | str) -> bytes:
    """Compute SHA-256 hash.

    Args:
        data: Input bytes or string to hash

    Returns:
        32-byte SHA-256 digest
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if NATIVE_AVAILABLE and sha256_native is not None:
        return bytes(sha256_native(data))
    return hashlib.sha256(data).digest()


def keccak256(data: bytes | str) -> bytes:
    """Compute Keccak-256 hash.

    Uses the original Keccak-256 algorithm (pre-SHA3 standardization),
    compatible with Ethereum and other blockchain implementations.

    Args:
        data: Input bytes or string to hash

    Returns:
        32-byte Keccak-256 digest
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    if NATIVE_AVAILABLE and keccak256_native is not None:
        return bytes(keccak256_native(data))
    return keccak_hash.new(digest_bits=256, data=data).digest()


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns:
        Tuple of (private_key, public_key) as 32-byte values
    """
    if NATIVE_AVAILABLE and _generate_keypair_native is not None:
        priv_bytes, pub_bytes = _generate_keypair_native()
        return bytes(priv_bytes), bytes(pub_bytes)
    signing_key = SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def sign_message(message: bytes, private_key: bytes) -> bytes:
    """Sign a message with Ed25519.

    Args:
        message: Message bytes to sign
        private_key: 32-byte Ed25519 private key

    Returns:
        64-byte signature
    """
    if NATIVE_AVAILABLE and _sign_message_native is not None:
        return bytes(_sign_message_native(message, private_key))
    signing_key = SigningKey(private_key)
    signed = signing_key.sign(message)
    return signed.signature


def verify_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        message: Original message bytes
        signature: 64-byte signature
        public_key: 32-byte Ed25519 public key

    Returns:
        True if signature is valid, False otherwise
    """
    if NATIVE_AVAILABLE and verify_ed25519_native is not None:
        try:
            return verify_ed25519_native(message, signature, public_key)
        except Exception:
            return False
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(message, signature)
        return True
    except (BadSignatureError, CryptoError, ValueError, TypeError):
        return False


__all__ = [
    "sha256",
    "keccak256",
    "generate_keypair",
    "sign_message",
    "verify_signature",
]
