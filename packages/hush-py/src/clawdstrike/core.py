"""Pure Python cryptographic primitives.

Provides SHA-256, Keccak-256 hashing and Ed25519 signature verification.
Uses PyNaCl for cryptographic operations and pycryptodome for Keccak-256.
"""

from __future__ import annotations

import hashlib
from typing import Union

from Crypto.Hash import keccak as keccak_hash
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


def sha256(data: Union[bytes, str]) -> bytes:
    """Compute SHA-256 hash.

    Args:
        data: Input bytes or string to hash

    Returns:
        32-byte SHA-256 digest
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


def keccak256(data: Union[bytes, str]) -> bytes:
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
    return keccak_hash.new(digest_bits=256, data=data).digest()


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns:
        Tuple of (private_key, public_key) as 32-byte values
    """
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
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(message, signature)
        return True
    except (BadSignatureError, Exception):
        return False


__all__ = [
    "sha256",
    "keccak256",
    "generate_keypair",
    "sign_message",
    "verify_signature",
]
