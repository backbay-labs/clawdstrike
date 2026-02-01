"""Tests for hush.core cryptographic primitives."""

import pytest
from hush.core import sha256, keccak256, verify_signature, sign_message, generate_keypair


class TestSha256:
    def test_sha256_bytes(self) -> None:
        result = sha256(b"hello")
        assert isinstance(result, bytes)
        assert len(result) == 32
        # Known SHA-256 hash of "hello"
        expected = bytes.fromhex(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert result == expected

    def test_sha256_string(self) -> None:
        result = sha256("hello")
        expected = bytes.fromhex(
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )
        assert result == expected

    def test_sha256_empty(self) -> None:
        result = sha256(b"")
        expected = bytes.fromhex(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert result == expected


class TestKeccak256:
    def test_keccak256_bytes(self) -> None:
        result = keccak256(b"hello")
        assert isinstance(result, bytes)
        assert len(result) == 32

    def test_keccak256_string(self) -> None:
        result = keccak256("hello")
        assert isinstance(result, bytes)
        assert len(result) == 32


class TestSignature:
    def test_generate_keypair(self) -> None:
        private_key, public_key = generate_keypair()
        assert isinstance(private_key, bytes)
        assert isinstance(public_key, bytes)
        assert len(private_key) == 32
        assert len(public_key) == 32

    def test_sign_and_verify(self) -> None:
        private_key, public_key = generate_keypair()
        message = b"test message"

        signature = sign_message(message, private_key)
        assert isinstance(signature, bytes)
        assert len(signature) == 64

        assert verify_signature(message, signature, public_key) is True

    def test_verify_wrong_message(self) -> None:
        private_key, public_key = generate_keypair()
        message = b"test message"

        signature = sign_message(message, private_key)

        assert verify_signature(b"wrong message", signature, public_key) is False

    def test_verify_wrong_key(self) -> None:
        private_key, public_key = generate_keypair()
        _, other_public_key = generate_keypair()
        message = b"test message"

        signature = sign_message(message, private_key)

        assert verify_signature(message, signature, other_public_key) is False

    def test_verify_invalid_signature(self) -> None:
        _, public_key = generate_keypair()
        message = b"test message"
        invalid_signature = b"\x00" * 64

        assert verify_signature(message, invalid_signature, public_key) is False
