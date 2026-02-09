"""Tests for native Rust backend (when available)."""
import pytest

from clawdstrike.native import NATIVE_AVAILABLE


@pytest.mark.skipif(not NATIVE_AVAILABLE, reason="Native backend not available")
class TestNativeBackend:
    """Tests that only run when native backend is available."""

    def test_is_native_available(self):
        """is_native_available should return True."""
        from clawdstrike.native import is_native_available
        assert is_native_available is not None
        assert is_native_available() is True

    def test_sha256_native(self):
        """sha256_native should match pure Python."""
        from clawdstrike.native import sha256_native
        from clawdstrike.core import sha256

        assert sha256_native is not None

        data = b"hello world"
        native_result = sha256_native(data)
        python_result = sha256(data)

        assert native_result == python_result

    def test_keccak256_native(self):
        """keccak256_native should match pure Python."""
        from clawdstrike.native import keccak256_native
        from clawdstrike.core import keccak256

        if keccak256_native is None:
            pytest.skip("keccak256_native not available")

        data = b"hello world"
        native_result = keccak256_native(data)
        python_result = keccak256(data)

        assert native_result == python_result

    def test_merkle_root_native(self):
        """merkle_root_native should match pure Python."""
        from clawdstrike.native import merkle_root_native
        from clawdstrike.merkle import hash_leaf, compute_root

        assert merkle_root_native is not None

        leaves = [hash_leaf(f"leaf{i}".encode()) for i in range(4)]

        native_result = merkle_root_native(leaves)
        python_result = compute_root(leaves)

        assert native_result == python_result

    def test_canonicalize_native(self):
        """canonicalize_native should match pure Python."""
        from clawdstrike.native import canonicalize_native
        from clawdstrike.canonical import canonicalize
        import json

        if canonicalize_native is None:
            pytest.skip("canonicalize_native not available")

        obj = {"z": 1, "a": 2, "nested": {"c": 3, "b": 4}}
        json_str = json.dumps(obj)

        native_result = canonicalize_native(json_str)
        python_result = canonicalize(obj)

        assert native_result == python_result


class TestNativeAvailabilityFlag:
    """Tests for NATIVE_AVAILABLE flag."""

    def test_native_available_is_bool(self):
        """NATIVE_AVAILABLE should be a boolean."""
        assert isinstance(NATIVE_AVAILABLE, bool)

    def test_package_works_without_native(self):
        """Package should work even without native backend."""
        from clawdstrike import sha256, compute_root, canonicalize, hash_leaf

        # These should work regardless of native availability
        assert len(sha256(b"test")) == 32
        assert canonicalize({"a": 1}) == '{"a":1}'

        # Merkle tree should work
        leaves = [hash_leaf(b"a"), hash_leaf(b"b")]
        root = compute_root(leaves)
        assert len(root) == 32

    def test_native_available_exported(self):
        """NATIVE_AVAILABLE should be importable from clawdstrike package."""
        from clawdstrike import NATIVE_AVAILABLE as imported_flag
        assert isinstance(imported_flag, bool)
