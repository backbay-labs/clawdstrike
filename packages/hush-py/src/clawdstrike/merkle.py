"""RFC 6962-compatible Merkle tree implementation.

This module implements Certificate Transparency style Merkle trees:
- LeafHash(data) = SHA256(0x00 || data)
- NodeHash(left, right) = SHA256(0x01 || left || right)

The tree uses left-balanced semantics (odd node carried upward unchanged).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List

from .core import sha256


def hash_leaf(data: bytes) -> bytes:
    """Hash a leaf node per RFC 6962: SHA256(0x00 || data).

    Args:
        data: Raw leaf data bytes

    Returns:
        32-byte leaf hash
    """
    return sha256(b'\x00' + data)


def hash_node(left: bytes, right: bytes) -> bytes:
    """Hash an internal node per RFC 6962: SHA256(0x01 || left || right).

    Args:
        left: 32-byte left child hash
        right: 32-byte right child hash

    Returns:
        32-byte node hash
    """
    return sha256(b'\x01' + left + right)


def compute_root(leaves: List[bytes]) -> bytes:
    """Compute Merkle root from leaf hashes.

    Uses left-balanced tree semantics: when a level has an odd number of
    nodes, the last node is carried upward unchanged (not duplicated).

    Args:
        leaves: List of 32-byte leaf hashes

    Returns:
        32-byte root hash

    Raises:
        ValueError: If leaves list is empty
    """
    if not leaves:
        raise ValueError("Cannot compute root of empty tree")

    if len(leaves) == 1:
        return leaves[0]

    # Build tree bottom-up
    current = list(leaves)
    while len(current) > 1:
        next_level: List[bytes] = []
        i = 0
        while i < len(current):
            if i + 1 < len(current):
                # Pair exists, hash them together
                next_level.append(hash_node(current[i], current[i + 1]))
            else:
                # Odd node out, carry upward unchanged
                next_level.append(current[i])
            i += 2
        current = next_level

    return current[0]


@dataclass
class MerkleProof:
    """Merkle inclusion proof.

    Attributes:
        tree_size: Total number of leaves in the tree
        leaf_index: Index of the leaf being proved (0-based)
        audit_path: List of sibling hashes from leaf to root
    """
    tree_size: int
    leaf_index: int
    audit_path: List[bytes]

    def verify(self, leaf_hash: bytes, expected_root: bytes) -> bool:
        """Verify this proof against an expected root.

        Args:
            leaf_hash: The 32-byte hash of the leaf being proved
            expected_root: The expected 32-byte root hash

        Returns:
            True if proof is valid, False otherwise
        """
        try:
            computed = self.compute_root(leaf_hash)
            return computed == expected_root
        except Exception:
            return False

    def compute_root(self, leaf_hash: bytes) -> bytes:
        """Compute the root from this proof and a leaf hash.

        Args:
            leaf_hash: The 32-byte hash of the leaf

        Returns:
            The computed 32-byte root hash

        Raises:
            ValueError: If proof is invalid
        """
        if self.tree_size == 0 or self.leaf_index >= self.tree_size:
            raise ValueError("Invalid proof: index out of range")

        h = leaf_hash
        idx = self.leaf_index
        size = self.tree_size
        path_iter = iter(self.audit_path)

        while size > 1:
            if idx % 2 == 0:
                # Current node is on the left
                if idx + 1 < size:
                    # Has a sibling on the right
                    sibling = next(path_iter, None)
                    if sibling is None:
                        raise ValueError("Invalid proof: missing sibling")
                    h = hash_node(h, sibling)
                # else: no sibling, carry upward unchanged
            else:
                # Current node is on the right, sibling on left
                sibling = next(path_iter, None)
                if sibling is None:
                    raise ValueError("Invalid proof: missing sibling")
                h = hash_node(sibling, h)

            idx //= 2
            size = (size + 1) // 2

        # Verify we consumed all siblings
        if next(path_iter, None) is not None:
            raise ValueError("Invalid proof: extra siblings")

        return h


class MerkleTree:
    """RFC 6962-compatible Merkle tree.

    Stores all tree levels for efficient proof generation.
    """

    def __init__(self, levels: List[List[bytes]]) -> None:
        """Initialize with pre-computed levels (internal use)."""
        self._levels = levels

    @classmethod
    def from_data(cls, data: List[bytes]) -> "MerkleTree":
        """Build tree from raw leaf data (will be hashed).

        Args:
            data: List of raw data bytes for each leaf

        Returns:
            MerkleTree instance

        Raises:
            ValueError: If data is empty
        """
        if not data:
            raise ValueError("Cannot build tree from empty data")

        leaves = [hash_leaf(d) for d in data]
        return cls.from_hashes(leaves)

    @classmethod
    def from_hashes(cls, leaf_hashes: List[bytes]) -> "MerkleTree":
        """Build tree from pre-hashed leaves.

        Args:
            leaf_hashes: List of 32-byte leaf hashes

        Returns:
            MerkleTree instance

        Raises:
            ValueError: If leaf_hashes is empty
        """
        if not leaf_hashes:
            raise ValueError("Cannot build tree from empty leaves")

        levels: List[List[bytes]] = [list(leaf_hashes)]
        current = list(leaf_hashes)

        while len(current) > 1:
            next_level: List[bytes] = []
            i = 0
            while i < len(current):
                if i + 1 < len(current):
                    next_level.append(hash_node(current[i], current[i + 1]))
                else:
                    next_level.append(current[i])
                i += 2
            levels.append(next_level)
            current = next_level

        return cls(levels)

    @property
    def leaf_count(self) -> int:
        """Number of leaves in the tree."""
        return len(self._levels[0]) if self._levels else 0

    @property
    def root(self) -> bytes:
        """The 32-byte root hash."""
        if not self._levels:
            return b'\x00' * 32
        return self._levels[-1][0]

    def inclusion_proof(self, leaf_index: int) -> MerkleProof:
        """Generate an inclusion proof for a leaf.

        Args:
            leaf_index: Index of the leaf (0-based)

        Returns:
            MerkleProof for the leaf

        Raises:
            ValueError: If leaf_index is out of range
        """
        if leaf_index < 0 or leaf_index >= self.leaf_count:
            raise ValueError(f"Index {leaf_index} out of range for {self.leaf_count} leaves")

        audit_path: List[bytes] = []
        idx = leaf_index

        for level in self._levels[:-1]:
            if len(level) <= 1:
                break

            if idx % 2 == 0:
                sibling_idx = idx + 1
                if sibling_idx < len(level):
                    audit_path.append(level[sibling_idx])
            else:
                audit_path.append(level[idx - 1])

            idx //= 2

        return MerkleProof(
            tree_size=self.leaf_count,
            leaf_index=leaf_index,
            audit_path=audit_path,
        )


def generate_proof(leaves: List[bytes], index: int) -> MerkleProof:
    """Generate a Merkle inclusion proof for a leaf at the given index.

    Args:
        leaves: List of 32-byte leaf hashes
        index: Index of the leaf to prove (0-based)

    Returns:
        MerkleProof that can verify the leaf against the tree root

    Raises:
        ValueError: If index is out of range or leaves is empty
    """
    if not leaves:
        raise ValueError("Cannot generate proof for empty tree")
    if index < 0 or index >= len(leaves):
        raise ValueError(f"Index {index} out of range for {len(leaves)} leaves")

    # Build tree levels
    levels: List[List[bytes]] = [list(leaves)]
    current = list(leaves)

    while len(current) > 1:
        next_level: List[bytes] = []
        i = 0
        while i < len(current):
            if i + 1 < len(current):
                next_level.append(hash_node(current[i], current[i + 1]))
            else:
                next_level.append(current[i])
            i += 2
        levels.append(next_level)
        current = next_level

    # Collect audit path
    audit_path: List[bytes] = []
    idx = index

    for level in levels[:-1]:  # Skip root level
        if len(level) <= 1:
            break

        if idx % 2 == 0:
            # Current is left, sibling is right
            sibling_idx = idx + 1
            if sibling_idx < len(level):
                audit_path.append(level[sibling_idx])
            # else: no sibling (odd node carried up)
        else:
            # Current is right, sibling is left
            audit_path.append(level[idx - 1])

        idx //= 2

    return MerkleProof(
        tree_size=len(leaves),
        leaf_index=index,
        audit_path=audit_path,
    )


__all__ = [
    "hash_leaf",
    "hash_node",
    "compute_root",
    "generate_proof",
    "MerkleTree",
    "MerkleProof",
]
