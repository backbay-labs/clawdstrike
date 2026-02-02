# Python Enhancements Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Merkle tree support, canonical JSON serialization, and complete PyO3 native bindings to hush-py for feature parity with hush-core Rust.

**Architecture:** Pure Python implementations for merkle.py and canonical.py that mirror the Rust hush-core behavior exactly. PyO3 native bindings wrap hush-core directly for performance-critical paths. Python falls back to pure implementations when native unavailable.

**Tech Stack:** Python 3.10+, PyNaCl, PyO3 0.20+, maturin, hush-core Rust crate

---

## Task 1: Create Merkle Tree Pure Python Implementation

**Files:**
- Create: `packages/hush-py/src/hush/merkle.py`
- Create: `packages/hush-py/tests/test_merkle.py`
- Modify: `packages/hush-py/src/hush/__init__.py`

### Step 1: Write the failing test for hash_leaf

Create the test file with the first test:

```python
# packages/hush-py/tests/test_merkle.py
"""Tests for RFC 6962-compatible Merkle tree implementation."""
import pytest


def test_hash_leaf_produces_32_bytes():
    """Leaf hash should be 32 bytes with 0x00 prefix."""
    from hush.merkle import hash_leaf

    result = hash_leaf(b"hello")
    assert isinstance(result, bytes)
    assert len(result) == 32
```

### Step 2: Run test to verify it fails

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py::test_hash_leaf_produces_32_bytes -v`
Expected: FAIL with "ModuleNotFoundError" or "ImportError"

### Step 3: Write minimal merkle.py with hash_leaf

```python
# packages/hush-py/src/hush/merkle.py
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
```

### Step 4: Run test to verify it passes

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py::test_hash_leaf_produces_32_bytes -v`
Expected: PASS

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add packages/hush-py/src/hush/merkle.py packages/hush-py/tests/test_merkle.py && git commit -m "feat(hush-py): add hash_leaf for RFC 6962 Merkle trees"
```

---

## Task 2: Add hash_node Function

**Files:**
- Modify: `packages/hush-py/src/hush/merkle.py`
- Modify: `packages/hush-py/tests/test_merkle.py`

### Step 1: Write the failing test for hash_node

Append to test file:

```python
def test_hash_node_produces_32_bytes():
    """Node hash combines two 32-byte hashes with 0x01 prefix."""
    from hush.merkle import hash_leaf, hash_node

    left = hash_leaf(b"left")
    right = hash_leaf(b"right")
    result = hash_node(left, right)

    assert isinstance(result, bytes)
    assert len(result) == 32


def test_hash_node_order_matters():
    """hash_node(a, b) != hash_node(b, a)."""
    from hush.merkle import hash_leaf, hash_node

    a = hash_leaf(b"a")
    b = hash_leaf(b"b")

    assert hash_node(a, b) != hash_node(b, a)
```

### Step 2: Run test to verify it fails

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py::test_hash_node_produces_32_bytes -v`
Expected: FAIL with "ImportError: cannot import name 'hash_node'"

### Step 3: Add hash_node to merkle.py

Add after hash_leaf:

```python
def hash_node(left: bytes, right: bytes) -> bytes:
    """Hash an internal node per RFC 6962: SHA256(0x01 || left || right).

    Args:
        left: 32-byte left child hash
        right: 32-byte right child hash

    Returns:
        32-byte node hash
    """
    return sha256(b'\x01' + left + right)
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py -v`
Expected: PASS (all 3 tests)

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-py): add hash_node for Merkle tree internal nodes"
```

---

## Task 3: Add compute_root Function

**Files:**
- Modify: `packages/hush-py/src/hush/merkle.py`
- Modify: `packages/hush-py/tests/test_merkle.py`

### Step 1: Write the failing tests for compute_root

Append to test file:

```python
def test_compute_root_single_leaf():
    """Single leaf tree: root equals the leaf hash."""
    from hush.merkle import hash_leaf, compute_root

    leaf = hash_leaf(b"single")
    leaves = [leaf]
    root = compute_root(leaves)

    assert root == leaf


def test_compute_root_two_leaves():
    """Two leaf tree: root is hash_node of both leaves."""
    from hush.merkle import hash_leaf, hash_node, compute_root

    left = hash_leaf(b"left")
    right = hash_leaf(b"right")

    root = compute_root([left, right])
    expected = hash_node(left, right)

    assert root == expected


def test_compute_root_empty_raises():
    """Empty tree should raise ValueError."""
    from hush.merkle import compute_root

    with pytest.raises(ValueError, match="empty"):
        compute_root([])


def test_compute_root_odd_count():
    """Odd leaf count: last leaf carried upward (not duplicated)."""
    from hush.merkle import hash_leaf, hash_node, compute_root

    # Three leaves: [a, b, c]
    # Level 0: [a, b, c]
    # Level 1: [hash_node(a, b), c]  <- c carried up
    # Level 2: [hash_node(hash_node(a, b), c)]
    a = hash_leaf(b"a")
    b = hash_leaf(b"b")
    c = hash_leaf(b"c")

    root = compute_root([a, b, c])
    expected = hash_node(hash_node(a, b), c)

    assert root == expected
```

### Step 2: Run test to verify it fails

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py::test_compute_root_single_leaf -v`
Expected: FAIL with "ImportError: cannot import name 'compute_root'"

### Step 3: Add compute_root to merkle.py

Add after hash_node:

```python
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
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py -v`
Expected: PASS (all 7 tests)

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-py): add compute_root for Merkle tree root calculation"
```

---

## Task 4: Add MerkleProof Dataclass and verify Method

**Files:**
- Modify: `packages/hush-py/src/hush/merkle.py`
- Modify: `packages/hush-py/tests/test_merkle.py`

### Step 1: Write the failing tests for MerkleProof

Append to test file:

```python
def test_merkle_proof_verify_valid():
    """Valid proof should verify against correct root."""
    from hush.merkle import hash_leaf, hash_node, MerkleProof

    # Manual two-leaf tree
    left = hash_leaf(b"left")
    right = hash_leaf(b"right")
    root = hash_node(left, right)

    # Proof for left leaf: sibling is right, on the right side
    proof = MerkleProof(
        tree_size=2,
        leaf_index=0,
        audit_path=[right],
    )

    assert proof.verify(left, root)


def test_merkle_proof_verify_invalid_root():
    """Proof should fail against wrong root."""
    from hush.merkle import hash_leaf, hash_node, MerkleProof

    left = hash_leaf(b"left")
    right = hash_leaf(b"right")
    root = hash_node(left, right)
    wrong_root = hash_leaf(b"wrong")

    proof = MerkleProof(
        tree_size=2,
        leaf_index=0,
        audit_path=[right],
    )

    assert not proof.verify(left, wrong_root)


def test_merkle_proof_verify_right_leaf():
    """Proof for right leaf (index 1) should also verify."""
    from hush.merkle import hash_leaf, hash_node, MerkleProof

    left = hash_leaf(b"left")
    right = hash_leaf(b"right")
    root = hash_node(left, right)

    # Proof for right leaf: sibling is left, on the left side
    proof = MerkleProof(
        tree_size=2,
        leaf_index=1,
        audit_path=[left],
    )

    assert proof.verify(right, root)
```

### Step 2: Run test to verify it fails

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py::test_merkle_proof_verify_valid -v`
Expected: FAIL with "ImportError: cannot import name 'MerkleProof'"

### Step 3: Add MerkleProof dataclass to merkle.py

Add after compute_root:

```python
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
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py -v`
Expected: PASS (all 10 tests)

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-py): add MerkleProof with verify and compute_root methods"
```

---

## Task 5: Add generate_proof Function

**Files:**
- Modify: `packages/hush-py/src/hush/merkle.py`
- Modify: `packages/hush-py/tests/test_merkle.py`

### Step 1: Write the failing tests for generate_proof

Append to test file:

```python
def test_generate_proof_two_leaves():
    """Generate and verify proof for 2-leaf tree."""
    from hush.merkle import hash_leaf, compute_root, generate_proof

    leaves = [hash_leaf(b"a"), hash_leaf(b"b")]
    root = compute_root(leaves)

    proof0 = generate_proof(leaves, 0)
    proof1 = generate_proof(leaves, 1)

    assert proof0.verify(leaves[0], root)
    assert proof1.verify(leaves[1], root)


def test_generate_proof_many_leaves():
    """Generate and verify proofs for 8-leaf tree."""
    from hush.merkle import hash_leaf, compute_root, generate_proof

    leaves = [hash_leaf(f"leaf{i}".encode()) for i in range(8)]
    root = compute_root(leaves)

    for i in range(8):
        proof = generate_proof(leaves, i)
        assert proof.verify(leaves[i], root), f"Proof failed for index {i}"


def test_generate_proof_odd_leaves():
    """Generate and verify proofs for odd-count tree (7 leaves)."""
    from hush.merkle import hash_leaf, compute_root, generate_proof

    leaves = [hash_leaf(f"leaf{i}".encode()) for i in range(7)]
    root = compute_root(leaves)

    for i in range(7):
        proof = generate_proof(leaves, i)
        assert proof.verify(leaves[i], root), f"Proof failed for index {i}"


def test_generate_proof_invalid_index():
    """generate_proof should raise for out-of-range index."""
    from hush.merkle import hash_leaf, generate_proof

    leaves = [hash_leaf(b"a"), hash_leaf(b"b")]

    with pytest.raises(ValueError, match="out of range"):
        generate_proof(leaves, 2)

    with pytest.raises(ValueError, match="out of range"):
        generate_proof(leaves, -1)
```

### Step 2: Run test to verify it fails

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py::test_generate_proof_two_leaves -v`
Expected: FAIL with "ImportError: cannot import name 'generate_proof'"

### Step 3: Add generate_proof to merkle.py

Add after MerkleProof class:

```python
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
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py -v`
Expected: PASS (all 14 tests)

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-py): add generate_proof for Merkle inclusion proofs"
```

---

## Task 6: Add MerkleTree Class

**Files:**
- Modify: `packages/hush-py/src/hush/merkle.py`
- Modify: `packages/hush-py/tests/test_merkle.py`

### Step 1: Write the failing tests for MerkleTree

Append to test file:

```python
def test_merkle_tree_from_data():
    """MerkleTree.from_data should hash leaves automatically."""
    from hush.merkle import MerkleTree, hash_leaf

    tree = MerkleTree.from_data([b"a", b"b", b"c"])

    assert tree.leaf_count == 3
    assert len(tree.root) == 32


def test_merkle_tree_from_hashes():
    """MerkleTree.from_hashes should use pre-hashed leaves."""
    from hush.merkle import MerkleTree, hash_leaf, compute_root

    leaves = [hash_leaf(b"a"), hash_leaf(b"b")]
    tree = MerkleTree.from_hashes(leaves)

    assert tree.leaf_count == 2
    assert tree.root == compute_root(leaves)


def test_merkle_tree_inclusion_proof():
    """MerkleTree.inclusion_proof should generate valid proofs."""
    from hush.merkle import MerkleTree, hash_leaf

    leaves = [hash_leaf(f"leaf{i}".encode()) for i in range(10)]
    tree = MerkleTree.from_hashes(leaves)

    for i in range(10):
        proof = tree.inclusion_proof(i)
        assert proof.verify(leaves[i], tree.root)


def test_merkle_tree_single_leaf():
    """Single leaf tree should work correctly."""
    from hush.merkle import MerkleTree, hash_leaf

    leaf = hash_leaf(b"single")
    tree = MerkleTree.from_hashes([leaf])

    assert tree.leaf_count == 1
    assert tree.root == leaf

    proof = tree.inclusion_proof(0)
    assert proof.verify(leaf, tree.root)
    assert len(proof.audit_path) == 0
```

### Step 2: Run test to verify it fails

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py::test_merkle_tree_from_data -v`
Expected: FAIL with "ImportError: cannot import name 'MerkleTree'"

### Step 3: Add MerkleTree class to merkle.py

Add before generate_proof:

```python
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
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py -v`
Expected: PASS (all 18 tests)

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-py): add MerkleTree class with from_data, from_hashes, and inclusion_proof"
```

---

## Task 7: Export Merkle API from __init__.py

**Files:**
- Modify: `packages/hush-py/src/hush/__init__.py`

### Step 1: Write the failing test for imports

Append to test file:

```python
def test_merkle_exports_from_package():
    """Merkle functions should be importable from hush package."""
    from hush import (
        hash_leaf,
        hash_node,
        compute_root,
        generate_proof,
        MerkleTree,
        MerkleProof,
    )

    # Just verify they're callable/classes
    assert callable(hash_leaf)
    assert callable(hash_node)
    assert callable(compute_root)
    assert callable(generate_proof)
    assert isinstance(MerkleTree, type)
    assert isinstance(MerkleProof, type)
```

### Step 2: Run test to verify it fails

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py::test_merkle_exports_from_package -v`
Expected: FAIL with "ImportError: cannot import name 'hash_leaf'"

### Step 3: Update __init__.py to export merkle API

Replace the content of `packages/hush-py/src/hush/__init__.py`:

```python
"""Hush - Python SDK for clawdstrike security verification."""

from hush.core import sha256, keccak256, verify_signature, sign_message, generate_keypair
from hush.receipt import Receipt, SignedReceipt
from hush.policy import Policy, PolicyEngine, PolicySettings, GuardConfigs
from hush.guards import (
    Severity,
    GuardResult,
    GuardContext,
    GuardAction,
    Guard,
    ForbiddenPathGuard,
    ForbiddenPathConfig,
    EgressAllowlistGuard,
    EgressAllowlistConfig,
    SecretLeakGuard,
    SecretLeakConfig,
    PatchIntegrityGuard,
    PatchIntegrityConfig,
    McpToolGuard,
    McpToolConfig,
)
from hush.merkle import (
    hash_leaf,
    hash_node,
    compute_root,
    generate_proof,
    MerkleTree,
    MerkleProof,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # Core crypto
    "sha256",
    "keccak256",
    "verify_signature",
    "sign_message",
    "generate_keypair",
    # Receipt
    "Receipt",
    "SignedReceipt",
    # Policy
    "Policy",
    "PolicyEngine",
    "PolicySettings",
    "GuardConfigs",
    # Guards base
    "Severity",
    "GuardResult",
    "GuardContext",
    "GuardAction",
    "Guard",
    # Guards
    "ForbiddenPathGuard",
    "ForbiddenPathConfig",
    "EgressAllowlistGuard",
    "EgressAllowlistConfig",
    "SecretLeakGuard",
    "SecretLeakConfig",
    "PatchIntegrityGuard",
    "PatchIntegrityConfig",
    "McpToolGuard",
    "McpToolConfig",
    # Merkle
    "hash_leaf",
    "hash_node",
    "compute_root",
    "generate_proof",
    "MerkleTree",
    "MerkleProof",
]
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_merkle.py -v`
Expected: PASS (all 19 tests)

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-py): export Merkle API from package __init__"
```

---

## Task 8: Create Canonical JSON Implementation

**Files:**
- Create: `packages/hush-py/src/hush/canonical.py`
- Create: `packages/hush-py/tests/test_canonical.py`

### Step 1: Write the failing tests for canonicalize

```python
# packages/hush-py/tests/test_canonical.py
"""Tests for RFC 8785 (JCS) canonical JSON implementation."""
import pytest


def test_canonicalize_sorted_keys():
    """Object keys should be sorted lexicographically."""
    from hush.canonical import canonicalize

    obj = {"z": 1, "a": 2, "m": 3}
    result = canonicalize(obj)

    assert result == '{"a":2,"m":3,"z":1}'


def test_canonicalize_no_whitespace():
    """Output should have no whitespace."""
    from hush.canonical import canonicalize

    obj = {"key": "value", "list": [1, 2, 3]}
    result = canonicalize(obj)

    assert " " not in result
    assert "\n" not in result
    assert "\t" not in result


def test_canonicalize_nested_objects():
    """Nested objects should have sorted keys at all levels."""
    from hush.canonical import canonicalize

    obj = {"outer": {"z": 1, "a": 2}, "inner": [3, 2, 1]}
    result = canonicalize(obj)

    assert result == '{"inner":[3,2,1],"outer":{"a":2,"z":1}}'


def test_canonicalize_numeric_string_keys():
    """String keys should be sorted lexicographically (not numerically)."""
    from hush.canonical import canonicalize

    obj = {"2": "b", "10": "a", "a": 0}
    result = canonicalize(obj)

    # "10" < "2" < "a" in lexicographic order
    assert result == '{"10":"a","2":"b","a":0}'
```

### Step 2: Run test to verify it fails

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_canonical.py::test_canonicalize_sorted_keys -v`
Expected: FAIL with "ModuleNotFoundError"

### Step 3: Create canonical.py with canonicalize

```python
# packages/hush-py/src/hush/canonical.py
"""RFC 8785 (JCS) canonical JSON implementation.

Provides deterministic JSON serialization for hashing and signing:
- No whitespace between elements
- Object keys sorted lexicographically (UTF-16 code units)
- Numbers in shortest form (no trailing zeros)
- Unicode preserved (except control characters escaped)
"""
from __future__ import annotations

import json
from typing import Any


def canonicalize(obj: Any) -> str:
    """Serialize object to canonical JSON per RFC 8785 (JCS).

    Args:
        obj: Python object to serialize (dict, list, str, int, float, bool, None)

    Returns:
        Canonical JSON string

    Raises:
        ValueError: If object contains non-finite floats (inf, nan)
    """
    return json.dumps(
        obj,
        separators=(',', ':'),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    )
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_canonical.py -v`
Expected: PASS (all 4 tests)

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add packages/hush-py/src/hush/canonical.py packages/hush-py/tests/test_canonical.py && git commit -m "feat(hush-py): add canonicalize for RFC 8785 canonical JSON"
```

---

## Task 9: Add canonical_hash Function

**Files:**
- Modify: `packages/hush-py/src/hush/canonical.py`
- Modify: `packages/hush-py/tests/test_canonical.py`

### Step 1: Write the failing tests for canonical_hash

Append to test file:

```python
def test_canonical_hash_sha256():
    """canonical_hash should hash canonicalized JSON with SHA-256."""
    from hush.canonical import canonicalize, canonical_hash
    from hush.core import sha256

    obj = {"message": "hello"}

    result = canonical_hash(obj, algorithm="sha256")
    expected = sha256(canonicalize(obj).encode("utf-8"))

    assert result == expected
    assert len(result) == 32


def test_canonical_hash_keccak256():
    """canonical_hash should support Keccak-256."""
    from hush.canonical import canonicalize, canonical_hash
    from hush.core import keccak256

    obj = {"message": "hello"}

    result = canonical_hash(obj, algorithm="keccak256")
    expected = keccak256(canonicalize(obj).encode("utf-8"))

    assert result == expected


def test_canonical_hash_default_sha256():
    """canonical_hash should default to SHA-256."""
    from hush.canonical import canonical_hash

    obj = {"test": True}

    result_default = canonical_hash(obj)
    result_explicit = canonical_hash(obj, algorithm="sha256")

    assert result_default == result_explicit


def test_canonical_hash_unknown_algorithm():
    """canonical_hash should raise for unknown algorithm."""
    from hush.canonical import canonical_hash

    with pytest.raises(ValueError, match="Unknown algorithm"):
        canonical_hash({"x": 1}, algorithm="md5")
```

### Step 2: Run test to verify it fails

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_canonical.py::test_canonical_hash_sha256 -v`
Expected: FAIL with "ImportError: cannot import name 'canonical_hash'"

### Step 3: Add canonical_hash to canonical.py

Add after canonicalize:

```python
def canonical_hash(obj: Any, algorithm: str = "sha256") -> bytes:
    """Hash object using canonical JSON serialization.

    Args:
        obj: Python object to serialize and hash
        algorithm: Hash algorithm ("sha256" or "keccak256")

    Returns:
        32-byte hash digest

    Raises:
        ValueError: If algorithm is not supported
    """
    from .core import sha256, keccak256

    canonical = canonicalize(obj).encode("utf-8")

    if algorithm == "sha256":
        return sha256(canonical)
    elif algorithm == "keccak256":
        return keccak256(canonical)
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}")
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_canonical.py -v`
Expected: PASS (all 8 tests)

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-py): add canonical_hash for hashing canonical JSON"
```

---

## Task 10: Export Canonical API from __init__.py

**Files:**
- Modify: `packages/hush-py/src/hush/__init__.py`
- Modify: `packages/hush-py/tests/test_canonical.py`

### Step 1: Write the failing test for imports

Append to test file:

```python
def test_canonical_exports_from_package():
    """Canonical functions should be importable from hush package."""
    from hush import canonicalize, canonical_hash

    assert callable(canonicalize)
    assert callable(canonical_hash)
```

### Step 2: Run test to verify it fails

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_canonical.py::test_canonical_exports_from_package -v`
Expected: FAIL with "ImportError: cannot import name 'canonicalize'"

### Step 3: Update __init__.py to export canonical API

Add imports after merkle imports:

```python
from hush.canonical import canonicalize, canonical_hash
```

Add to __all__ list:

```python
    # Canonical JSON
    "canonicalize",
    "canonical_hash",
```

### Step 4: Run tests to verify they pass

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_canonical.py -v`
Expected: PASS (all 9 tests)

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-py): export canonical JSON API from package __init__"
```

---

## Task 11: Add More Canonical JSON Edge Case Tests

**Files:**
- Modify: `packages/hush-py/tests/test_canonical.py`

### Step 1: Add edge case tests

Append to test file:

```python
def test_canonicalize_primitives():
    """Primitives should serialize correctly."""
    from hush.canonical import canonicalize

    assert canonicalize(True) == "true"
    assert canonicalize(False) == "false"
    assert canonicalize(None) == "null"
    assert canonicalize("hello") == '"hello"'
    assert canonicalize(42) == "42"


def test_canonicalize_empty_structures():
    """Empty dict and list should serialize correctly."""
    from hush.canonical import canonicalize

    assert canonicalize({}) == "{}"
    assert canonicalize([]) == "[]"


def test_canonicalize_unicode():
    """Unicode should be preserved (not escaped)."""
    from hush.canonical import canonicalize

    obj = {"emoji": "\U0001F680", "chinese": "\u4e2d\u6587"}
    result = canonicalize(obj)

    # Unicode should appear literally, not escaped
    assert "\U0001F680" in result or "\\u" not in result.replace("\\u4", "")


def test_canonicalize_escape_sequences():
    """Control characters should be escaped."""
    from hush.canonical import canonicalize

    obj = {"newline": "\n", "tab": "\t", "quote": '"'}
    result = canonicalize(obj)

    assert "\\n" in result
    assert "\\t" in result
    assert '\\"' in result


def test_canonicalize_nan_raises():
    """NaN should raise ValueError."""
    from hush.canonical import canonicalize
    import math

    with pytest.raises(ValueError):
        canonicalize({"bad": float("nan")})


def test_canonicalize_inf_raises():
    """Infinity should raise ValueError."""
    from hush.canonical import canonicalize

    with pytest.raises(ValueError):
        canonicalize({"bad": float("inf")})
```

### Step 2: Run tests to verify they pass

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_canonical.py -v`
Expected: PASS (all 15 tests)

### Step 3: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "test(hush-py): add edge case tests for canonical JSON"
```

---

## Task 12: Enhance PyO3 Native Bindings - Add keccak256_native

**Files:**
- Modify: `packages/hush-py/hush-native/src/lib.rs`

### Step 1: Add keccak256_native function

Add after sha256_native:

```rust
/// Compute Keccak-256 hash using native implementation.
#[pyfunction]
fn keccak256_native(data: &[u8]) -> PyResult<Vec<u8>> {
    use hush_core::hashing::keccak256;
    Ok(keccak256(data).as_bytes().to_vec())
}
```

### Step 2: Register in module

Update the pymodule function to add:

```rust
m.add_function(wrap_pyfunction!(keccak256_native, m)?)?;
```

### Step 3: Verify it compiles

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py/hush-native && cargo check`
Expected: Compiles without errors

### Step 4: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-native): add keccak256_native binding"
```

---

## Task 13: Add verify_ed25519_native to PyO3 Bindings

**Files:**
- Modify: `packages/hush-py/hush-native/src/lib.rs`
- Modify: `packages/hush-py/hush-native/Cargo.toml`

### Step 1: Update Cargo.toml dependencies

Ensure signing module is available (should already be via hush-core):

```toml
[dependencies]
pyo3 = { version = "0.20", features = ["extension-module"] }
hush-core = { path = "../../../crates/hush-core" }
hex = "0.4"
```

### Step 2: Add verify_ed25519_native function

Add to lib.rs:

```rust
/// Verify Ed25519 signature using native implementation.
#[pyfunction]
fn verify_ed25519_native(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> PyResult<bool> {
    use hush_core::signing::verify_ed25519;

    match verify_ed25519(message, signature, public_key) {
        Ok(valid) => Ok(valid),
        Err(_) => Ok(false),
    }
}
```

### Step 3: Register in module

Add to pymodule:

```rust
m.add_function(wrap_pyfunction!(verify_ed25519_native, m)?)?;
```

### Step 4: Verify it compiles

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py/hush-native && cargo check`
Expected: Compiles without errors

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-native): add verify_ed25519_native binding"
```

---

## Task 14: Add generate_merkle_proof_native to PyO3 Bindings

**Files:**
- Modify: `packages/hush-py/hush-native/src/lib.rs`

### Step 1: Add generate_merkle_proof_native function

Add to lib.rs:

```rust
/// Generate Merkle inclusion proof using native implementation.
/// Returns (tree_size, leaf_index, audit_path_hex_list).
#[pyfunction]
fn generate_merkle_proof_native(
    leaves: Vec<Vec<u8>>,
    index: usize,
) -> PyResult<(usize, usize, Vec<String>)> {
    use hush_core::merkle::MerkleTree;
    use hush_core::hashing::Hash;

    if leaves.is_empty() {
        return Err(PyValueError::new_err("Cannot generate proof for empty tree"));
    }
    if index >= leaves.len() {
        return Err(PyValueError::new_err(format!(
            "Index {} out of range for {} leaves",
            index, leaves.len()
        )));
    }

    // Convert to Hash type
    let leaf_hashes: Vec<Hash> = leaves
        .iter()
        .map(|l| {
            let arr: [u8; 32] = l.as_slice().try_into()
                .map_err(|_| PyValueError::new_err("Leaf must be 32 bytes"))?;
            Ok(Hash::from_bytes(arr))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let tree = MerkleTree::from_hashes(leaf_hashes)
        .map_err(|e| PyValueError::new_err(format!("Failed to build tree: {}", e)))?;

    let proof = tree.inclusion_proof(index)
        .map_err(|e| PyValueError::new_err(format!("Failed to generate proof: {}", e)))?;

    let audit_path_hex: Vec<String> = proof.audit_path
        .iter()
        .map(|h| format!("0x{}", h.to_hex()))
        .collect();

    Ok((proof.tree_size, proof.leaf_index, audit_path_hex))
}
```

### Step 2: Register in module

Add to pymodule:

```rust
m.add_function(wrap_pyfunction!(generate_merkle_proof_native, m)?)?;
```

### Step 3: Verify it compiles

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py/hush-native && cargo check`
Expected: Compiles without errors

### Step 4: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-native): add generate_merkle_proof_native binding"
```

---

## Task 15: Add canonicalize_native to PyO3 Bindings

**Files:**
- Modify: `packages/hush-py/hush-native/src/lib.rs`
- Modify: `packages/hush-py/hush-native/Cargo.toml`

### Step 1: Update Cargo.toml for serde_json

Add serde_json dependency:

```toml
[dependencies]
pyo3 = { version = "0.20", features = ["extension-module"] }
hush-core = { path = "../../../crates/hush-core" }
hex = "0.4"
serde_json = "1.0"
```

### Step 2: Add canonicalize_native function

Add to lib.rs:

```rust
/// Canonicalize JSON string using native RFC 8785 implementation.
#[pyfunction]
fn canonicalize_native(json_str: &str) -> PyResult<String> {
    use hush_core::canonicalize_json;

    let value: serde_json::Value = serde_json::from_str(json_str)
        .map_err(|e| PyValueError::new_err(format!("Invalid JSON: {}", e)))?;

    canonicalize_json(&value)
        .map_err(|e| PyValueError::new_err(format!("Canonicalization failed: {}", e)))
}
```

### Step 3: Register in module

Add to pymodule:

```rust
m.add_function(wrap_pyfunction!(canonicalize_native, m)?)?;
```

### Step 4: Verify it compiles

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py/hush-native && cargo check`
Expected: Compiles without errors

### Step 5: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-native): add canonicalize_native binding"
```

---

## Task 16: Add Native Backend Detection to Python

**Files:**
- Create: `packages/hush-py/src/hush/native.py`
- Modify: `packages/hush-py/src/hush/__init__.py`

### Step 1: Create native.py module

```python
# packages/hush-py/src/hush/native.py
"""Native Rust backend detection and imports.

This module attempts to load the native Rust bindings (hush_native).
If unavailable, NATIVE_AVAILABLE will be False and native_* functions
will be None.
"""
from __future__ import annotations

from typing import Callable, Optional

# Try to import native bindings
NATIVE_AVAILABLE: bool = False
is_native_available: Optional[Callable[[], bool]] = None
sha256_native: Optional[Callable[[bytes], bytes]] = None
keccak256_native: Optional[Callable[[bytes], bytes]] = None
merkle_root_native: Optional[Callable[[list], bytes]] = None
verify_receipt_native: Optional[Callable[[str, str, str], bool]] = None
verify_ed25519_native: Optional[Callable[[bytes, bytes, bytes], bool]] = None
generate_merkle_proof_native: Optional[Callable[[list, int], tuple]] = None
canonicalize_native: Optional[Callable[[str], str]] = None

try:
    from hush_native import (
        is_native_available as _is_native_available,
        sha256_native as _sha256_native,
        merkle_root_native as _merkle_root_native,
        verify_receipt_native as _verify_receipt_native,
    )

    NATIVE_AVAILABLE = True
    is_native_available = _is_native_available
    sha256_native = _sha256_native
    merkle_root_native = _merkle_root_native
    verify_receipt_native = _verify_receipt_native

    # Try to import optional functions that may not exist in older versions
    try:
        from hush_native import keccak256_native as _keccak256_native
        keccak256_native = _keccak256_native
    except ImportError:
        pass

    try:
        from hush_native import verify_ed25519_native as _verify_ed25519_native
        verify_ed25519_native = _verify_ed25519_native
    except ImportError:
        pass

    try:
        from hush_native import generate_merkle_proof_native as _generate_merkle_proof_native
        generate_merkle_proof_native = _generate_merkle_proof_native
    except ImportError:
        pass

    try:
        from hush_native import canonicalize_native as _canonicalize_native
        canonicalize_native = _canonicalize_native
    except ImportError:
        pass

except ImportError:
    pass


__all__ = [
    "NATIVE_AVAILABLE",
    "is_native_available",
    "sha256_native",
    "keccak256_native",
    "merkle_root_native",
    "verify_receipt_native",
    "verify_ed25519_native",
    "generate_merkle_proof_native",
    "canonicalize_native",
]
```

### Step 2: Update __init__.py to export NATIVE_AVAILABLE

Add import:

```python
from hush.native import NATIVE_AVAILABLE
```

Add to __all__:

```python
    # Native backend
    "NATIVE_AVAILABLE",
```

### Step 3: Run tests to verify no regressions

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest -v`
Expected: All tests pass

### Step 4: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-py): add native backend detection module"
```

---

## Task 17: Run Full Test Suite

**Files:**
- None (verification only)

### Step 1: Run all tests

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest -v --tb=short`
Expected: 100+ tests pass

### Step 2: Run mypy type checking

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m mypy src/hush --ignore-missing-imports`
Expected: No errors (or only minor warnings)

### Step 3: Run ruff linting

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m ruff check src/hush`
Expected: No errors

---

## Task 18: Build Native Bindings with Maturin

**Files:**
- Modify: `packages/hush-py/hush-native/pyproject.toml`

### Step 1: Update pyproject.toml for maturin

Replace content of `packages/hush-py/hush-native/pyproject.toml`:

```toml
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "hush-native"
version = "0.1.0"
description = "Native Rust bindings for hush Python SDK"
requires-python = ">=3.10"
license = { text = "MIT" }

[tool.maturin]
features = ["pyo3/extension-module"]
python-source = "python"
module-name = "hush_native"
```

### Step 2: Build with maturin

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py/hush-native && maturin develop`
Expected: Build succeeds and installs hush_native module

### Step 3: Verify native module works

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -c "from hush_native import is_native_available; print(is_native_available())"`
Expected: Prints "True"

### Step 4: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "build(hush-native): configure maturin build system"
```

---

## Task 19: Add Native Backend Tests

**Files:**
- Create: `packages/hush-py/tests/test_native.py`

### Step 1: Create native backend tests

```python
# packages/hush-py/tests/test_native.py
"""Tests for native Rust backend (when available)."""
import pytest

from hush.native import NATIVE_AVAILABLE


@pytest.mark.skipif(not NATIVE_AVAILABLE, reason="Native backend not available")
class TestNativeBackend:
    """Tests that only run when native backend is available."""

    def test_is_native_available(self):
        """is_native_available should return True."""
        from hush.native import is_native_available
        assert is_native_available is not None
        assert is_native_available() is True

    def test_sha256_native(self):
        """sha256_native should match pure Python."""
        from hush.native import sha256_native
        from hush.core import sha256

        assert sha256_native is not None

        data = b"hello world"
        native_result = sha256_native(data)
        python_result = sha256(data)

        assert native_result == python_result

    def test_merkle_root_native(self):
        """merkle_root_native should match pure Python."""
        from hush.native import merkle_root_native
        from hush.merkle import hash_leaf, compute_root

        assert merkle_root_native is not None

        leaves = [hash_leaf(f"leaf{i}".encode()) for i in range(4)]

        native_result = merkle_root_native(leaves)
        python_result = compute_root(leaves)

        assert native_result == python_result


class TestNativeAvailabilityFlag:
    """Tests for NATIVE_AVAILABLE flag."""

    def test_native_available_is_bool(self):
        """NATIVE_AVAILABLE should be a boolean."""
        assert isinstance(NATIVE_AVAILABLE, bool)

    def test_package_works_without_native(self):
        """Package should work even without native backend."""
        from hush import sha256, compute_root, canonicalize

        # These should work regardless of native availability
        assert len(sha256(b"test")) == 32
        assert canonicalize({"a": 1}) == '{"a":1}'
```

### Step 2: Run native tests

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest tests/test_native.py -v`
Expected: Tests pass (skipped if native not built)

### Step 3: Commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "test(hush-py): add native backend tests"
```

---

## Task 20: Final Verification and Summary

**Files:**
- None (verification only)

### Step 1: Run complete test suite

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -m pytest -v --tb=short 2>&1 | tail -20`
Expected: 100+ tests pass

### Step 2: Verify all imports work

Run: `cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements/packages/hush-py && python -c "from hush import hash_leaf, hash_node, compute_root, generate_proof, MerkleTree, MerkleProof, canonicalize, canonical_hash, NATIVE_AVAILABLE; print('All imports successful'); print(f'Native available: {NATIVE_AVAILABLE}')"`
Expected: "All imports successful" and native availability status

### Step 3: Create summary commit

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git log --oneline -15
```

### Step 4: Final commit for branch

```bash
cd /Users/connor/Medica/clawdstrike-ws13-python-enhancements && git add -A && git commit -m "feat(hush-py): complete Python enhancements - Merkle trees, canonical JSON, PyO3 bindings

- Add RFC 6962 Merkle tree (hash_leaf, hash_node, compute_root, MerkleTree, MerkleProof)
- Add RFC 8785 canonical JSON (canonicalize, canonical_hash)
- Enhance PyO3 bindings (keccak256, verify_ed25519, generate_proof, canonicalize)
- Add native backend detection module
- Add 25+ new tests for Merkle and canonical JSON
- All 115+ tests passing"
```

---

## Acceptance Criteria Checklist

After completing all tasks, verify:

- [ ] `merkle.py` implements: `hash_leaf`, `hash_node`, `compute_root`, `generate_proof`, `MerkleTree`, `MerkleProof`
- [ ] `canonical.py` implements: `canonicalize`, `canonical_hash`
- [ ] `hush-native` builds with maturin
- [ ] Native bindings provide 7+ functions: `is_native_available`, `sha256_native`, `keccak256_native`, `merkle_root_native`, `verify_receipt_native`, `verify_ed25519_native`, `generate_merkle_proof_native`, `canonicalize_native`
- [ ] Tests for Merkle: 15+ tests
- [ ] Tests for canonical: 10+ tests
- [ ] All 100+ tests pass
- [ ] `from hush import compute_root, canonicalize` works
- [ ] `from hush import NATIVE_AVAILABLE` works
