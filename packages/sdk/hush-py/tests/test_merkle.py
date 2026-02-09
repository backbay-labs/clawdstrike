"""Tests for RFC 6962-compatible Merkle tree implementation."""
import pytest


def test_hash_leaf_produces_32_bytes():
    """Leaf hash should be 32 bytes with 0x00 prefix."""
    from clawdstrike.merkle import hash_leaf

    result = hash_leaf(b"hello")
    assert isinstance(result, bytes)
    assert len(result) == 32


def test_hash_node_produces_32_bytes():
    """Node hash combines two 32-byte hashes with 0x01 prefix."""
    from clawdstrike.merkle import hash_leaf, hash_node

    left = hash_leaf(b"left")
    right = hash_leaf(b"right")
    result = hash_node(left, right)

    assert isinstance(result, bytes)
    assert len(result) == 32


def test_hash_node_order_matters():
    """hash_node(a, b) != hash_node(b, a)."""
    from clawdstrike.merkle import hash_leaf, hash_node

    a = hash_leaf(b"a")
    b = hash_leaf(b"b")

    assert hash_node(a, b) != hash_node(b, a)


def test_compute_root_single_leaf():
    """Single leaf tree: root equals the leaf hash."""
    from clawdstrike.merkle import hash_leaf, compute_root

    leaf = hash_leaf(b"single")
    leaves = [leaf]
    root = compute_root(leaves)

    assert root == leaf


def test_compute_root_two_leaves():
    """Two leaf tree: root is hash_node of both leaves."""
    from clawdstrike.merkle import hash_leaf, hash_node, compute_root

    left = hash_leaf(b"left")
    right = hash_leaf(b"right")

    root = compute_root([left, right])
    expected = hash_node(left, right)

    assert root == expected


def test_compute_root_empty_raises():
    """Empty tree should raise ValueError."""
    from clawdstrike.merkle import compute_root

    with pytest.raises(ValueError, match="empty"):
        compute_root([])


def test_compute_root_odd_count():
    """Odd leaf count: last leaf carried upward (not duplicated)."""
    from clawdstrike.merkle import hash_leaf, hash_node, compute_root

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


def test_merkle_proof_verify_valid():
    """Valid proof should verify against correct root."""
    from clawdstrike.merkle import hash_leaf, hash_node, MerkleProof

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
    from clawdstrike.merkle import hash_leaf, hash_node, MerkleProof

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
    from clawdstrike.merkle import hash_leaf, hash_node, MerkleProof

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


def test_generate_proof_two_leaves():
    """Generate and verify proof for 2-leaf tree."""
    from clawdstrike.merkle import hash_leaf, compute_root, generate_proof

    leaves = [hash_leaf(b"a"), hash_leaf(b"b")]
    root = compute_root(leaves)

    proof0 = generate_proof(leaves, 0)
    proof1 = generate_proof(leaves, 1)

    assert proof0.verify(leaves[0], root)
    assert proof1.verify(leaves[1], root)


def test_generate_proof_many_leaves():
    """Generate and verify proofs for 8-leaf tree."""
    from clawdstrike.merkle import hash_leaf, compute_root, generate_proof

    leaves = [hash_leaf(f"leaf{i}".encode()) for i in range(8)]
    root = compute_root(leaves)

    for i in range(8):
        proof = generate_proof(leaves, i)
        assert proof.verify(leaves[i], root), f"Proof failed for index {i}"


def test_generate_proof_odd_leaves():
    """Generate and verify proofs for odd-count tree (7 leaves)."""
    from clawdstrike.merkle import hash_leaf, compute_root, generate_proof

    leaves = [hash_leaf(f"leaf{i}".encode()) for i in range(7)]
    root = compute_root(leaves)

    for i in range(7):
        proof = generate_proof(leaves, i)
        assert proof.verify(leaves[i], root), f"Proof failed for index {i}"


def test_generate_proof_invalid_index():
    """generate_proof should raise for out-of-range index."""
    from clawdstrike.merkle import hash_leaf, generate_proof

    leaves = [hash_leaf(b"a"), hash_leaf(b"b")]

    with pytest.raises(ValueError, match="out of range"):
        generate_proof(leaves, 2)

    with pytest.raises(ValueError, match="out of range"):
        generate_proof(leaves, -1)


def test_merkle_tree_from_data():
    """MerkleTree.from_data should hash leaves automatically."""
    from clawdstrike.merkle import MerkleTree, hash_leaf

    tree = MerkleTree.from_data([b"a", b"b", b"c"])

    assert tree.leaf_count == 3
    assert len(tree.root) == 32


def test_merkle_tree_from_hashes():
    """MerkleTree.from_hashes should use pre-hashed leaves."""
    from clawdstrike.merkle import MerkleTree, hash_leaf, compute_root

    leaves = [hash_leaf(b"a"), hash_leaf(b"b")]
    tree = MerkleTree.from_hashes(leaves)

    assert tree.leaf_count == 2
    assert tree.root == compute_root(leaves)


def test_merkle_tree_inclusion_proof():
    """MerkleTree.inclusion_proof should generate valid proofs."""
    from clawdstrike.merkle import MerkleTree, hash_leaf

    leaves = [hash_leaf(f"leaf{i}".encode()) for i in range(10)]
    tree = MerkleTree.from_hashes(leaves)

    for i in range(10):
        proof = tree.inclusion_proof(i)
        assert proof.verify(leaves[i], tree.root)


def test_merkle_tree_single_leaf():
    """Single leaf tree should work correctly."""
    from clawdstrike.merkle import MerkleTree, hash_leaf

    leaf = hash_leaf(b"single")
    tree = MerkleTree.from_hashes([leaf])

    assert tree.leaf_count == 1
    assert tree.root == leaf

    proof = tree.inclusion_proof(0)
    assert proof.verify(leaf, tree.root)
    assert len(proof.audit_path) == 0


def test_merkle_exports_from_package():
    """Merkle functions should be importable from clawdstrike package."""
    from clawdstrike import (
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
