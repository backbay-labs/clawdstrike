//! Property-based tests for Merkle tree operations

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hush_core::merkle::{leaf_hash, MerkleTree};
use proptest::prelude::*;

proptest! {
    /// Merkle root is deterministic for the same leaves
    #[test]
    fn merkle_root_deterministic(
        leaves in prop::collection::vec(any::<Vec<u8>>(), 1..50)
    ) {
        let tree1 = MerkleTree::from_leaves(&leaves).expect("valid tree");
        let tree2 = MerkleTree::from_leaves(&leaves).expect("valid tree");
        prop_assert_eq!(tree1.root(), tree2.root());
    }

    /// Merkle proof is valid for any leaf
    #[test]
    fn merkle_proof_valid(
        leaves in prop::collection::vec(any::<Vec<u8>>(), 2..30),
        index_ratio in 0.0..1.0f64,
    ) {
        let tree = MerkleTree::from_leaves(&leaves).expect("valid tree");
        let index = ((leaves.len() as f64) * index_ratio) as usize;
        let index = index.min(leaves.len() - 1);

        let proof = tree.inclusion_proof(index).expect("valid proof");
        let root = tree.root();
        prop_assert!(proof.verify(&leaves[index], &root));
    }

    /// Single leaf tree has root equal to leaf hash
    #[test]
    fn merkle_single_leaf(leaf in any::<Vec<u8>>()) {
        let tree = MerkleTree::from_leaves(&[&leaf]).expect("valid tree");
        prop_assert_eq!(tree.root(), leaf_hash(&leaf));
    }

    /// Merkle proof for single leaf is empty
    #[test]
    fn merkle_single_leaf_proof_empty(leaf in any::<Vec<u8>>()) {
        let tree = MerkleTree::from_leaves(&[&leaf]).expect("valid tree");
        let proof = tree.inclusion_proof(0).expect("valid proof");
        prop_assert!(proof.audit_path.is_empty());
    }

    /// Proof fails for wrong leaf data
    #[test]
    fn merkle_proof_wrong_leaf(
        leaves in prop::collection::vec(any::<Vec<u8>>(), 2..20),
        wrong_leaf in any::<Vec<u8>>(),
    ) {
        let tree = MerkleTree::from_leaves(&leaves).expect("valid tree");
        let proof = tree.inclusion_proof(0).expect("valid proof");
        let root = tree.root();

        // Wrong leaf should not verify (unless it happens to match)
        if wrong_leaf != leaves[0] {
            prop_assert!(!proof.verify(&wrong_leaf, &root));
        }
    }

    /// Leaf count matches input
    #[test]
    fn merkle_leaf_count(
        leaves in prop::collection::vec(any::<Vec<u8>>(), 1..100)
    ) {
        let tree = MerkleTree::from_leaves(&leaves).expect("valid tree");
        prop_assert_eq!(tree.leaf_count(), leaves.len());
    }

    /// Different leaves produce different roots
    #[test]
    fn merkle_different_leaves_different_roots(
        leaves1 in prop::collection::vec(any::<Vec<u8>>(), 1..20),
        leaves2 in prop::collection::vec(any::<Vec<u8>>(), 1..20),
    ) {
        prop_assume!(leaves1 != leaves2);
        let tree1 = MerkleTree::from_leaves(&leaves1).expect("valid tree");
        let tree2 = MerkleTree::from_leaves(&leaves2).expect("valid tree");
        // Different leaves should produce different roots (collision unlikely)
        prop_assert_ne!(tree1.root(), tree2.root());
    }
}
