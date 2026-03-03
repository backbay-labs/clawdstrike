//! Merkle transparency log for the package registry.
//!
//! Implements an RFC 6962-style append-only Merkle tree with:
//! - Domain-separated hashing (leaf = `SHA-256(0x00 || data)`, interior = `SHA-256(0x01 || left || right)`)
//! - Inclusion proofs (RFC 6962 §2.1.1)
//! - Consistency proofs (RFC 6962 §2.1.2)
//! - `LeafData` for package metadata with canonical JSON serialization

use hush_core::canonical::canonicalize;
use hush_core::merkle::{leaf_hash, node_hash};
use hush_core::Hash;
use serde::{Deserialize, Serialize};

/// Errors specific to the Merkle transparency log.
#[derive(Debug, thiserror::Error)]
pub enum MerkleError {
    #[error("leaf index {index} out of range for tree of size {tree_size}")]
    LeafIndexOutOfRange { index: u64, tree_size: u64 },

    #[error("old size {old_size} exceeds current tree size {tree_size}")]
    OldSizeExceedsTree { old_size: u64, tree_size: u64 },

    #[error("old size must be greater than zero")]
    OldSizeZero,

    #[error("empty tree has no root")]
    EmptyTree,

    #[error("canonical JSON error: {0}")]
    Canonical(String),

    #[error("inclusion proof verification failed")]
    InclusionProofFailed,

    #[error("consistency proof verification failed")]
    ConsistencyProofFailed,
}

/// Package metadata stored as a leaf in the transparency log.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeafData {
    pub package_name: String,
    pub version: String,
    pub content_hash: String,
    pub publisher_key: String,
    pub timestamp: String,
}

impl LeafData {
    /// Compute the domain-separated leaf hash: `SHA-256(0x00 || canonical_json(self))`.
    pub fn leaf_hash(&self) -> Result<Hash, MerkleError> {
        let value =
            serde_json::to_value(self).map_err(|e| MerkleError::Canonical(e.to_string()))?;
        let canonical = canonicalize(&value).map_err(|e| MerkleError::Canonical(e.to_string()))?;
        Ok(leaf_hash(canonical.as_bytes()))
    }
}

/// Inclusion proof for a leaf in the transparency log (RFC 6962 §2.1.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub proof_path: Vec<String>,
}

/// Consistency proof between two tree sizes (RFC 6962 §2.1.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsistencyProof {
    pub old_size: u64,
    pub new_size: u64,
    pub proof_path: Vec<String>,
}

/// An append-only Merkle tree for the package transparency log.
///
/// This tree stores leaf hashes and recomputes the root on demand using
/// the RFC 6962 recursive algorithm (left-balanced binary tree).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    leaf_hashes: Vec<Hash>,
}

impl MerkleTree {
    /// Create an empty Merkle tree.
    pub fn new() -> Self {
        Self {
            leaf_hashes: Vec::new(),
        }
    }

    /// Append raw leaf data and return the leaf index.
    pub fn append(&mut self, leaf_data: &[u8]) -> u64 {
        let hash = leaf_hash(leaf_data);
        self.leaf_hashes.push(hash);
        (self.leaf_hashes.len() - 1) as u64
    }

    /// Append a pre-hashed leaf and return the leaf index.
    pub fn append_hash(&mut self, hash: Hash) -> u64 {
        self.leaf_hashes.push(hash);
        (self.leaf_hashes.len() - 1) as u64
    }

    /// Return the number of leaves in the tree.
    pub fn tree_size(&self) -> u64 {
        self.leaf_hashes.len() as u64
    }

    /// Compute and return the root hash.
    ///
    /// Returns an error if the tree is empty.
    pub fn root(&self) -> Result<String, MerkleError> {
        if self.leaf_hashes.is_empty() {
            return Err(MerkleError::EmptyTree);
        }
        Ok(merkle_tree_hash(&self.leaf_hashes).to_hex())
    }

    /// Generate an inclusion proof for the leaf at `leaf_index` (RFC 6962 §2.1.1).
    pub fn generate_inclusion_proof(&self, leaf_index: u64) -> Result<InclusionProof, MerkleError> {
        let n = self.tree_size();
        if n == 0 {
            return Err(MerkleError::EmptyTree);
        }
        if leaf_index >= n {
            return Err(MerkleError::LeafIndexOutOfRange {
                index: leaf_index,
                tree_size: n,
            });
        }
        let mut path = Vec::new();
        subproof(
            leaf_index as usize,
            0,
            self.leaf_hashes.len(),
            &self.leaf_hashes,
            &mut path,
        );
        Ok(InclusionProof {
            leaf_index,
            tree_size: n,
            proof_path: path.iter().map(|h| h.to_hex()).collect(),
        })
    }

    /// Generate a consistency proof from `old_size` to the current tree size (RFC 6962 §2.1.2).
    pub fn generate_consistency_proof(
        &self,
        old_size: u64,
    ) -> Result<ConsistencyProof, MerkleError> {
        let new_size = self.tree_size();
        if old_size == 0 {
            return Err(MerkleError::OldSizeZero);
        }
        if old_size > new_size {
            return Err(MerkleError::OldSizeExceedsTree {
                old_size,
                tree_size: new_size,
            });
        }
        let path = consistency_proof_path(old_size as usize, new_size as usize, &self.leaf_hashes);
        Ok(ConsistencyProof {
            old_size,
            new_size,
            proof_path: path.iter().map(|h| h.to_hex()).collect(),
        })
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RFC 6962 §2.1 recursive tree hash
// ---------------------------------------------------------------------------

/// Compute the Merkle tree hash for a slice of leaf hashes using the
/// RFC 6962 left-balanced recursive algorithm.
fn merkle_tree_hash(hashes: &[Hash]) -> Hash {
    match hashes.len() {
        0 => Hash::zero(),
        1 => hashes[0],
        n => {
            let k = largest_power_of_two_less_than(n);
            let left = merkle_tree_hash(&hashes[..k]);
            let right = merkle_tree_hash(&hashes[k..]);
            node_hash(&left, &right)
        }
    }
}

/// Return the largest power of 2 that is strictly less than `n`.
fn largest_power_of_two_less_than(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut p = 1usize;
    while (p << 1) < n {
        p <<= 1;
    }
    p
}

// ---------------------------------------------------------------------------
// RFC 6962 §2.1.1 — inclusion proof (PATH)
// ---------------------------------------------------------------------------

/// Recursive helper that computes the inclusion proof path.
///
/// `m` is the target leaf index relative to `leaves[start..]`, and `leaves[start..end]`
/// is the subtree being decomposed.
fn subproof(m: usize, start: usize, end: usize, leaves: &[Hash], path: &mut Vec<Hash>) {
    let n = end - start;
    if n <= 1 {
        return;
    }
    let k = largest_power_of_two_less_than(n);
    if m < k {
        // Target is in the left subtree — emit the right subtree hash.
        subproof(m, start, start + k, leaves, path);
        path.push(merkle_tree_hash(&leaves[start + k..end]));
    } else {
        // Target is in the right subtree — emit the left subtree hash.
        subproof(m - k, start + k, end, leaves, path);
        path.push(merkle_tree_hash(&leaves[start..start + k]));
    }
}

// ---------------------------------------------------------------------------
// RFC 6962 §2.1.2 — consistency proof
// ---------------------------------------------------------------------------

/// Compute the consistency proof path between `old_size` and `new_size`.
fn consistency_proof_path(old_size: usize, new_size: usize, leaves: &[Hash]) -> Vec<Hash> {
    let mut path = Vec::new();
    if old_size == new_size {
        return path;
    }
    // Find the largest subtree of old_size that is a complete subtree of new_size.
    consistency_subproof(old_size, 0, new_size, leaves, &mut path, true);
    path
}

/// Recursive helper for the consistency proof.
///
/// This walks down the tree from `[start..end)` looking for the boundary at
/// `old_size` (relative to `start`).  `start_from_old_root` is true only on
/// the initial call and suppresses emitting the hash of the old tree itself
/// (the verifier already knows it).
fn consistency_subproof(
    old_size: usize,
    start: usize,
    end: usize,
    leaves: &[Hash],
    path: &mut Vec<Hash>,
    start_from_old_root: bool,
) {
    let n = end - start;
    if old_size == n {
        // The old tree exactly covers this subtree.
        if !start_from_old_root {
            path.push(merkle_tree_hash(&leaves[start..end]));
        }
        return;
    }
    if n <= 1 {
        return;
    }
    let k = largest_power_of_two_less_than(n);
    if old_size <= k {
        // old boundary is inside the left subtree
        consistency_subproof(
            old_size,
            start,
            start + k,
            leaves,
            path,
            start_from_old_root,
        );
        path.push(merkle_tree_hash(&leaves[start + k..end]));
    } else {
        // old boundary is inside the right subtree
        consistency_subproof(old_size - k, start + k, end, leaves, path, false);
        path.push(merkle_tree_hash(&leaves[start..start + k]));
    }
}

// ---------------------------------------------------------------------------
// Verification helpers (standalone, no tree required)
// ---------------------------------------------------------------------------

/// Direction at each decomposition level.
#[derive(Debug, Clone, Copy)]
enum Side {
    /// The proof element is a RIGHT sibling (we are in the LEFT subtree).
    Right,
    /// The proof element is a LEFT sibling (we are in the RIGHT subtree).
    Left,
}

/// Decompose the inclusion proof path by tracing the tree decomposition.
///
/// Returns the list of directions from deepest level to root, matching the
/// order in which `subproof` appends hashes to the path.
fn inclusion_decomposition(mut leaf_index: usize, mut tree_size: usize) -> Vec<Side> {
    let mut levels = Vec::new();
    while tree_size > 1 {
        let k = largest_power_of_two_less_than(tree_size);
        if leaf_index < k {
            levels.push(Side::Right);
            tree_size = k;
        } else {
            levels.push(Side::Left);
            leaf_index -= k;
            tree_size -= k;
        }
    }
    // Reverse because subproof recurses first then pushes, so the path is
    // ordered from deepest recursion (bottom) to top.
    levels.reverse();
    levels
}

/// Verify an inclusion proof against a known leaf hash and root.
pub fn verify_inclusion_proof(proof: &InclusionProof, leaf_hash_hex: &str, root: &str) -> bool {
    let Ok(lh) = Hash::from_hex(leaf_hash_hex) else {
        return false;
    };
    let path: Result<Vec<Hash>, _> = proof.proof_path.iter().map(|h| Hash::from_hex(h)).collect();
    let Ok(path) = path else {
        return false;
    };

    let tree_size = proof.tree_size as usize;
    let leaf_index = proof.leaf_index as usize;

    if tree_size == 0 || leaf_index >= tree_size {
        return false;
    }
    if tree_size == 1 {
        return path.is_empty() && lh.to_hex() == root;
    }

    let levels = inclusion_decomposition(leaf_index, tree_size);
    if levels.len() != path.len() {
        return false;
    }

    let mut hash = lh;
    for (side, sibling) in levels.iter().zip(path.iter()) {
        match side {
            Side::Right => hash = node_hash(&hash, sibling),
            Side::Left => hash = node_hash(sibling, &hash),
        }
    }

    hash.to_hex() == root
}

/// Decompose the consistency proof path.
///
/// Returns a list of `(Side, affects_old_root)` from deepest to root,
/// matching the order in which `consistency_subproof` appends hashes.
///
/// `affects_old_root` is true when the sibling should be combined into
/// the old root accumulator (i.e., we went right at that level, meaning
/// the sibling is the left subtree hash which is part of the old tree).
///
/// The returned boolean indicates whether proof generation emits an explicit
/// seed hash in `proof_path[0]` (the `old_size == n` base hash when the
/// recursion has already moved off the old root).
fn consistency_decomposition(old_size: usize, new_size: usize) -> (Vec<(Side, bool)>, bool) {
    let mut levels = Vec::new();
    let path_includes_seed = consistency_decomposition_inner(old_size, new_size, true, &mut levels);

    // Note: NOT reversed. consistency_decomposition_inner recurses first then
    // pushes, producing levels in the same bottom-up order as the proof path.
    (levels, path_includes_seed)
}

fn consistency_decomposition_inner(
    old_size: usize,
    n: usize,
    start_from_old_root: bool,
    levels: &mut Vec<(Side, bool)>,
) -> bool {
    if old_size == n {
        return !start_from_old_root;
    }
    if n <= 1 {
        return false;
    }
    let k = largest_power_of_two_less_than(n);
    if old_size <= k {
        // old boundary is in the left subtree, sibling is RIGHT
        let path_includes_seed =
            consistency_decomposition_inner(old_size, k, start_from_old_root, levels);
        // The right subtree hash only affects new_root (not old_root).
        levels.push((Side::Right, false));
        path_includes_seed
    } else {
        // old boundary is in the right subtree, sibling is LEFT
        let path_includes_seed =
            consistency_decomposition_inner(old_size - k, n - k, false, levels);
        // The left subtree hash affects BOTH old and new root.
        levels.push((Side::Left, true));
        path_includes_seed
    }
}

/// Verify a consistency proof (public API).
pub fn verify_consistency_proof_full(
    proof: &ConsistencyProof,
    old_root: &str,
    new_root: &str,
) -> bool {
    let path: Result<Vec<Hash>, _> = proof.proof_path.iter().map(|h| Hash::from_hex(h)).collect();
    let Ok(path) = path else {
        return false;
    };
    let Ok(old_root_hash) = Hash::from_hex(old_root) else {
        return false;
    };
    let Ok(new_root_hash) = Hash::from_hex(new_root) else {
        return false;
    };

    let old_size = proof.old_size as usize;
    let new_size = proof.new_size as usize;

    if old_size == 0 || old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return path.is_empty() && old_root_hash == new_root_hash;
    }

    let (levels, path_includes_seed) = consistency_decomposition(old_size, new_size);

    // The proof path may have one extra element at the front (the seed node)
    // when proof generation emitted the base subtree hash.
    let (seed, proof_hashes) = if path_includes_seed {
        // First element is the seed (the old tree boundary node hash).
        if path.is_empty() {
            return false;
        }
        (path[0], &path[1..])
    } else {
        // old_root is not in the proof; use the caller-provided old_root as seed.
        (old_root_hash, path.as_slice())
    };

    if levels.len() != proof_hashes.len() {
        return false;
    }

    let mut old_hash = seed;
    let mut new_hash = seed;

    for ((side, affects_old), sibling) in levels.iter().zip(proof_hashes.iter()) {
        match side {
            Side::Right => {
                new_hash = node_hash(&new_hash, sibling);
                if *affects_old {
                    old_hash = node_hash(&old_hash, sibling);
                }
            }
            Side::Left => {
                new_hash = node_hash(sibling, &new_hash);
                if *affects_old {
                    old_hash = node_hash(sibling, &old_hash);
                }
            }
        }
    }

    old_hash == old_root_hash && new_hash == new_root_hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_leaf_data(name: &str, version: &str) -> LeafData {
        LeafData {
            package_name: name.to_string(),
            version: version.to_string(),
            content_hash: format!("sha256:{name}-{version}"),
            publisher_key: "ed25519:testkey".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    // -----------------------------------------------------------------------
    // Empty tree
    // -----------------------------------------------------------------------
    #[test]
    fn empty_tree_has_no_root() {
        let tree = MerkleTree::new();
        assert!(tree.root().is_err());
        assert_eq!(tree.tree_size(), 0);
    }

    // -----------------------------------------------------------------------
    // Single leaf
    // -----------------------------------------------------------------------
    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let mut tree = MerkleTree::new();
        tree.append(b"leaf-0");
        assert_eq!(tree.tree_size(), 1);

        let expected = leaf_hash(b"leaf-0").to_hex();
        assert_eq!(tree.root().unwrap(), expected);
    }

    // -----------------------------------------------------------------------
    // Power-of-2 trees
    // -----------------------------------------------------------------------
    #[test]
    fn power_of_2_trees() {
        for size in [2, 4, 8, 16] {
            let mut tree = MerkleTree::new();
            for i in 0..size {
                tree.append(format!("leaf-{i}").as_bytes());
            }
            // Verify root is computable and deterministic.
            let root1 = tree.root().unwrap();
            let root2 = tree.root().unwrap();
            assert_eq!(root1, root2, "root should be deterministic for size {size}");
        }
    }

    // -----------------------------------------------------------------------
    // Non-power-of-2 trees
    // -----------------------------------------------------------------------
    #[test]
    fn non_power_of_2_trees() {
        for size in [3, 5, 7, 9, 15, 17] {
            let mut tree = MerkleTree::new();
            for i in 0..size {
                tree.append(format!("leaf-{i}").as_bytes());
            }
            let root = tree.root().unwrap();
            assert!(!root.is_empty(), "root should not be empty for size {size}");
        }
    }

    // -----------------------------------------------------------------------
    // Inclusion proof roundtrips
    // -----------------------------------------------------------------------
    #[test]
    fn inclusion_proof_roundtrip_various_sizes() {
        for size in [1, 2, 3, 4, 7, 16, 100] {
            let mut tree = MerkleTree::new();
            let mut leaves = Vec::new();
            for i in 0u64..size {
                let data = format!("leaf-{i}");
                tree.append(data.as_bytes());
                leaves.push(data);
            }
            let root = tree.root().unwrap();

            for idx in 0..size {
                let proof = tree.generate_inclusion_proof(idx).unwrap();
                let lh = leaf_hash(leaves[idx as usize].as_bytes()).to_hex();
                assert!(
                    verify_inclusion_proof(&proof, &lh, &root),
                    "inclusion proof failed for size={size}, idx={idx}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Inclusion proof rejects tampered hash
    // -----------------------------------------------------------------------
    #[test]
    fn inclusion_proof_rejects_tampered_path() {
        let mut tree = MerkleTree::new();
        for i in 0..8u64 {
            tree.append(format!("leaf-{i}").as_bytes());
        }
        let root = tree.root().unwrap();
        let mut proof = tree.generate_inclusion_proof(3).unwrap();

        // Tamper with one hash in the path.
        if let Some(h) = proof.proof_path.first_mut() {
            *h = "ff".repeat(32);
        }
        let lh = leaf_hash(b"leaf-3").to_hex();
        assert!(!verify_inclusion_proof(&proof, &lh, &root));
    }

    // -----------------------------------------------------------------------
    // Inclusion proof rejects wrong leaf index
    // -----------------------------------------------------------------------
    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let mut tree = MerkleTree::new();
        for i in 0..8u64 {
            tree.append(format!("leaf-{i}").as_bytes());
        }
        let root = tree.root().unwrap();
        let proof = tree.generate_inclusion_proof(3).unwrap();

        // Try to verify with the wrong leaf.
        let wrong_lh = leaf_hash(b"leaf-5").to_hex();
        assert!(!verify_inclusion_proof(&proof, &wrong_lh, &root));
    }

    // -----------------------------------------------------------------------
    // Inclusion proof out-of-range
    // -----------------------------------------------------------------------
    #[test]
    fn inclusion_proof_out_of_range() {
        let mut tree = MerkleTree::new();
        tree.append(b"leaf-0");
        assert!(tree.generate_inclusion_proof(1).is_err());
        assert!(tree.generate_inclusion_proof(100).is_err());
    }

    // -----------------------------------------------------------------------
    // Consistency proof roundtrip
    // -----------------------------------------------------------------------
    #[test]
    fn consistency_proof_roundtrip() {
        let mut tree = MerkleTree::new();
        let mut snapshots = Vec::new();

        for i in 0..20u64 {
            tree.append(format!("leaf-{i}").as_bytes());
            snapshots.push((tree.tree_size(), tree.root().unwrap()));
        }

        // Test specific (old_size -> full tree) pairs.
        for old_idx in [0, 1, 3, 7, 14, 19] {
            let (old_size, ref old_root) = snapshots[old_idx];
            let new_root = tree.root().unwrap();

            let proof = tree.generate_consistency_proof(old_size).unwrap();
            assert!(
                verify_consistency_proof_full(&proof, old_root, &new_root),
                "consistency failed for old_size={old_size}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Consistency proof between every adjacent pair
    // -----------------------------------------------------------------------
    #[test]
    fn consistency_proof_adjacent_sizes() {
        let max = 32;
        let mut tree = MerkleTree::new();
        let mut roots = Vec::new();

        for i in 0..max {
            tree.append(format!("leaf-{i}").as_bytes());
            roots.push(tree.root().unwrap());
        }

        // Test consistency from each size to the final tree.
        for old_size in 1..=max as u64 {
            let old_root = &roots[old_size as usize - 1];
            let new_root = &roots[roots.len() - 1];
            let proof = tree.generate_consistency_proof(old_size).unwrap();
            assert!(
                verify_consistency_proof_full(&proof, old_root, new_root),
                "consistency failed for old_size={old_size} -> {max}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Consistency decomposition stays in sync with proof generation shape
    // -----------------------------------------------------------------------
    #[test]
    fn consistency_decomposition_matches_generated_path_shape() {
        let mut tree = MerkleTree::new();
        for i in 0..64u64 {
            tree.append(format!("leaf-{i}").as_bytes());
        }

        for new_size in 2usize..=64 {
            let leaves = &tree.leaf_hashes[..new_size];
            for old_size in 1usize..new_size {
                let path = consistency_proof_path(old_size, new_size, leaves);
                let (levels, path_includes_seed) = consistency_decomposition(old_size, new_size);
                let expected_len = levels.len() + usize::from(path_includes_seed);
                assert_eq!(
                    path.len(),
                    expected_len,
                    "shape mismatch old_size={old_size} new_size={new_size}"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Consistency proof rejects tampered old root
    // -----------------------------------------------------------------------
    #[test]
    fn consistency_proof_rejects_tampered_old_root() {
        let mut tree = MerkleTree::new();
        for i in 0..8u64 {
            tree.append(format!("leaf-{i}").as_bytes());
        }
        let root_at_4 = {
            let mut t = MerkleTree::new();
            for i in 0..4u64 {
                t.append(format!("leaf-{i}").as_bytes());
            }
            t.root().unwrap()
        };

        let proof = tree.generate_consistency_proof(4).unwrap();
        let new_root = tree.root().unwrap();

        // Correct verification should pass.
        assert!(verify_consistency_proof_full(&proof, &root_at_4, &new_root));

        // Tampered old root should fail.
        let fake_root = "ff".repeat(32);
        assert!(!verify_consistency_proof_full(
            &proof, &fake_root, &new_root
        ));
    }

    // -----------------------------------------------------------------------
    // Consistency proof edge case: old_size == 0
    // -----------------------------------------------------------------------
    #[test]
    fn consistency_proof_old_size_zero() {
        let mut tree = MerkleTree::new();
        tree.append(b"leaf-0");
        assert!(tree.generate_consistency_proof(0).is_err());
    }

    // -----------------------------------------------------------------------
    // Consistency proof edge case: old_size > tree_size
    // -----------------------------------------------------------------------
    #[test]
    fn consistency_proof_old_size_exceeds_tree() {
        let mut tree = MerkleTree::new();
        tree.append(b"leaf-0");
        assert!(tree.generate_consistency_proof(5).is_err());
    }

    // -----------------------------------------------------------------------
    // Append-only: root changes correctly
    // -----------------------------------------------------------------------
    #[test]
    fn append_only_root_changes() {
        let mut tree = MerkleTree::new();
        tree.append(b"leaf-0");
        let root1 = tree.root().unwrap();

        tree.append(b"leaf-1");
        let root2 = tree.root().unwrap();

        assert_ne!(root1, root2, "root should change after append");

        // Root should be deterministic.
        assert_eq!(tree.root().unwrap(), root2);
    }

    // -----------------------------------------------------------------------
    // Domain separation: leaf hash != interior node hash for same data
    // -----------------------------------------------------------------------
    #[test]
    fn domain_separation_leaf_vs_interior() {
        let data = b"test-data";
        let lh = leaf_hash(data);
        // Interior node hash with the same data as both children.
        let ih = node_hash(&lh, &lh);
        assert_ne!(lh, ih, "leaf hash and interior hash must differ");
    }

    #[test]
    fn domain_separation_prefix_byte_differs() {
        let data = b"hello";
        // Leaf: SHA256(0x00 || data)
        let lh = leaf_hash(data);
        // Compute SHA256(0x01 || data) using hush_core::sha256 on the prefixed data.
        let mut prefixed = vec![0x01u8];
        prefixed.extend_from_slice(data);
        let manual = hush_core::sha256(&prefixed);

        assert_ne!(
            lh, manual,
            "0x00 prefix and 0x01 prefix must produce different hashes"
        );
    }

    // -----------------------------------------------------------------------
    // LeafData hashing
    // -----------------------------------------------------------------------
    #[test]
    fn leaf_data_hash_is_deterministic() {
        let data = make_leaf_data("my-pkg", "1.0.0");
        let h1 = data.leaf_hash().unwrap();
        let h2 = data.leaf_hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn leaf_data_different_inputs_different_hashes() {
        let d1 = make_leaf_data("pkg-a", "1.0.0");
        let d2 = make_leaf_data("pkg-b", "1.0.0");
        assert_ne!(d1.leaf_hash().unwrap(), d2.leaf_hash().unwrap());
    }

    #[test]
    fn leaf_data_serialization_roundtrip() {
        let data = make_leaf_data("my-pkg", "2.0.0");
        let json = serde_json::to_string(&data).unwrap();
        let restored: LeafData = serde_json::from_str(&json).unwrap();
        assert_eq!(data, restored);
    }

    // -----------------------------------------------------------------------
    // LeafData integrated into MerkleTree
    // -----------------------------------------------------------------------
    #[test]
    fn leaf_data_in_tree() {
        let mut tree = MerkleTree::new();
        let data = make_leaf_data("my-pkg", "1.0.0");
        let hash = data.leaf_hash().unwrap();
        let idx = tree.append_hash(hash);
        assert_eq!(idx, 0);
        assert_eq!(tree.tree_size(), 1);

        let root = tree.root().unwrap();
        let proof = tree.generate_inclusion_proof(0).unwrap();
        assert!(verify_inclusion_proof(&proof, &hash.to_hex(), &root));
    }

    // -----------------------------------------------------------------------
    // Proof serialization roundtrip
    // -----------------------------------------------------------------------
    #[test]
    fn inclusion_proof_serialization_roundtrip() {
        let mut tree = MerkleTree::new();
        for i in 0..5u64 {
            tree.append(format!("leaf-{i}").as_bytes());
        }
        let proof = tree.generate_inclusion_proof(2).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let restored: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof.leaf_index, restored.leaf_index);
        assert_eq!(proof.tree_size, restored.tree_size);
        assert_eq!(proof.proof_path, restored.proof_path);

        let lh = leaf_hash(b"leaf-2").to_hex();
        let root = tree.root().unwrap();
        assert!(verify_inclusion_proof(&restored, &lh, &root));
    }

    #[test]
    fn consistency_proof_serialization_roundtrip() {
        let mut tree = MerkleTree::new();
        for i in 0..8u64 {
            tree.append(format!("leaf-{i}").as_bytes());
        }
        let proof = tree.generate_consistency_proof(4).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        let restored: ConsistencyProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof.old_size, restored.old_size);
        assert_eq!(proof.new_size, restored.new_size);
        assert_eq!(proof.proof_path, restored.proof_path);
    }

    // -----------------------------------------------------------------------
    // Consistency proof: same size yields empty proof
    // -----------------------------------------------------------------------
    #[test]
    fn consistency_proof_same_size() {
        let mut tree = MerkleTree::new();
        for i in 0..4u64 {
            tree.append(format!("leaf-{i}").as_bytes());
        }
        let proof = tree.generate_consistency_proof(4).unwrap();
        assert!(proof.proof_path.is_empty());
        let root = tree.root().unwrap();
        assert!(verify_consistency_proof_full(&proof, &root, &root));
    }

    // -----------------------------------------------------------------------
    // Append returns correct indices
    // -----------------------------------------------------------------------
    #[test]
    fn append_returns_sequential_indices() {
        let mut tree = MerkleTree::new();
        for i in 0..10u64 {
            let idx = tree.append(format!("leaf-{i}").as_bytes());
            assert_eq!(idx, i);
        }
    }

    // -----------------------------------------------------------------------
    // Two-leaf tree root verification
    // -----------------------------------------------------------------------
    #[test]
    fn two_leaf_tree_root() {
        let mut tree = MerkleTree::new();
        tree.append(b"left");
        tree.append(b"right");

        let expected = node_hash(&leaf_hash(b"left"), &leaf_hash(b"right"));
        assert_eq!(tree.root().unwrap(), expected.to_hex());
    }
}
