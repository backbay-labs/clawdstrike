//! RFC 6962-compatible Merkle tree (Certificate Transparency style).
//!
//! This tree is required for transparency log checkpoints:
//! - `LeafHash(leaf_bytes) = SHA256(0x00 || leaf_bytes)`
//! - `NodeHash(left,right) = SHA256(0x01 || left || right)`
//!
//! This implementation does **not** "duplicate last" when a level has an odd
//! number of nodes; it carries the last node upward unchanged (left-balanced /
//! append-only semantics).

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::error::{Error, Result};
use crate::hashing::Hash;

/// Compute leaf hash per RFC 6962: SHA256(0x00 || leaf_bytes)
///
/// # Examples
///
/// ```rust
/// use hush_core::merkle::leaf_hash;
///
/// let hash = leaf_hash(b"hello");
/// assert_eq!(hash.as_bytes().len(), 32);
/// ```
pub fn leaf_hash(leaf_bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(leaf_bytes);
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// Compute node hash per RFC 6962: SHA256(0x01 || left || right)
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// RFC 6962-compatible Merkle tree
#[derive(Clone, Debug)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use hush_core::MerkleTree;
    ///
    /// let leaves = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    /// let tree = MerkleTree::from_leaves(&leaves).unwrap();
    /// assert_eq!(tree.leaf_count(), 3);
    /// ```
    pub fn from_leaves<T: AsRef<[u8]>>(leaves: &[T]) -> Result<Self> {
        if leaves.is_empty() {
            return Err(Error::EmptyTree);
        }

        let mut levels: Vec<Vec<Hash>> = Vec::new();
        let mut current: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l.as_ref())).collect();
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next: Vec<Hash> = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(node_hash(&current[i], &current[i + 1]));
                } else {
                    // Carry last node upward unchanged.
                    next.push(current[i]);
                }
                i += 2;
            }
            levels.push(next.clone());
            current = next;
        }

        Ok(Self { levels })
    }

    /// Build a Merkle tree from pre-hashed leaves
    pub fn from_hashes(leaf_hashes: Vec<Hash>) -> Result<Self> {
        if leaf_hashes.is_empty() {
            return Err(Error::EmptyTree);
        }

        let mut levels: Vec<Vec<Hash>> = Vec::new();
        let mut current = leaf_hashes;
        levels.push(current.clone());

        while current.len() > 1 {
            let mut next: Vec<Hash> = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                if i + 1 < current.len() {
                    next.push(node_hash(&current[i], &current[i + 1]));
                } else {
                    next.push(current[i]);
                }
                i += 2;
            }
            levels.push(next.clone());
            current = next;
        }

        Ok(Self { levels })
    }

    /// Get the number of leaves
    pub fn leaf_count(&self) -> usize {
        self.levels.first().map(|l| l.len()).unwrap_or(0)
    }

    /// Get the root hash
    pub fn root(&self) -> Hash {
        self.levels
            .last()
            .and_then(|l| l.first())
            .copied()
            .unwrap_or_else(Hash::zero)
    }

    /// Generate an inclusion proof for a leaf at the given index.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use hush_core::MerkleTree;
    ///
    /// let leaves = vec![b"a".to_vec(), b"b".to_vec()];
    /// let tree = MerkleTree::from_leaves(&leaves).unwrap();
    /// let proof = tree.inclusion_proof(0).unwrap();
    /// assert!(proof.verify(&leaves[0], &tree.root()));
    /// ```
    pub fn inclusion_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        let tree_size = self.leaf_count();
        if leaf_index >= tree_size {
            return Err(Error::InvalidProofIndex {
                index: leaf_index,
                leaves: tree_size,
            });
        }

        let mut audit_path: Vec<Hash> = Vec::new();
        let mut idx = leaf_index;

        for level in &self.levels {
            if level.len() <= 1 {
                break;
            }

            if idx % 2 == 0 {
                let sib = idx + 1;
                if sib < level.len() {
                    audit_path.push(level[sib]);
                }
            } else {
                audit_path.push(level[idx - 1]);
            }

            idx /= 2;
        }

        Ok(MerkleProof {
            tree_size,
            leaf_index,
            audit_path,
        })
    }
}

/// Merkle inclusion proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Total number of leaves in the tree
    pub tree_size: usize,
    /// Index of the leaf being proved
    pub leaf_index: usize,
    /// Audit path (sibling hashes from leaf to root)
    pub audit_path: Vec<Hash>,
}

impl MerkleProof {
    /// Compute the root from leaf bytes and the proof
    pub fn compute_root(&self, leaf_bytes: &[u8]) -> Result<Hash> {
        self.compute_root_from_hash(leaf_hash(leaf_bytes))
    }

    /// Compute the root from a pre-hashed leaf and the proof
    pub fn compute_root_from_hash(&self, leaf_hash: Hash) -> Result<Hash> {
        if self.tree_size == 0 || self.leaf_index >= self.tree_size {
            return Err(Error::MerkleProofFailed);
        }

        let mut h = leaf_hash;
        let mut idx = self.leaf_index;
        let mut size = self.tree_size;
        let mut it = self.audit_path.iter();

        while size > 1 {
            if idx % 2 == 0 {
                if idx + 1 < size {
                    let sibling = it.next().ok_or(Error::MerkleProofFailed)?;
                    h = node_hash(&h, sibling);
                } // else: carried upward (no sibling at this level)
            } else {
                let sibling = it.next().ok_or(Error::MerkleProofFailed)?;
                h = node_hash(sibling, &h);
            }

            idx /= 2;
            size = size.div_ceil(2);
        }

        if it.next().is_some() {
            return Err(Error::MerkleProofFailed);
        }

        Ok(h)
    }

    /// Verify the proof against expected root
    pub fn verify(&self, leaf_bytes: &[u8], expected_root: &Hash) -> bool {
        self.compute_root(leaf_bytes)
            .map(|root| &root == expected_root)
            .unwrap_or(false)
    }

    /// Verify the proof from a pre-hashed leaf
    pub fn verify_hash(&self, leaf_hash: Hash, expected_root: &Hash) -> bool {
        self.compute_root_from_hash(leaf_hash)
            .map(|root| &root == expected_root)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree_hash_recursive(level0: &[Hash]) -> Hash {
        match level0.len() {
            0 => Hash::zero(),
            1 => level0[0],
            n => {
                let k = largest_power_of_two_less_than(n);
                let left = tree_hash_recursive(&level0[..k]);
                let right = tree_hash_recursive(&level0[k..]);
                node_hash(&left, &right)
            }
        }
    }

    fn largest_power_of_two_less_than(n: usize) -> usize {
        let mut p = 1usize;
        while (p << 1) < n {
            p <<= 1;
        }
        p
    }

    #[test]
    fn root_matches_recursive_reference() {
        for n in 1..32usize {
            let leaves: Vec<Vec<u8>> = (0..n).map(|i| format!("leaf-{i}").into_bytes()).collect();
            let tree = MerkleTree::from_leaves(&leaves).unwrap();

            let leaf_hashes: Vec<Hash> = leaves.iter().map(|l| leaf_hash(l)).collect();
            let expected = tree_hash_recursive(&leaf_hashes);
            assert_eq!(tree.root(), expected, "n={n}");
        }
    }

    #[test]
    fn inclusion_proofs_roundtrip() {
        let leaves: Vec<Vec<u8>> = (0..25usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root();

        for (idx, leaf) in leaves.iter().enumerate() {
            let proof = tree.inclusion_proof(idx).unwrap();
            assert!(proof.verify(leaf, &root), "idx={idx}");
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_leaf() {
        let leaves: Vec<Vec<u8>> = (0..10usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let root = tree.root();

        let proof = tree.inclusion_proof(3).unwrap();
        assert!(!proof.verify(b"wrong", &root));
    }

    #[test]
    fn single_leaf_tree() {
        let tree = MerkleTree::from_leaves(&[b"single"]).unwrap();
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.root(), leaf_hash(b"single"));

        let proof = tree.inclusion_proof(0).unwrap();
        assert!(proof.verify(b"single", &tree.root()));
        assert!(proof.audit_path.is_empty());
    }

    #[test]
    fn two_leaf_tree() {
        let leaves: Vec<&[u8]> = vec![b"left", b"right"];
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        assert_eq!(tree.leaf_count(), 2);

        let expected_root = node_hash(&leaf_hash(b"left"), &leaf_hash(b"right"));
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn empty_tree_fails() {
        let empty: Vec<&[u8]> = vec![];
        let result = MerkleTree::from_leaves(&empty);
        assert!(result.is_err());
    }

    #[test]
    fn proof_serialization_roundtrip() {
        let leaves: Vec<Vec<u8>> = (0..5usize)
            .map(|i| format!("leaf-{i}").into_bytes())
            .collect();
        let tree = MerkleTree::from_leaves(&leaves).unwrap();
        let proof = tree.inclusion_proof(2).unwrap();

        let json = serde_json::to_string(&proof).unwrap();
        let restored: MerkleProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof.tree_size, restored.tree_size);
        assert_eq!(proof.leaf_index, restored.leaf_index);
        assert_eq!(proof.audit_path.len(), restored.audit_path.len());
        assert!(restored.verify(&leaves[2], &tree.root()));
    }
}
