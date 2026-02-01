#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct MerkleInput {
    leaves: Vec<Vec<u8>>,
    proof_index: usize,
}

fuzz_target!(|input: MerkleInput| {
    // Skip empty or very large inputs
    if input.leaves.is_empty() || input.leaves.len() > 1000 {
        return;
    }

    // Building a tree should never panic
    let tree = match hush_core::MerkleTree::from_leaves(&input.leaves) {
        Ok(t) => t,
        Err(_) => return,
    };

    // Root should always be 32 bytes
    assert_eq!(tree.root().as_bytes().len(), 32);

    // Leaf count should match
    assert_eq!(tree.leaf_count(), input.leaves.len());

    // If index is valid, proof should verify
    if input.proof_index < input.leaves.len() {
        if let Ok(proof) = tree.inclusion_proof(input.proof_index) {
            let root = tree.root();
            assert!(proof.verify(&input.leaves[input.proof_index], &root));
        }
    }
});
