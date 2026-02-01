//! Integration tests for hush-wasm
//! These run as regular Rust tests (not WASM)

use hush_core::{Keypair, Receipt, SignedReceipt, Verdict};

#[test]
fn test_full_receipt_workflow() {
    // Create a receipt
    let content_hash = hush_core::sha256(b"test content");
    let receipt = Receipt::new(content_hash, Verdict::pass())
        .with_id("integration-test-001");

    // Sign it
    let keypair = Keypair::generate();
    let signed = SignedReceipt::sign(receipt, &keypair).unwrap();

    // Serialize to JSON
    let json = signed.to_json().unwrap();

    // This would be verified in WASM
    let restored = SignedReceipt::from_json(&json).unwrap();
    let keys = hush_core::receipt::PublicKeySet::new(keypair.public_key());
    let result = restored.verify(&keys);

    assert!(result.valid);
    assert!(result.signer_valid);
}

#[test]
fn test_merkle_proof_workflow() {
    use hush_core::MerkleTree;

    // Create leaves
    let leaves: Vec<Vec<u8>> = (0..5)
        .map(|i| format!("leaf-{}", i).into_bytes())
        .collect();

    // Build tree
    let tree = MerkleTree::from_leaves(&leaves).unwrap();
    let root = tree.root();

    // Generate proof for leaf 2
    let proof = tree.inclusion_proof(2).unwrap();

    // Verify proof
    assert!(proof.verify(&leaves[2], &root));

    // Serialize proof to JSON
    let proof_json = serde_json::to_string(&proof).unwrap();
    let restored: hush_core::MerkleProof = serde_json::from_str(&proof_json).unwrap();

    assert!(restored.verify(&leaves[2], &root));
}

#[test]
fn test_hash_functions() {
    let data = b"hello world";
    
    let sha_hash = hush_core::sha256(data);
    assert_eq!(sha_hash.to_hex().len(), 64);
    
    let keccak_hash = hush_core::keccak256(data);
    assert_eq!(keccak_hash.to_hex().len(), 64);
    
    // Hashes should be different
    assert_ne!(sha_hash, keccak_hash);
}

#[test]
fn test_signature_verification() {
    let keypair = Keypair::generate();
    let message = b"test message for signing";
    
    let signature = keypair.sign(message);
    
    // Valid verification
    assert!(keypair.public_key().verify(message, &signature));
    
    // Wrong message should fail
    assert!(!keypair.public_key().verify(b"wrong message", &signature));
}
