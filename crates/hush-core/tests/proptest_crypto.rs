//! Property-based tests for cryptographic primitives

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hush_core::{keccak256, sha256, Hash, Keypair};
use proptest::prelude::*;

proptest! {
    /// SHA-256 always produces the same hash for the same input
    #[test]
    fn sha256_deterministic(data in any::<Vec<u8>>()) {
        let h1 = sha256(&data);
        let h2 = sha256(&data);
        prop_assert_eq!(h1, h2);
    }

    /// SHA-256 always produces 32-byte output
    #[test]
    fn sha256_length(data in any::<Vec<u8>>()) {
        let hash = sha256(&data);
        prop_assert_eq!(hash.as_bytes().len(), 32);
    }

    /// Keccak-256 always produces the same hash for the same input
    #[test]
    fn keccak256_deterministic(data in any::<Vec<u8>>()) {
        let h1 = keccak256(&data);
        let h2 = keccak256(&data);
        prop_assert_eq!(h1, h2);
    }

    /// Keccak-256 always produces 32-byte output
    #[test]
    fn keccak256_length(data in any::<Vec<u8>>()) {
        let hash = keccak256(&data);
        prop_assert_eq!(hash.as_bytes().len(), 32);
    }

    /// Different inputs (usually) produce different hashes
    #[test]
    fn sha256_collision_resistance(
        data1 in any::<Vec<u8>>(),
        data2 in any::<Vec<u8>>(),
    ) {
        prop_assume!(data1 != data2);
        let h1 = sha256(&data1);
        let h2 = sha256(&data2);
        // This should almost always pass - collisions are astronomically unlikely
        prop_assert_ne!(h1, h2);
    }

    /// Sign/verify roundtrip always works
    #[test]
    fn sign_verify_roundtrip(message in any::<Vec<u8>>()) {
        let keypair = Keypair::generate();
        let signature = keypair.sign(&message);
        prop_assert!(keypair.public_key().verify(&message, &signature));
    }

    /// Different messages produce different signatures
    #[test]
    fn different_messages_different_signatures(
        msg1 in any::<Vec<u8>>(),
        msg2 in any::<Vec<u8>>(),
    ) {
        prop_assume!(msg1 != msg2);
        let keypair = Keypair::generate();
        let sig1 = keypair.sign(&msg1);
        let sig2 = keypair.sign(&msg2);
        prop_assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    /// Signature verification fails for wrong message
    #[test]
    fn verify_fails_wrong_message(
        msg1 in any::<Vec<u8>>(),
        msg2 in any::<Vec<u8>>(),
    ) {
        prop_assume!(msg1 != msg2);
        let keypair = Keypair::generate();
        let signature = keypair.sign(&msg1);
        prop_assert!(!keypair.public_key().verify(&msg2, &signature));
    }

    /// Hash from_hex/to_hex roundtrip
    #[test]
    fn hash_hex_roundtrip(data in any::<Vec<u8>>()) {
        let hash = sha256(&data);
        let hex_str = hash.to_hex();
        let restored = Hash::from_hex(&hex_str).expect("valid hex");
        prop_assert_eq!(hash, restored);
    }

    /// Hash 0x-prefixed hex roundtrip
    #[test]
    fn hash_hex_prefixed_roundtrip(data in any::<Vec<u8>>()) {
        let hash = sha256(&data);
        let hex_str = hash.to_hex_prefixed();
        let restored = Hash::from_hex(&hex_str).expect("valid hex");
        prop_assert_eq!(hash, restored);
    }
}
