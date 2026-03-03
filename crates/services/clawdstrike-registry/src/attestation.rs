//! Publish attestation envelopes for the registry transparency log.
//!
//! A `PublishAttestation` records the registry's cryptographic witness of a
//! publish event: the publisher key, their signature over the content, the
//! content hash, and the registry's own counter-signature — all in a single
//! canonical JSON document that can be independently verified.

use hush_core::canonical::canonicalize;
use hush_core::{sha256, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::RegistryError;

/// Schema identifier for the attestation envelope.
pub const ATTESTATION_SCHEMA: &str = "clawdstrike.registry.publish_attestation.v1";

/// The attestation fact: a structured record of the publish event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublishAttestation {
    /// Schema version identifier.
    pub schema: String,
    /// Fully-qualified package name.
    pub package_name: String,
    /// SemVer version string.
    pub version: String,
    /// Hex-encoded Ed25519 public key of the publisher.
    pub publisher_key: String,
    /// Hex-encoded Ed25519 signature from the publisher over the content hash.
    pub publisher_signature: String,
    /// Hex-encoded SHA-256 hash of the `.cpkg` archive.
    pub content_hash: String,
    /// Hex-encoded Ed25519 counter-signature from the registry.
    pub registry_signature: String,
    /// Transparency log leaf index (populated once the Merkle tree is updated).
    pub leaf_index: Option<u64>,
    /// ISO-8601 timestamp of attestation creation.
    pub timestamp: String,
}

/// A signed attestation: the attestation fact plus the registry's envelope
/// signature over the canonical JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// The attestation body.
    pub attestation: PublishAttestation,
    /// Hex-encoded Ed25519 signature over the canonical JSON of `attestation`.
    pub envelope_signature: String,
    /// Hex-encoded public key of the signing registry key.
    pub registry_public_key: String,
    /// Key ID of the signing key (for key rotation).
    pub key_id: String,
}

impl PublishAttestation {
    /// Compute the canonical JSON representation of this attestation.
    pub fn to_canonical_json(&self) -> Result<String, RegistryError> {
        let value = serde_json::to_value(self)
            .map_err(|e| RegistryError::Internal(format!("attestation serialization: {e}")))?;
        canonicalize(&value)
            .map_err(|e| RegistryError::Internal(format!("attestation canonicalization: {e}")))
    }

    /// Compute the SHA-256 hash of the canonical JSON.
    pub fn hash(&self) -> Result<String, RegistryError> {
        let canonical = self.to_canonical_json()?;
        Ok(sha256(canonical.as_bytes()).to_hex())
    }
}

/// Input data for creating a publish attestation.
pub struct AttestationInput<'a> {
    pub package_name: &'a str,
    pub version: &'a str,
    pub publisher_key: &'a str,
    pub publisher_signature: &'a str,
    pub content_hash: &'a str,
    pub registry_signature: &'a str,
    pub leaf_index: Option<u64>,
    pub timestamp: &'a str,
}

/// Create a new publish attestation from the publish event data.
pub fn create_publish_attestation(input: &AttestationInput<'_>) -> PublishAttestation {
    PublishAttestation {
        schema: ATTESTATION_SCHEMA.to_string(),
        package_name: input.package_name.to_string(),
        version: input.version.to_string(),
        publisher_key: input.publisher_key.to_string(),
        publisher_signature: input.publisher_signature.to_string(),
        content_hash: input.content_hash.to_string(),
        registry_signature: input.registry_signature.to_string(),
        leaf_index: input.leaf_index,
        timestamp: input.timestamp.to_string(),
    }
}

/// Sign an attestation with the given registry keypair and key ID.
pub fn sign_attestation(
    attestation: &PublishAttestation,
    keypair: &Keypair,
    key_id: &str,
) -> Result<SignedAttestation, RegistryError> {
    let canonical = attestation.to_canonical_json()?;
    let signature = keypair.sign(canonical.as_bytes());

    Ok(SignedAttestation {
        attestation: attestation.clone(),
        envelope_signature: signature.to_hex(),
        registry_public_key: keypair.public_key().to_hex(),
        key_id: key_id.to_string(),
    })
}

/// Verify a signed attestation against the expected registry public key.
///
/// Returns the inner attestation on success, or a verification error.
#[allow(dead_code)]
pub fn verify_attestation(
    signed: &SignedAttestation,
    registry_pubkey: &PublicKey,
) -> Result<PublishAttestation, RegistryError> {
    let canonical = signed.attestation.to_canonical_json()?;

    let signature = Signature::from_hex(&signed.envelope_signature)
        .map_err(|e| RegistryError::Integrity(format!("invalid envelope signature hex: {e}")))?;

    if !registry_pubkey.verify(canonical.as_bytes(), &signature) {
        return Err(RegistryError::Integrity(
            "attestation envelope signature verification failed".into(),
        ));
    }

    Ok(signed.attestation.clone())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> Keypair {
        Keypair::from_seed(&[42u8; 32])
    }

    fn test_input(leaf_index: Option<u64>) -> AttestationInput<'static> {
        AttestationInput {
            package_name: "my-guard",
            version: "1.0.0",
            publisher_key: "pub_key_hex",
            publisher_signature: "pub_sig_hex",
            content_hash: "content_hash_hex",
            registry_signature: "registry_sig_hex",
            leaf_index,
            timestamp: "2025-06-01T00:00:00Z",
        }
    }

    #[test]
    fn create_sign_verify_roundtrip() {
        let kp = test_keypair();
        let attestation = create_publish_attestation(&test_input(None));

        let signed = sign_attestation(&attestation, &kp, "test-key-id").unwrap();
        let recovered = verify_attestation(&signed, &kp.public_key()).unwrap();

        assert_eq!(recovered.package_name, "my-guard");
        assert_eq!(recovered.version, "1.0.0");
        assert_eq!(recovered.schema, ATTESTATION_SCHEMA);
    }

    #[test]
    fn verify_rejects_tampered_attestation() {
        let kp = test_keypair();
        let attestation = create_publish_attestation(&test_input(None));

        let mut signed = sign_attestation(&attestation, &kp, "test-key-id").unwrap();
        // Tamper with the attestation body.
        signed.attestation.version = "2.0.0".to_string();

        let result = verify_attestation(&signed, &kp.public_key());
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("signature verification failed"));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp = test_keypair();
        let other_kp = Keypair::generate();

        let attestation = create_publish_attestation(&test_input(None));

        let signed = sign_attestation(&attestation, &kp, "test-key-id").unwrap();
        let result = verify_attestation(&signed, &other_kp.public_key());
        assert!(result.is_err());
    }

    #[test]
    fn attestation_hash_is_deterministic() {
        let a = create_publish_attestation(&AttestationInput {
            package_name: "pkg",
            version: "1.0.0",
            publisher_key: "pk",
            publisher_signature: "sig",
            content_hash: "hash",
            registry_signature: "rsig",
            leaf_index: None,
            timestamp: "2025-06-01T00:00:00Z",
        });
        let h1 = a.hash().unwrap();
        let h2 = a.hash().unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn attestation_with_leaf_index() {
        let kp = test_keypair();
        let attestation = create_publish_attestation(&test_input(Some(42)));

        assert_eq!(attestation.leaf_index, Some(42));

        let signed = sign_attestation(&attestation, &kp, "key-1").unwrap();
        let recovered = verify_attestation(&signed, &kp.public_key()).unwrap();
        assert_eq!(recovered.leaf_index, Some(42));
    }

    #[test]
    fn signed_attestation_serde_roundtrip() {
        let kp = test_keypair();
        let attestation = create_publish_attestation(&AttestationInput {
            package_name: "my-guard",
            version: "1.0.0",
            publisher_key: "pk",
            publisher_signature: "sig",
            content_hash: "hash",
            registry_signature: "rsig",
            leaf_index: Some(7),
            timestamp: "2025-06-01T00:00:00Z",
        });

        let signed = sign_attestation(&attestation, &kp, "k1").unwrap();
        let json = serde_json::to_string(&signed).unwrap();
        let restored: SignedAttestation = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.envelope_signature, signed.envelope_signature);
        assert_eq!(restored.attestation.package_name, "my-guard");

        // And it should still verify.
        let recovered = verify_attestation(&restored, &kp.public_key()).unwrap();
        assert_eq!(recovered.version, "1.0.0");
    }
}
