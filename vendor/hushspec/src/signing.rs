//! Policy signing and verification using Ed25519.
//!
//! This module provides detached signature creation and verification for
//! HushSpec policy documents. Signatures are stored as `.sig` JSON files
//! alongside the signed policy file.
//!
//! # Design
//!
//! - **Content hash**: SHA-256 of the raw file bytes (not parsed/re-serialized).
//! - **Signature**: Ed25519 signature over the raw content hash bytes (32 bytes).
//! - **Key format**: Raw 32-byte keys encoded as base64.
//! - **Detached**: Signatures live in a separate `.sig` file, not inline in YAML.
//!
//! # Feature flag
//!
//! This module is only available when the `signing` feature is enabled.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The current signature format version.
pub const FORMAT_VERSION: &str = "0.1.0";

/// The signature algorithm identifier.
pub const ALGORITHM: &str = "ed25519";

#[derive(Serialize)]
struct SignedEnvelope<'a> {
    format_version: &'a str,
    algorithm: &'a str,
    content_hash: &'a str,
    signed_at: &'a str,
    key_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    signer: Option<&'a str>,
}

/// A detached policy signature, serializable to/from JSON `.sig` files.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySignature {
    pub format_version: String,
    pub algorithm: String,
    pub content_hash: String,
    pub signature: String,
    pub signed_at: String,
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum VerificationOutcome {
    Valid {
        key_id: String,
        signed_at: String,
        signer: Option<String>,
    },
    Invalid {
        reason: String,
    },
    NoSignature,
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid key data: {0}")]
    InvalidKey(String),

    #[error("invalid signature data: {0}")]
    InvalidSignature(String),

    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("unsupported format version: {0}")]
    UnsupportedVersion(String),
}

/// Compute the SHA-256 hex digest of raw content bytes.
pub fn content_hash(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let hash = hasher.finalize();
    hex::encode(hash)
}

/// Sign a policy file's raw content bytes.
///
/// The signature is computed over the SHA-256 hash of the raw bytes,
/// ensuring byte-exact verification regardless of YAML parser behavior.
pub fn sign_policy(
    content: &[u8],
    signing_key: &SigningKey,
    key_id: &str,
    signer: Option<&str>,
) -> PolicySignature {
    let hash = content_hash(content);
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let payload = signed_payload(&hash, &now, key_id, signer);
    let sig = signing_key.sign(&payload);

    PolicySignature {
        format_version: FORMAT_VERSION.to_string(),
        algorithm: ALGORITHM.to_string(),
        content_hash: hash,
        signature: BASE64.encode(sig.to_bytes()),
        signed_at: now,
        key_id: key_id.to_string(),
        signer: signer.map(String::from),
    }
}

/// Verify a policy signature against raw content bytes.
///
/// Returns [`VerificationOutcome::Valid`] if the signature matches,
/// [`VerificationOutcome::Invalid`] with a reason string otherwise.
pub fn verify_policy(
    content: &[u8],
    signature: &PolicySignature,
    verifying_key: &VerifyingKey,
) -> VerificationOutcome {
    if signature.format_version != FORMAT_VERSION {
        return VerificationOutcome::Invalid {
            reason: format!(
                "unsupported format version '{}', expected '{}'",
                signature.format_version, FORMAT_VERSION
            ),
        };
    }

    if signature.algorithm != ALGORITHM {
        return VerificationOutcome::Invalid {
            reason: format!(
                "unsupported algorithm '{}', expected '{}'",
                signature.algorithm, ALGORITHM
            ),
        };
    }

    let expected_hash = content_hash(content);
    if signature.content_hash != expected_hash {
        return VerificationOutcome::Invalid {
            reason: format!(
                "content hash mismatch: signature has '{}', computed '{}'",
                signature.content_hash, expected_hash
            ),
        };
    }

    let sig_bytes = match BASE64.decode(&signature.signature) {
        Ok(bytes) => bytes,
        Err(e) => {
            return VerificationOutcome::Invalid {
                reason: format!("invalid base64 in signature field: {e}"),
            };
        }
    };

    let ed_sig = match Signature::from_slice(&sig_bytes) {
        Ok(sig) => sig,
        Err(e) => {
            return VerificationOutcome::Invalid {
                reason: format!("invalid Ed25519 signature bytes: {e}"),
            };
        }
    };

    let payload = signed_payload(
        &signature.content_hash,
        &signature.signed_at,
        &signature.key_id,
        signature.signer.as_deref(),
    );
    match verifying_key.verify(&payload, &ed_sig) {
        Ok(()) => VerificationOutcome::Valid {
            key_id: signature.key_id.clone(),
            signed_at: signature.signed_at.clone(),
            signer: signature.signer.clone(),
        },
        Err(e) => VerificationOutcome::Invalid {
            reason: format!("Ed25519 signature verification failed: {e}"),
        },
    }
}

fn signed_payload(
    content_hash: &str,
    signed_at: &str,
    key_id: &str,
    signer: Option<&str>,
) -> Vec<u8> {
    serde_json::to_vec(&SignedEnvelope {
        format_version: FORMAT_VERSION,
        algorithm: ALGORITHM,
        content_hash,
        signed_at,
        key_id,
        signer,
    })
    .expect("signed envelope serialization should not fail")
}

/// Load a detached signature from a `.sig` JSON file.
pub fn load_signature(path: &Path) -> Result<PolicySignature, SigningError> {
    let content = std::fs::read_to_string(path)?;
    let sig: PolicySignature = serde_json::from_str(&content)?;

    if sig.format_version != FORMAT_VERSION {
        return Err(SigningError::UnsupportedVersion(sig.format_version.clone()));
    }
    if sig.algorithm != ALGORITHM {
        return Err(SigningError::UnsupportedAlgorithm(sig.algorithm.clone()));
    }

    Ok(sig)
}

/// Save a detached signature to a `.sig` JSON file.
pub fn save_signature(signature: &PolicySignature, path: &Path) -> Result<(), SigningError> {
    let json = serde_json::to_string_pretty(signature)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Generate a new Ed25519 keypair using `OsRng`.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn encode_signing_key(key: &SigningKey) -> String {
    BASE64.encode(key.to_bytes())
}

pub fn encode_verifying_key(key: &VerifyingKey) -> String {
    BASE64.encode(key.to_bytes())
}

pub fn decode_signing_key(encoded: &str) -> Result<SigningKey, SigningError> {
    let bytes = BASE64
        .decode(encoded.trim())
        .map_err(|e| SigningError::InvalidKey(format!("invalid base64: {e}")))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SigningError::InvalidKey("signing key must be exactly 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn decode_verifying_key(encoded: &str) -> Result<VerifyingKey, SigningError> {
    let bytes = BASE64
        .decode(encoded.trim())
        .map_err(|e| SigningError::InvalidKey(format!("invalid base64: {e}")))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SigningError::InvalidKey("verifying key must be exactly 32 bytes".into()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| SigningError::InvalidKey(format!("invalid Ed25519 public key: {e}")))
}

/// Format for on-disk key files.
///
/// Private key file (`hushspec.key`):
/// ```text
/// -----BEGIN HUSHSPEC PRIVATE KEY-----
/// <base64-encoded 32 bytes>
/// -----END HUSHSPEC PRIVATE KEY-----
/// ```
///
/// Public key file (`hushspec.pub`):
/// ```text
/// -----BEGIN HUSHSPEC PUBLIC KEY-----
/// <base64-encoded 32 bytes>
/// -----END HUSHSPEC PUBLIC KEY-----
/// ```
pub fn format_private_key_pem(key: &SigningKey) -> String {
    format!(
        "-----BEGIN HUSHSPEC PRIVATE KEY-----\n{}\n-----END HUSHSPEC PRIVATE KEY-----\n",
        encode_signing_key(key)
    )
}

/// Format a public key in PEM-like envelope.
pub fn format_public_key_pem(key: &VerifyingKey) -> String {
    format!(
        "-----BEGIN HUSHSPEC PUBLIC KEY-----\n{}\n-----END HUSHSPEC PUBLIC KEY-----\n",
        encode_verifying_key(key)
    )
}

/// Parse a private key from PEM-like envelope or raw base64.
pub fn parse_private_key_pem(content: &str) -> Result<SigningKey, SigningError> {
    let trimmed = content.trim();
    let key_data = if trimmed.starts_with("-----BEGIN HUSHSPEC PRIVATE KEY-----") {
        trimmed
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("")
    } else {
        trimmed.to_string()
    };
    decode_signing_key(&key_data)
}

/// Parse a public key from PEM-like envelope or raw base64.
pub fn parse_public_key_pem(content: &str) -> Result<VerifyingKey, SigningError> {
    let trimmed = content.trim();
    let key_data = if trimmed.starts_with("-----BEGIN HUSHSPEC PUBLIC KEY-----") {
        trimmed
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("")
    } else {
        trimmed.to_string()
    };
    decode_verifying_key(&key_data)
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_deterministic() {
        let data = b"hushspec: \"0.1.0\"\nname: test\n";
        let h1 = content_hash(data);
        let h2 = content_hash(data);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex = 64 chars
    }

    #[test]
    fn content_hash_differs_for_different_input() {
        let h1 = content_hash(b"hello");
        let h2 = content_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let content = b"hushspec: \"0.1.0\"\nname: test-sign\n";

        let sig = sign_policy(content, &sk, "test-key-1", Some("tester@example.com"));
        assert_eq!(sig.format_version, FORMAT_VERSION);
        assert_eq!(sig.algorithm, ALGORITHM);
        assert_eq!(sig.key_id, "test-key-1");
        assert_eq!(sig.signer.as_deref(), Some("tester@example.com"));
        assert_eq!(sig.content_hash, content_hash(content));

        let outcome = verify_policy(content, &sig, &vk);
        assert!(
            matches!(outcome, VerificationOutcome::Valid { .. }),
            "expected Valid, got {outcome:?}"
        );
    }

    #[test]
    fn verify_fails_with_wrong_key() {
        let (sk, _vk) = generate_keypair();
        let (_sk2, vk2) = generate_keypair();
        let content = b"policy content here";

        let sig = sign_policy(content, &sk, "key-1", None);
        let outcome = verify_policy(content, &sig, &vk2);
        assert!(
            matches!(outcome, VerificationOutcome::Invalid { .. }),
            "expected Invalid, got {outcome:?}"
        );
    }

    #[test]
    fn verify_fails_with_tampered_content() {
        let (sk, vk) = generate_keypair();
        let content = b"original content";

        let sig = sign_policy(content, &sk, "key-1", None);
        let tampered = b"tampered content";
        let outcome = verify_policy(tampered, &sig, &vk);
        assert!(
            matches!(outcome, VerificationOutcome::Invalid { ref reason } if reason.contains("content hash mismatch")),
            "expected Invalid with hash mismatch, got {outcome:?}"
        );
    }

    #[test]
    fn verify_rejects_unsupported_version() {
        let (sk, vk) = generate_keypair();
        let content = b"content";
        let mut sig = sign_policy(content, &sk, "key-1", None);
        sig.format_version = "99.0.0".to_string();

        let outcome = verify_policy(content, &sig, &vk);
        assert!(
            matches!(outcome, VerificationOutcome::Invalid { ref reason } if reason.contains("unsupported format version")),
            "got {outcome:?}"
        );
    }

    #[test]
    fn verify_rejects_unsupported_algorithm() {
        let (sk, vk) = generate_keypair();
        let content = b"content";
        let mut sig = sign_policy(content, &sk, "key-1", None);
        sig.algorithm = "rsa4096".to_string();

        let outcome = verify_policy(content, &sig, &vk);
        assert!(
            matches!(outcome, VerificationOutcome::Invalid { ref reason } if reason.contains("unsupported algorithm")),
            "got {outcome:?}"
        );
    }

    #[test]
    fn signature_json_roundtrip() {
        let (sk, _vk) = generate_keypair();
        let content = b"test policy data";
        let sig = sign_policy(content, &sk, "roundtrip-key", Some("alice"));

        let json = serde_json::to_string_pretty(&sig).unwrap();
        let deserialized: PolicySignature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, deserialized);
    }

    #[test]
    fn key_encoding_roundtrip() {
        let (sk, vk) = generate_keypair();

        let sk_encoded = encode_signing_key(&sk);
        let sk_decoded = decode_signing_key(&sk_encoded).unwrap();
        assert_eq!(sk.to_bytes(), sk_decoded.to_bytes());

        let vk_encoded = encode_verifying_key(&vk);
        let vk_decoded = decode_verifying_key(&vk_encoded).unwrap();
        assert_eq!(vk.to_bytes(), vk_decoded.to_bytes());
    }

    #[test]
    fn pem_format_roundtrip() {
        let (sk, vk) = generate_keypair();

        let sk_pem = format_private_key_pem(&sk);
        let sk_parsed = parse_private_key_pem(&sk_pem).unwrap();
        assert_eq!(sk.to_bytes(), sk_parsed.to_bytes());

        let vk_pem = format_public_key_pem(&vk);
        let vk_parsed = parse_public_key_pem(&vk_pem).unwrap();
        assert_eq!(vk.to_bytes(), vk_parsed.to_bytes());
    }

    #[test]
    fn pem_accepts_raw_base64() {
        let (sk, vk) = generate_keypair();

        let sk_raw = encode_signing_key(&sk);
        let sk_parsed = parse_private_key_pem(&sk_raw).unwrap();
        assert_eq!(sk.to_bytes(), sk_parsed.to_bytes());

        let vk_raw = encode_verifying_key(&vk);
        let vk_parsed = parse_public_key_pem(&vk_raw).unwrap();
        assert_eq!(vk.to_bytes(), vk_parsed.to_bytes());
    }

    #[test]
    fn signature_file_roundtrip() {
        let (sk, _vk) = generate_keypair();
        let content = b"file roundtrip test";
        let sig = sign_policy(content, &sk, "file-key", None);

        let dir = std::env::temp_dir().join(format!(
            "hushspec-sig-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        let sig_path = dir.join("policy.yaml.sig");
        save_signature(&sig, &sig_path).unwrap();
        let loaded = load_signature(&sig_path).unwrap();
        assert_eq!(sig, loaded);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn decode_signing_key_rejects_wrong_length() {
        let result = decode_signing_key(&BASE64.encode([0u8; 16]));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("32 bytes"));
    }

    #[test]
    fn decode_verifying_key_rejects_wrong_length() {
        let result = decode_verifying_key(&BASE64.encode([0u8; 16]));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("32 bytes"));
    }
}
