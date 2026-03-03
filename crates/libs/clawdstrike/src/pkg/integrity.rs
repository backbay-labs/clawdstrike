//! Package signing and verification using Ed25519 + SHA-256.

use std::fs;
use std::path::Path;

use hush_core::{Hash, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A cryptographic signature over a package archive.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PackageSignature {
    /// SHA-256 hash of the archive bytes.
    pub hash: Hash,
    /// Ed25519 signature over the hash bytes.
    pub signature: Signature,
    /// Optional embedded public key (for distribution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
}

/// Sign a `.cpkg` archive file.
///
/// Computes the SHA-256 hash of the file bytes, signs the hash with
/// the provided keypair, and returns a [`PackageSignature`].
pub fn sign_package(archive_path: &Path, keypair: &Keypair) -> Result<PackageSignature> {
    let bytes = fs::read(archive_path)?;
    let hash = hush_core::sha256(&bytes);
    let signature = keypair.sign(hash.as_bytes());

    Ok(PackageSignature {
        hash,
        signature,
        public_key: Some(keypair.public_key()),
    })
}

/// Verify a `.cpkg` archive against a [`PackageSignature`] and a public key.
///
/// Returns `true` if the archive hash matches and the signature is valid.
pub fn verify_package(
    archive_path: &Path,
    signature: &PackageSignature,
    public_key: &PublicKey,
) -> Result<bool> {
    let bytes = fs::read(archive_path)?;
    let hash = hush_core::sha256(&bytes);

    if hash != signature.hash {
        return Ok(false);
    }

    Ok(public_key.verify(hash.as_bytes(), &signature.signature))
}

/// Verify using the embedded public key inside the signature.
pub fn verify_package_embedded(archive_path: &Path, signature: &PackageSignature) -> Result<bool> {
    match &signature.public_key {
        Some(pk) => verify_package(archive_path, signature, pk),
        None => Err(Error::PkgError(
            "no public key embedded in signature".to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn create_test_archive(tmp: &Path) -> PathBuf {
        let archive = tmp.join("test.cpkg");
        fs::write(&archive, b"fake archive content for signing").unwrap();
        archive
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = create_test_archive(tmp.path());
        let keypair = Keypair::generate();

        let sig = sign_package(&archive, &keypair).unwrap();
        assert!(verify_package(&archive, &sig, &keypair.public_key()).unwrap());
    }

    #[test]
    fn verify_embedded_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = create_test_archive(tmp.path());
        let keypair = Keypair::generate();

        let sig = sign_package(&archive, &keypair).unwrap();
        assert!(verify_package_embedded(&archive, &sig).unwrap());
    }

    #[test]
    fn tamper_detection() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = create_test_archive(tmp.path());
        let keypair = Keypair::generate();

        let sig = sign_package(&archive, &keypair).unwrap();

        // Tamper with the archive.
        fs::write(&archive, b"tampered content!!!").unwrap();
        assert!(!verify_package(&archive, &sig, &keypair.public_key()).unwrap());
    }

    #[test]
    fn wrong_key_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = create_test_archive(tmp.path());
        let keypair = Keypair::generate();
        let other_keypair = Keypair::generate();

        let sig = sign_package(&archive, &keypair).unwrap();
        assert!(!verify_package(&archive, &sig, &other_keypair.public_key()).unwrap());
    }

    #[test]
    fn signature_serde_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = create_test_archive(tmp.path());
        let keypair = Keypair::generate();

        let sig = sign_package(&archive, &keypair).unwrap();
        let json = serde_json::to_string(&sig).unwrap();
        let restored: PackageSignature = serde_json::from_str(&json).unwrap();

        assert!(verify_package(&archive, &restored, &keypair.public_key()).unwrap());
    }
}
