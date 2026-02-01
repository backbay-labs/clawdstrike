//! Cryptographic hashing (SHA-256 and Keccak-256)

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Keccak256;

use crate::error::{Error, Result};

/// A 32-byte hash value
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash {
    #[serde(with = "hash_serde")]
    bytes: [u8; 32],
}

mod hash_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(d: D) -> std::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(d)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("hash must be 32 bytes"))
    }
}

impl Hash {
    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Create from hex string (with or without 0x prefix)
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        let bytes = hex::decode(hex_str).map_err(|e| Error::InvalidHex(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(Error::InvalidHashLength {
                expected: 32,
                actual: bytes.len(),
            });
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(arr))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Export as hex (no prefix)
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Export as 0x-prefixed hex
    pub fn to_hex_prefixed(&self) -> String {
        format!("0x{}", self.to_hex())
    }

    /// Zero hash
    pub fn zero() -> Self {
        Self { bytes: [0u8; 32] }
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

/// Compute SHA-256 hash of data.
///
/// # Examples
///
/// ```rust
/// use hush_core::sha256;
///
/// let hash = sha256(b"hello");
/// assert_eq!(hash.as_bytes().len(), 32);
///
/// // Known test vector
/// assert_eq!(
///     hash.to_hex(),
///     "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
/// );
/// ```
pub fn sha256(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// Compute SHA-256 hash and return as hex string
pub fn sha256_hex(data: &[u8]) -> String {
    sha256(data).to_hex_prefixed()
}

/// Compute Keccak-256 hash (Ethereum-compatible).
///
/// # Examples
///
/// ```rust
/// use hush_core::keccak256;
///
/// let hash = keccak256(b"hello");
/// assert_eq!(hash.as_bytes().len(), 32);
///
/// // Known test vector (Ethereum keccak256)
/// assert_eq!(
///     hash.to_hex(),
///     "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
/// );
/// ```
pub fn keccak256(data: &[u8]) -> Hash {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash::from_bytes(bytes)
}

/// Compute Keccak-256 hash and return as hex string
pub fn keccak256_hex(data: &[u8]) -> String {
    keccak256(data).to_hex_prefixed()
}

/// Concatenate two hashes for Merkle tree computation
pub fn concat_hashes(left: &Hash, right: &Hash) -> Hash {
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(left.as_bytes());
    combined.extend_from_slice(right.as_bytes());
    sha256(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        // Known SHA-256 hash of "hello"
        assert_eq!(
            hash.to_hex(),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert!(hash.starts_with("0x"));
        assert_eq!(hash.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_keccak256() {
        let hash = keccak256(b"hello");
        // Known Keccak-256 hash of "hello"
        assert_eq!(
            hash.to_hex(),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_hash_from_hex() {
        let original = sha256(b"test");
        let from_hex = Hash::from_hex(&original.to_hex()).unwrap();
        let from_hex_prefixed = Hash::from_hex(&original.to_hex_prefixed()).unwrap();

        assert_eq!(original, from_hex);
        assert_eq!(original, from_hex_prefixed);
    }

    #[test]
    fn test_hash_serde() {
        let hash = sha256(b"test");
        let json = serde_json::to_string(&hash).unwrap();
        let restored: Hash = serde_json::from_str(&json).unwrap();

        assert_eq!(hash, restored);
        assert!(json.contains("0x")); // Should be prefixed in JSON
    }

    #[test]
    fn test_concat_hashes() {
        let h1 = sha256(b"left");
        let h2 = sha256(b"right");
        let combined = concat_hashes(&h1, &h2);

        // Should be deterministic
        let combined2 = concat_hashes(&h1, &h2);
        assert_eq!(combined, combined2);

        // Order matters
        let combined_reversed = concat_hashes(&h2, &h1);
        assert_ne!(combined, combined_reversed);
    }
}
