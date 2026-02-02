# Clawdstrike OSS Workspace Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create the clawdstrike OSS repository with a complete Rust workspace containing crypto primitives (hush-core), network proxy utilities (hush-proxy), runtime guards (clawdstrike), CLI tool (hush-cli), and daemon (hushd).

**Architecture:** Extract and adapt battle-tested code from Glia Fab's cyntra-trust (crypto) and aegis-daemon (guards/policy) crates into a clean OSS workspace. The workspace follows a layered design: hush-core (crypto primitives) -> hush-proxy (network utilities) -> clawdstrike (guards + policy engine) -> hush-cli/hushd (user-facing tools).

**Tech Stack:** Rust 1.75+ (async traits), ed25519-dalek, sha2, sha3, serde, tokio, async-trait, regex, globset, ipnet

---

## Working Directory

All work happens in: `/Users/connor/Medica/clawdstrike-ws1-oss-repo/`

## Source Reference Paths (in glia-fab)

- Crypto: `/Users/connor/Medica/glia-fab/crates/cyntra-trust/src/`
- Guards: `/Users/connor/Medica/glia-fab/crates/aegis-daemon/src/guards/`
- Config: `/Users/connor/Medica/glia-fab/crates/aegis-daemon/src/config.rs`
- Proxy: `/Users/connor/Medica/glia-fab/crates/aegis-proxy-core/src/`

---

## Task 1: Workspace Cargo.toml Setup

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/.gitkeep`

**Step 1: Create workspace Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "crates/hush-core",
    "crates/hush-proxy",
    "crates/clawdstrike",
    "crates/hush-cli",
    "crates/hushd",
]

[workspace.package]
version = "0.1.0"
edition = "2021"
license = "MIT"
repository = "https://github.com/backbay-labs/clawdstrike"
rust-version = "1.75"

[workspace.dependencies]
# Crypto
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
sha2 = "0.10"
sha3 = "0.10"
rand = "0.8"
hex = "0.4"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9"

# Async runtime
tokio = { version = "1.35", features = ["full"] }
async-trait = "0.1"

# Patterns
regex = "1.10"
globset = "0.4"
ipnet = "2.9"

# Error handling
thiserror = "1.0"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }

# Time
chrono = { version = "0.4", features = ["serde"] }

# UUID
uuid = { version = "1.6", features = ["v4", "serde"] }

# CLI
clap = { version = "4.4", features = ["derive"] }

# Internal crates
hush-core = { path = "crates/hush-core" }
hush-proxy = { path = "crates/hush-proxy" }
clawdstrike = { path = "crates/clawdstrike" }

[profile.release]
lto = true
codegen-units = 1
```

**Step 2: Create crates directory**

```bash
mkdir -p crates
```

**Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "feat: initialize Rust workspace with member crates"
```

---

## Task 2: hush-core Crate - Cargo.toml and lib.rs

**Files:**
- Create: `crates/hush-core/Cargo.toml`
- Create: `crates/hush-core/src/lib.rs`

**Step 1: Create hush-core Cargo.toml**

```toml
[package]
name = "hush-core"
description = "Core cryptographic primitives for clawdstrike"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
ed25519-dalek.workspace = true
sha2.workspace = true
sha3.workspace = true
rand.workspace = true
hex.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["rt-multi-thread", "macros"] }

[features]
default = []
wasm = []
```

**Step 2: Create lib.rs module structure**

```rust
//! Hush Core Cryptographic Primitives
//!
//! Core cryptographic operations for the clawdstrike attestation system:
//! - Ed25519 signing and verification
//! - SHA-256 and Keccak-256 hashing
//! - Merkle tree construction and proof verification
//! - Canonical JSON (RFC 8785)
//! - Receipt types and signing

pub mod signing;
pub mod hashing;
pub mod canonical;
pub mod merkle;
pub mod receipt;
pub mod error;

pub use signing::{Keypair, PublicKey, Signature};
pub use hashing::{Hash, sha256, sha256_hex, keccak256, keccak256_hex};
pub use canonical::canonicalize as canonicalize_json;
pub use merkle::{MerkleTree, MerkleProof};
pub use receipt::{Receipt, SignedReceipt, Verdict, Provenance};
pub use error::{Error, Result};

/// Commonly used types
pub mod prelude {
    pub use crate::{
        Keypair, PublicKey, Signature,
        Hash, sha256, keccak256,
        MerkleTree, MerkleProof,
        Receipt, SignedReceipt,
        Error, Result,
    };
}
```

**Step 3: Commit**

```bash
git add crates/hush-core/
git commit -m "feat(hush-core): add Cargo.toml and lib.rs module structure"
```

---

## Task 3: hush-core Error Types

**Files:**
- Create: `crates/hush-core/src/error.rs`

**Step 1: Create error.rs**

```rust
//! Error types for hush-core operations

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Invalid hex encoding: {0}")]
    InvalidHex(String),

    #[error("Invalid hash length: expected {expected}, got {actual}")]
    InvalidHashLength { expected: usize, actual: usize },

    #[error("Merkle proof verification failed")]
    MerkleProofFailed,

    #[error("Empty tree: cannot compute root")]
    EmptyTree,

    #[error("Invalid proof: leaf index {index} out of bounds for tree with {leaves} leaves")]
    InvalidProofIndex { index: usize, leaves: usize },

    #[error("JSON serialization error: {0}")]
    JsonError(String),

    #[error("Receipt verification failed: {0}")]
    ReceiptVerificationFailed(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::JsonError(e.to_string())
    }
}

/// Result type for hush-core operations
pub type Result<T> = std::result::Result<T, Error>;
```

**Step 2: Commit**

```bash
git add crates/hush-core/src/error.rs
git commit -m "feat(hush-core): add error types"
```

---

## Task 4: hush-core Signing Module

**Files:**
- Create: `crates/hush-core/src/signing.rs`

**Step 1: Create signing.rs (Ed25519 implementation)**

```rust
//! Ed25519 signing and verification

use ed25519_dalek::{
    SigningKey, VerifyingKey,
    Signature as DalekSignature,
    Signer, Verifier,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::error::{Result, Error};

/// Ed25519 keypair for signing
#[derive(Clone)]
pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Create from raw seed bytes (32 bytes)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        Self { signing_key }
    }

    /// Create from hex-encoded seed
    pub fn from_hex(hex_seed: &str) -> Result<Self> {
        let hex_seed = hex_seed.strip_prefix("0x").unwrap_or(hex_seed);
        let bytes = hex::decode(hex_seed)
            .map_err(|e| Error::InvalidHex(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(Error::InvalidPrivateKey);
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self::from_seed(&seed))
    }

    /// Get the public key
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            verifying_key: self.signing_key.verifying_key(),
        }
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> Signature {
        let sig = self.signing_key.sign(message);
        Signature { inner: sig }
    }

    /// Export seed as hex
    pub fn to_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }
}

/// Ed25519 public key for verification
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey {
    #[serde(with = "pubkey_serde")]
    verifying_key: VerifyingKey,
}

mod pubkey_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(key: &VerifyingKey, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&hex::encode(key.to_bytes()))
    }

    pub fn deserialize<'de, D>(d: D) -> std::result::Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(d)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
            serde::de::Error::custom("public key must be 32 bytes")
        })?;
        VerifyingKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

impl PublicKey {
    /// Create from raw bytes (32 bytes)
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_bytes(bytes)
            .map_err(|e| Error::InvalidPublicKey(e.to_string()))?;
        Ok(Self { verifying_key })
    }

    /// Create from hex-encoded bytes
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)
            .map_err(|e| Error::InvalidHex(e.to_string()))?;

        if bytes.len() != 32 {
            return Err(Error::InvalidPublicKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify(message, &signature.inner).is_ok()
    }

    /// Export as hex
    pub fn to_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Export as 0x-prefixed hex
    pub fn to_hex_prefixed(&self) -> String {
        format!("0x{}", self.to_hex())
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.verifying_key.as_bytes()
    }
}

/// Ed25519 signature
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Signature {
    #[serde(with = "sig_serde")]
    inner: DalekSignature,
}

mod sig_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(sig: &DalekSignature, s: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&hex::encode(sig.to_bytes()))
    }

    pub fn deserialize<'de, D>(d: D) -> std::result::Result<DalekSignature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str = String::deserialize(d)?;
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
        let bytes = hex::decode(hex_str).map_err(serde::de::Error::custom)?;
        let bytes: [u8; 64] = bytes.try_into().map_err(|_| {
            serde::de::Error::custom("signature must be 64 bytes")
        })?;
        Ok(DalekSignature::from_bytes(&bytes))
    }
}

impl Signature {
    /// Create from raw bytes (64 bytes)
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self {
            inner: DalekSignature::from_bytes(bytes),
        }
    }

    /// Create from hex-encoded bytes
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)
            .map_err(|e| Error::InvalidHex(e.to_string()))?;

        if bytes.len() != 64 {
            return Err(Error::InvalidSignature);
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&arr))
    }

    /// Export as hex
    pub fn to_hex(&self) -> String {
        hex::encode(self.inner.to_bytes())
    }

    /// Export as 0x-prefixed hex
    pub fn to_hex_prefixed(&self) -> String {
        format!("0x{}", self.to_hex())
    }

    /// Get raw bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }
}

/// Verify a signature (convenience function)
pub fn verify_signature(public_key: &PublicKey, message: &[u8], signature: &Signature) -> bool {
    public_key.verify(message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let keypair = Keypair::generate();
        let message = b"Hello, Clawdstrike!";

        let signature = keypair.sign(message);
        assert!(keypair.public_key().verify(message, &signature));
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let keypair = Keypair::generate();
        let signature = keypair.sign(b"Hello, Clawdstrike!");
        assert!(!keypair.public_key().verify(b"Wrong message", &signature));
    }

    #[test]
    fn test_keypair_from_seed() {
        let seed = [42u8; 32];
        let kp1 = Keypair::from_seed(&seed);
        let kp2 = Keypair::from_seed(&seed);

        assert_eq!(kp1.public_key().to_hex(), kp2.public_key().to_hex());
    }

    #[test]
    fn test_hex_roundtrip() {
        let keypair = Keypair::generate();
        let pubkey_hex = keypair.public_key().to_hex();
        let restored = PublicKey::from_hex(&pubkey_hex).unwrap();

        assert_eq!(keypair.public_key(), restored);
    }

    #[test]
    fn test_signature_hex_roundtrip() {
        let keypair = Keypair::generate();
        let signature = keypair.sign(b"test");
        let sig_hex = signature.to_hex();
        let restored = Signature::from_hex(&sig_hex).unwrap();

        assert_eq!(signature.to_bytes(), restored.to_bytes());
    }

    #[test]
    fn test_serde_roundtrip() {
        let keypair = Keypair::generate();
        let pubkey = keypair.public_key();
        let signature = keypair.sign(b"test");

        let pubkey_json = serde_json::to_string(&pubkey).unwrap();
        let sig_json = serde_json::to_string(&signature).unwrap();

        let pubkey_restored: PublicKey = serde_json::from_str(&pubkey_json).unwrap();
        let sig_restored: Signature = serde_json::from_str(&sig_json).unwrap();

        assert_eq!(pubkey, pubkey_restored);
        assert!(pubkey.verify(b"test", &sig_restored));
    }
}
```

**Step 2: Verify tests pass**

```bash
cd /Users/connor/Medica/clawdstrike-ws1-oss-repo && cargo test -p hush-core signing
```

**Step 3: Commit**

```bash
git add crates/hush-core/src/signing.rs
git commit -m "feat(hush-core): add Ed25519 signing module"
```

---

## Task 5: hush-core Hashing Module

**Files:**
- Create: `crates/hush-core/src/hashing.rs`

**Step 1: Create hashing.rs (SHA-256 and Keccak-256)**

```rust
//! Cryptographic hashing (SHA-256 and Keccak-256)

use sha2::{Sha256, Digest as Sha2Digest};
use sha3::Keccak256;
use serde::{Deserialize, Serialize};

use crate::error::{Result, Error};

/// A 32-byte hash value
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash {
    #[serde(with = "hash_serde")]
    bytes: [u8; 32],
}

mod hash_serde {
    use serde::{Deserializer, Serializer, Deserialize};

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
        bytes.try_into().map_err(|_| {
            serde::de::Error::custom("hash must be 32 bytes")
        })
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

        let bytes = hex::decode(hex_str)
            .map_err(|e| Error::InvalidHex(e.to_string()))?;

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

/// Compute SHA-256 hash
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

/// Compute Keccak-256 hash (Ethereum-compatible)
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
```

**Step 2: Verify tests pass**

```bash
cd /Users/connor/Medica/clawdstrike-ws1-oss-repo && cargo test -p hush-core hashing
```

**Step 3: Commit**

```bash
git add crates/hush-core/src/hashing.rs
git commit -m "feat(hush-core): add SHA-256 and Keccak-256 hashing"
```

---

## Task 6: hush-core Canonical JSON Module

**Files:**
- Create: `crates/hush-core/src/canonical.rs`

**Step 1: Create canonical.rs (RFC 8785 JCS implementation)**

```rust
//! Canonical JSON for hashing/signatures (RFC 8785 JCS)
//!
//! Provides byte-for-byte identical canonical JSON across Rust/Python/TS.

use serde_json::Value;

use crate::error::{Result, Error};

/// Canonicalize a JSON value using RFC 8785 (JCS).
pub fn canonicalize(value: &Value) -> Result<String> {
    match value {
        Value::Object(map) => {
            let mut pairs: Vec<_> = map.iter().collect();
            pairs.sort_by(|(a, _), (b, _)| a.as_str().cmp(b.as_str()));

            let mut out = String::from("{");
            for (idx, (k, v)) in pairs.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(&escape_json_string(k));
                out.push_str("\":");
                out.push_str(&canonicalize(v)?);
            }
            out.push('}');
            Ok(out)
        }
        Value::Array(arr) => {
            let mut out = String::from("[");
            for (idx, v) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&canonicalize(v)?);
            }
            out.push(']');
            Ok(out)
        }
        Value::String(s) => Ok(format!("\"{}\"", escape_json_string(s))),
        Value::Number(n) => canonicalize_number(n),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok("null".to_string()),
    }
}

fn canonicalize_number(n: &serde_json::Number) -> Result<String> {
    if let Some(i) = n.as_i64() {
        return Ok(i.to_string());
    }
    if let Some(u) = n.as_u64() {
        return Ok(u.to_string());
    }
    if let Some(f) = n.as_f64() {
        return canonicalize_f64(f);
    }
    Err(Error::JsonError("Unsupported JSON number".into()))
}

/// JCS number serialization for IEEE-754 doubles.
fn canonicalize_f64(v: f64) -> Result<String> {
    if !v.is_finite() {
        return Err(Error::JsonError("Non-finite numbers are not valid JSON".into()));
    }
    if v == 0.0 {
        return Ok("0".to_string());
    }

    let sign = if v.is_sign_negative() { "-" } else { "" };
    let abs = v.abs();
    let use_exponential = abs >= 1e21 || abs < 1e-6;

    let (digits, sci_exp) = parse_to_scientific_parts(&format!("{:?}", abs))?;

    if !use_exponential {
        let rendered = render_decimal(&digits, sci_exp);
        return Ok(format!("{}{}", sign, rendered));
    }

    let mantissa = if digits.len() == 1 {
        digits.clone()
    } else {
        format!("{}.{}", &digits[0..1], &digits[1..])
    };
    let exp_sign = if sci_exp >= 0 { "+" } else { "" };
    Ok(format!("{sign}{mantissa}e{exp_sign}{sci_exp}"))
}

fn parse_to_scientific_parts(s: &str) -> Result<(String, i32)> {
    let s = s.trim();
    if s.is_empty() {
        return Err(Error::JsonError("Empty number string".into()));
    }

    let (mantissa, exp_opt) = if let Some((m, e)) = s.split_once('e') {
        (m, Some(e))
    } else if let Some((m, e)) = s.split_once('E') {
        (m, Some(e))
    } else {
        (s, None)
    };

    let (digits_before_dot, mut digits) = if let Some((a, b)) = mantissa.split_once('.') {
        let frac = b.trim_end_matches('0');
        (a.len() as i32, format!("{a}{frac}"))
    } else {
        (mantissa.len() as i32, mantissa.to_string())
    };

    digits = digits.trim_start_matches('0').to_string();
    if digits.is_empty() {
        digits = "0".to_string();
    }
    digits = digits.trim_end_matches('0').to_string();
    if digits.is_empty() {
        digits = "0".to_string();
    }

    let sci_exp = if let Some(exp_str) = exp_opt {
        let exp: i32 = exp_str
            .parse()
            .map_err(|_| Error::JsonError(format!("Invalid exponent: {exp_str}")))?;
        exp + (digits_before_dot - 1)
    } else {
        if mantissa.contains('.') {
            let (int_part, frac_part_raw) = mantissa
                .split_once('.')
                .ok_or_else(|| Error::JsonError("Invalid decimal".into()))?;
            let frac_part = frac_part_raw.trim_end_matches('0');

            let int_stripped = int_part.trim_start_matches('0');
            if !int_stripped.is_empty() {
                (int_stripped.len() as i32) - 1
            } else {
                let leading_zeros = frac_part.chars().take_while(|c| *c == '0').count() as i32;
                -(leading_zeros + 1)
            }
        } else {
            (mantissa.trim_start_matches('0').len() as i32) - 1
        }
    };

    Ok((digits, sci_exp))
}

fn render_decimal(digits: &str, sci_exp: i32) -> String {
    let digits_len = digits.len() as i32;
    let shift = sci_exp - (digits_len - 1);

    if shift >= 0 {
        let mut out = String::with_capacity(digits.len() + shift as usize);
        out.push_str(digits);
        out.extend(std::iter::repeat('0').take(shift as usize));
        return out;
    }

    let pos = digits_len + shift;
    if pos > 0 {
        let pos_usize = pos as usize;
        let mut out = String::with_capacity(digits.len() + 1);
        out.push_str(&digits[..pos_usize]);
        out.push('.');
        out.push_str(&digits[pos_usize..]);
        trim_decimal(out)
    } else {
        let zeros = (-pos) as usize;
        let mut out = String::with_capacity(2 + zeros + digits.len());
        out.push_str("0.");
        out.extend(std::iter::repeat('0').take(zeros));
        out.push_str(digits);
        trim_decimal(out)
    }
}

fn trim_decimal(mut s: String) -> String {
    if let Some(dot) = s.find('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.len() == dot + 1 {
            s.pop();
        }
    }
    s
}

fn escape_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\u{08}' => result.push_str("\\b"),
            '\u{0C}' => result.push_str("\\f"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_numbers() {
        let value = serde_json::json!({
            "a": 1.0,
            "b": 0.0,
            "c": -0.0,
            "d": 1e21,
            "e": 1e20,
            "f": 1e-6,
            "g": 1e-7,
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(
            canonical,
            r#"{"a":1,"b":0,"c":0,"d":1e+21,"e":100000000000000000000,"f":0.000001,"g":1e-7}"#
        );
    }

    #[test]
    fn test_unicode_and_controls() {
        let value = serde_json::json!({
            "emoji": "\u{1F600}",
            "nl": "\n",
            "tab": "\t",
        });

        let canonical = canonicalize(&value).unwrap();
        assert!(canonical.contains("\\n"));
        assert!(canonical.contains("\\t"));
    }

    #[test]
    fn test_escape_shortcuts() {
        let value = serde_json::json!({
            "b": "\u{0008}",
            "f": "\u{000c}",
            "quote": "\"",
            "backslash": "\\",
        });

        let canonical = canonicalize(&value).unwrap();
        assert!(canonical.contains("\\b"));
        assert!(canonical.contains("\\f"));
        assert!(canonical.contains("\\\""));
        assert!(canonical.contains("\\\\"));
    }

    #[test]
    fn test_key_ordering() {
        let value = serde_json::json!({
            "z": 1,
            "a": 2,
            "m": 3,
        });

        let canonical = canonicalize(&value).unwrap();
        assert_eq!(canonical, r#"{"a":2,"m":3,"z":1}"#);
    }
}
```

**Step 2: Verify tests pass**

```bash
cd /Users/connor/Medica/clawdstrike-ws1-oss-repo && cargo test -p hush-core canonical
```

**Step 3: Commit**

```bash
git add crates/hush-core/src/canonical.rs
git commit -m "feat(hush-core): add RFC 8785 canonical JSON"
```

---

## Task 7: hush-core Merkle Tree Module

**Files:**
- Create: `crates/hush-core/src/merkle.rs`

**Step 1: Create merkle.rs**

```rust
//! Merkle tree construction and proof verification.

use serde::{Deserialize, Serialize};

use crate::error::{Result, Error};
use crate::hashing::{Hash, sha256, concat_hashes};

/// A Merkle tree built from leaf hashes
#[derive(Clone, Debug)]
pub struct MerkleTree {
    nodes: Vec<Hash>,
    leaf_count: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from leaf data (hashes each item first)
    pub fn from_data<T: AsRef<[u8]>>(items: &[T]) -> Result<Self> {
        if items.is_empty() {
            return Err(Error::EmptyTree);
        }

        let leaves: Vec<Hash> = items.iter().map(|item| sha256(item.as_ref())).collect();
        Self::from_leaves(leaves)
    }

    /// Build a Merkle tree from pre-computed leaf hashes
    pub fn from_leaves(leaves: Vec<Hash>) -> Result<Self> {
        if leaves.is_empty() {
            return Err(Error::EmptyTree);
        }

        let leaf_count = leaves.len();
        let mut nodes = Vec::with_capacity(leaf_count * 2);
        nodes.extend(leaves);

        let mut level_start = 0;
        let mut level_len = leaf_count;

        while level_len > 1 {
            let next_level_start = nodes.len();

            for i in (0..level_len).step_by(2) {
                let left = &nodes[level_start + i];
                let right = if i + 1 < level_len {
                    &nodes[level_start + i + 1]
                } else {
                    left
                };
                nodes.push(concat_hashes(left, right));
            }

            level_start = next_level_start;
            level_len = (level_len + 1) / 2;
        }

        Ok(Self { nodes, leaf_count })
    }

    /// Build from hex-encoded leaf hashes
    pub fn from_hex_leaves(hex_leaves: &[String]) -> Result<Self> {
        let leaves: Result<Vec<Hash>> = hex_leaves
            .iter()
            .map(|h| Hash::from_hex(h))
            .collect();
        Self::from_leaves(leaves?)
    }

    /// Get the Merkle root
    pub fn root(&self) -> Hash {
        self.nodes[self.nodes.len() - 1]
    }

    /// Get the number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// Get a leaf hash by index
    pub fn leaf(&self, index: usize) -> Option<&Hash> {
        if index < self.leaf_count {
            Some(&self.nodes[index])
        } else {
            None
        }
    }

    /// Generate an inclusion proof for a leaf
    pub fn get_proof(&self, leaf_index: usize) -> Result<MerkleProof> {
        if leaf_index >= self.leaf_count {
            return Err(Error::InvalidProofIndex {
                index: leaf_index,
                leaves: self.leaf_count,
            });
        }

        let mut siblings = Vec::new();
        let mut path_bits = Vec::new();

        let mut current_index = leaf_index;
        let mut level_start = 0;
        let mut level_len = self.leaf_count;

        while level_len > 1 {
            let sibling_index = if current_index % 2 == 0 {
                path_bits.push(false);
                if current_index + 1 < level_len {
                    current_index + 1
                } else {
                    current_index
                }
            } else {
                path_bits.push(true);
                current_index - 1
            };

            siblings.push(self.nodes[level_start + sibling_index]);

            current_index /= 2;
            level_start += level_len;
            level_len = (level_len + 1) / 2;
        }

        Ok(MerkleProof {
            leaf_hash: self.nodes[leaf_index],
            siblings,
            path_bits,
            root: self.root(),
        })
    }
}

/// A Merkle inclusion proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_hash: Hash,
    pub siblings: Vec<Hash>,
    pub path_bits: Vec<bool>,
    pub root: Hash,
}

impl MerkleProof {
    /// Verify the proof
    pub fn verify(&self) -> bool {
        self.verify_against(&self.leaf_hash, &self.root)
    }

    /// Verify against specific leaf and root
    pub fn verify_against(&self, leaf_hash: &Hash, expected_root: &Hash) -> bool {
        if self.siblings.len() != self.path_bits.len() {
            return false;
        }

        let mut current = *leaf_hash;

        for (sibling, is_right) in self.siblings.iter().zip(self.path_bits.iter()) {
            current = if *is_right {
                concat_hashes(sibling, &current)
            } else {
                concat_hashes(&current, sibling)
            };
        }

        current == *expected_root
    }

    /// Convert to JSON string
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let tree = MerkleTree::from_data(&[b"leaf1"]).unwrap();
        assert_eq!(tree.leaf_count(), 1);

        let proof = tree.get_proof(0).unwrap();
        assert!(proof.verify());
        assert!(proof.siblings.is_empty());
    }

    #[test]
    fn test_two_leaves() {
        let tree = MerkleTree::from_data(&[b"leaf1", b"leaf2"]).unwrap();
        assert_eq!(tree.leaf_count(), 2);

        let proof0 = tree.get_proof(0).unwrap();
        let proof1 = tree.get_proof(1).unwrap();

        assert!(proof0.verify());
        assert!(proof1.verify());
        assert_eq!(proof0.siblings.len(), 1);
        assert_eq!(proof1.siblings.len(), 1);
    }

    #[test]
    fn test_power_of_two_leaves() {
        let items: Vec<Vec<u8>> = (0..8).map(|i| format!("leaf{}", i).into_bytes()).collect();
        let tree = MerkleTree::from_data(&items).unwrap();
        assert_eq!(tree.leaf_count(), 8);

        for i in 0..8 {
            let proof = tree.get_proof(i).unwrap();
            assert!(proof.verify(), "Proof {} failed", i);
            assert_eq!(proof.siblings.len(), 3);
        }
    }

    #[test]
    fn test_non_power_of_two_leaves() {
        let items: Vec<Vec<u8>> = (0..5).map(|i| format!("leaf{}", i).into_bytes()).collect();
        let tree = MerkleTree::from_data(&items).unwrap();
        assert_eq!(tree.leaf_count(), 5);

        for i in 0..5 {
            let proof = tree.get_proof(i).unwrap();
            assert!(proof.verify(), "Proof {} failed", i);
        }
    }

    #[test]
    fn test_proof_wrong_leaf() {
        let tree = MerkleTree::from_data(&[b"leaf1", b"leaf2", b"leaf3"]).unwrap();
        let proof = tree.get_proof(0).unwrap();

        let wrong_leaf = sha256(b"wrong");
        assert!(!proof.verify_against(&wrong_leaf, &proof.root));
    }

    #[test]
    fn test_proof_wrong_root() {
        let tree = MerkleTree::from_data(&[b"leaf1", b"leaf2", b"leaf3"]).unwrap();
        let proof = tree.get_proof(0).unwrap();

        let wrong_root = sha256(b"wrong");
        assert!(!proof.verify_against(&proof.leaf_hash, &wrong_root));
    }

    #[test]
    fn test_deterministic_root() {
        let items = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let tree1 = MerkleTree::from_data(&items).unwrap();
        let tree2 = MerkleTree::from_data(&items).unwrap();

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_proof_serialization() {
        let tree = MerkleTree::from_data(&[b"leaf1", b"leaf2"]).unwrap();
        let proof = tree.get_proof(0).unwrap();

        let json = proof.to_json().unwrap();
        let restored = MerkleProof::from_json(&json).unwrap();

        assert!(restored.verify());
        assert_eq!(proof.root, restored.root);
    }

    #[test]
    fn test_empty_tree() {
        let result = MerkleTree::from_data::<&[u8]>(&[]);
        assert!(matches!(result, Err(Error::EmptyTree)));
    }

    #[test]
    fn test_invalid_proof_index() {
        let tree = MerkleTree::from_data(&[b"leaf1"]).unwrap();
        let result = tree.get_proof(5);
        assert!(matches!(result, Err(Error::InvalidProofIndex { .. })));
    }
}
```

**Step 2: Verify tests pass**

```bash
cd /Users/connor/Medica/clawdstrike-ws1-oss-repo && cargo test -p hush-core merkle
```

**Step 3: Commit**

```bash
git add crates/hush-core/src/merkle.rs
git commit -m "feat(hush-core): add Merkle tree construction and proofs"
```

---

## Task 8: hush-core Receipt Module

**Files:**
- Create: `crates/hush-core/src/receipt.rs`

**Step 1: Create receipt.rs (simplified from RunReceipt)**

```rust
//! Receipt types and signing
//!
//! Generic receipt structure for attestation, simplified from Glia-specific RunReceipt.

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;

use crate::error::Result;
use crate::signing::{Keypair, PublicKey, Signature, verify_signature};
use crate::hashing::{Hash, sha256, keccak256};

/// Verdict result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verdict {
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scores: Option<JsonValue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
}

impl Default for Verdict {
    fn default() -> Self {
        Self {
            passed: true,
            gate_id: None,
            scores: None,
            threshold: None,
        }
    }
}

/// Violation reference
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ViolationRef {
    pub guard: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

/// Provenance information
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<ViolationRef>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, JsonValue>,
}

/// Generic Receipt (unsigned)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// ISO-8601 timestamp string
    pub timestamp: String,
    /// Content hash (what this receipt attests to)
    pub content_hash: Hash,
    pub verdict: Verdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, JsonValue>,
}

impl Receipt {
    /// Create a new receipt
    pub fn new(content_hash: Hash) -> Self {
        Self {
            version: "1.0.0".to_string(),
            receipt_id: Some(uuid::Uuid::new_v4().to_string()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            content_hash,
            verdict: Verdict::default(),
            provenance: None,
            metadata: HashMap::new(),
        }
    }

    /// Serialize to canonical JSON (sorted keys, no extra whitespace)
    pub fn to_canonical_json(&self) -> Result<String> {
        let value = serde_json::to_value(self)?;
        crate::canonical::canonicalize(&value)
    }

    /// Compute SHA-256 hash of canonical JSON
    pub fn hash_sha256(&self) -> Result<Hash> {
        let canonical = self.to_canonical_json()?;
        Ok(sha256(canonical.as_bytes()))
    }

    /// Compute Keccak-256 hash of canonical JSON (for Ethereum)
    pub fn hash_keccak256(&self) -> Result<Hash> {
        let canonical = self.to_canonical_json()?;
        Ok(keccak256(canonical.as_bytes()))
    }
}

/// Signatures on a receipt
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signatures {
    pub primary: Signature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier: Option<Signature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Signature>,
}

/// Signed Receipt
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedReceipt {
    pub receipt: Receipt,
    pub signatures: Signatures,
}

impl SignedReceipt {
    /// Sign a receipt with the primary keypair
    pub fn sign(receipt: Receipt, keypair: &Keypair) -> Result<Self> {
        let canonical = receipt.to_canonical_json()?;
        let primary_sig = keypair.sign(canonical.as_bytes());

        Ok(Self {
            receipt,
            signatures: Signatures {
                primary: primary_sig,
                verifier: None,
                witness: None,
            },
        })
    }

    /// Add verifier signature
    pub fn add_verifier_signature(&mut self, verifier_keypair: &Keypair) -> Result<()> {
        let canonical = self.receipt.to_canonical_json()?;
        self.signatures.verifier = Some(verifier_keypair.sign(canonical.as_bytes()));
        Ok(())
    }

    /// Add witness signature
    pub fn add_witness_signature(&mut self, witness_keypair: &Keypair) -> Result<()> {
        let canonical = self.receipt.to_canonical_json()?;
        self.signatures.witness = Some(witness_keypair.sign(canonical.as_bytes()));
        Ok(())
    }

    /// Verify all signatures
    pub fn verify(&self, public_keys: &PublicKeySet) -> VerificationResult {
        let canonical = match self.receipt.to_canonical_json() {
            Ok(c) => c,
            Err(e) => {
                return VerificationResult {
                    valid: false,
                    primary_sig_valid: false,
                    verifier_sig_valid: None,
                    witness_sig_valid: None,
                    errors: vec![format!("Failed to serialize receipt: {}", e)],
                };
            }
        };
        let message = canonical.as_bytes();

        let mut result = VerificationResult {
            valid: true,
            primary_sig_valid: false,
            verifier_sig_valid: None,
            witness_sig_valid: None,
            errors: vec![],
        };

        // Verify primary signature (required)
        result.primary_sig_valid = verify_signature(
            &public_keys.primary,
            message,
            &self.signatures.primary,
        );
        if !result.primary_sig_valid {
            result.valid = false;
            result.errors.push("Invalid primary signature".to_string());
        }

        // Verify verifier signature (optional)
        if let (Some(sig), Some(pk)) = (&self.signatures.verifier, &public_keys.verifier) {
            let valid = verify_signature(pk, message, sig);
            result.verifier_sig_valid = Some(valid);
            if !valid {
                result.valid = false;
                result.errors.push("Invalid verifier signature".to_string());
            }
        }

        // Verify witness signature (optional)
        if let (Some(sig), Some(pk)) = (&self.signatures.witness, &public_keys.witness) {
            let valid = verify_signature(pk, message, sig);
            result.witness_sig_valid = Some(valid);
            if !valid {
                result.valid = false;
                result.errors.push("Invalid witness signature".to_string());
            }
        }

        result
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

/// Set of public keys for verification
#[derive(Clone, Debug)]
pub struct PublicKeySet {
    pub primary: PublicKey,
    pub verifier: Option<PublicKey>,
    pub witness: Option<PublicKey>,
}

/// Result of receipt verification
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub primary_sig_valid: bool,
    pub verifier_sig_valid: Option<bool>,
    pub witness_sig_valid: Option<bool>,
    pub errors: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_receipt() -> Receipt {
        Receipt {
            version: "1.0.0".to_string(),
            receipt_id: Some("test-receipt-001".to_string()),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            content_hash: Hash::zero(),
            verdict: Verdict {
                passed: true,
                gate_id: Some("gate-001".to_string()),
                scores: Some(serde_json::json!({"overall": 1.0})),
                threshold: Some(0.7),
            },
            provenance: Some(Provenance {
                policy_hash: Some(Hash::zero()),
                violations: vec![],
                metadata: HashMap::new(),
            }),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_sign_and_verify() {
        let receipt = make_test_receipt();
        let keypair = Keypair::generate();

        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();

        let keys = PublicKeySet {
            primary: keypair.public_key(),
            verifier: None,
            witness: None,
        };

        let result = signed.verify(&keys);
        assert!(result.valid);
        assert!(result.primary_sig_valid);
    }

    #[test]
    fn test_sign_with_verifier() {
        let receipt = make_test_receipt();
        let primary_kp = Keypair::generate();
        let verifier_kp = Keypair::generate();

        let mut signed = SignedReceipt::sign(receipt, &primary_kp).unwrap();
        signed.add_verifier_signature(&verifier_kp).unwrap();

        let keys = PublicKeySet {
            primary: primary_kp.public_key(),
            verifier: Some(verifier_kp.public_key()),
            witness: None,
        };

        let result = signed.verify(&keys);
        assert!(result.valid);
        assert!(result.primary_sig_valid);
        assert_eq!(result.verifier_sig_valid, Some(true));
    }

    #[test]
    fn test_wrong_key_fails() {
        let receipt = make_test_receipt();
        let primary_kp = Keypair::generate();
        let wrong_kp = Keypair::generate();

        let signed = SignedReceipt::sign(receipt, &primary_kp).unwrap();

        let keys = PublicKeySet {
            primary: wrong_kp.public_key(),
            verifier: None,
            witness: None,
        };

        let result = signed.verify(&keys);
        assert!(!result.valid);
        assert!(!result.primary_sig_valid);
        assert!(result.errors.contains(&"Invalid primary signature".to_string()));
    }

    #[test]
    fn test_canonical_json_deterministic() {
        let receipt = make_test_receipt();
        let json1 = receipt.to_canonical_json().unwrap();
        let json2 = receipt.to_canonical_json().unwrap();
        assert_eq!(json1, json2);
    }

    #[test]
    fn test_serialization_roundtrip() {
        let receipt = make_test_receipt();
        let keypair = Keypair::generate();
        let signed = SignedReceipt::sign(receipt, &keypair).unwrap();

        let json = signed.to_json().unwrap();
        let restored = SignedReceipt::from_json(&json).unwrap();

        let keys = PublicKeySet {
            primary: keypair.public_key(),
            verifier: None,
            witness: None,
        };

        let result = restored.verify(&keys);
        assert!(result.valid);
    }
}
```

**Step 2: Add uuid and chrono dependencies to Cargo.toml**

Update `crates/hush-core/Cargo.toml`:

```toml
[dependencies]
# ... existing deps ...
uuid.workspace = true
chrono.workspace = true
```

**Step 3: Verify tests pass**

```bash
cd /Users/connor/Medica/clawdstrike-ws1-oss-repo && cargo test -p hush-core receipt
```

**Step 4: Commit**

```bash
git add crates/hush-core/
git commit -m "feat(hush-core): add Receipt types and signing"
```

---

## Task 9: hush-proxy Crate Setup

**Files:**
- Create: `crates/hush-proxy/Cargo.toml`
- Create: `crates/hush-proxy/src/lib.rs`
- Create: `crates/hush-proxy/src/dns.rs`
- Create: `crates/hush-proxy/src/sni.rs`
- Create: `crates/hush-proxy/src/policy.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "hush-proxy"
description = "Network proxy utilities for clawdstrike"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
serde.workspace = true
chrono.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["rt-multi-thread", "macros"] }
```

**Step 2: Create lib.rs**

```rust
//! Hush Proxy Core
//!
//! Shared utilities for network proxy implementations:
//! - DNS query parsing and NXDOMAIN response generation
//! - TLS SNI extraction from ClientHello
//! - Domain and IP pattern matching for policy enforcement

pub mod dns;
pub mod sni;
pub mod policy;

pub use dns::{build_nxdomain_response, parse_dns_query};
pub use policy::{is_host_allowed, matches_domain};
pub use sni::{extract_sni, is_tls_client_hello};
```

**Step 3: Create dns.rs**

```rust
//! DNS utilities for proxy implementations.

/// Parse a DNS query to extract the queried domain name.
pub fn parse_dns_query(data: &[u8]) -> Option<String> {
    if data.len() < 12 {
        return None;
    }

    let mut pos = 12;
    let mut domain_parts = Vec::new();
    let mut jumps = 0;
    const MAX_JUMPS: u8 = 10;

    while pos < data.len() {
        let len = data[pos] as usize;

        if len == 0 {
            break;
        }

        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= data.len() {
                return None;
            }
            jumps += 1;
            if jumps > MAX_JUMPS {
                return None;
            }
            let offset = ((len & 0x3F) << 8) | (data[pos + 1] as usize);
            if offset >= data.len() {
                return None;
            }
            pos = offset;
            continue;
        }

        if len > 63 || pos + 1 + len > data.len() {
            return None;
        }

        let label = std::str::from_utf8(&data[pos + 1..pos + 1 + len]).ok()?;
        domain_parts.push(label.to_string());
        pos += 1 + len;
    }

    if domain_parts.is_empty() {
        return None;
    }

    Some(domain_parts.join("."))
}

/// Build an NXDOMAIN response for a DNS query.
pub fn build_nxdomain_response(query: &[u8]) -> Vec<u8> {
    let mut response = query.to_vec();

    if response.len() >= 12 {
        response[2] = 0x81;
        response[3] = 0x83;
        response[6] = 0;
        response[7] = 0;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query_example_com() {
        let query = [
            0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00,
        ];

        assert_eq!(parse_dns_query(&query), Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_dns_query_too_short() {
        let short = [0x00, 0x01, 0x02];
        assert_eq!(parse_dns_query(&short), None);
    }

    #[test]
    fn test_build_nxdomain_response_sets_flags() {
        let query = [
            0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, b'f', b'o', b'o', 0x00,
        ];

        let response = build_nxdomain_response(&query);

        assert_eq!(response[2], 0x81);
        assert_eq!(response[3], 0x83);
    }
}
```

**Step 4: Create sni.rs**

```rust
//! TLS SNI (Server Name Indication) extraction utilities.

/// Check if data appears to be a TLS ClientHello message.
pub fn is_tls_client_hello(data: &[u8]) -> bool {
    data.len() > 5
        && data[0] == 0x16
        && data[1] == 0x03
        && data[5] == 0x01
}

/// Extract the SNI hostname from a TLS ClientHello message.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    if data.len() < 43 {
        return None;
    }

    let mut pos = 43;

    if pos >= data.len() {
        return None;
    }
    let session_len = data[pos] as usize;
    pos += 1 + session_len;

    if pos + 2 > data.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    if pos >= data.len() {
        return None;
    }
    let comp_len = data[pos] as usize;
    pos += 1 + comp_len;

    if pos + 2 > data.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;

    while pos + 4 <= ext_end && pos + 4 <= data.len() {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_size = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0 {
            if pos + 5 > data.len() {
                return None;
            }
            pos += 3;

            let name_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
            pos += 2;

            if pos + name_len <= data.len() {
                return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
            }
            return None;
        }

        pos += ext_size;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_tls_client_hello_valid() {
        let tls10 = [0x16, 0x03, 0x01, 0x00, 0x05, 0x01];
        assert!(is_tls_client_hello(&tls10));
    }

    #[test]
    fn test_is_tls_client_hello_http() {
        let http = b"GET / HTTP/1.1\r\n";
        assert!(!is_tls_client_hello(http));
    }

    #[test]
    fn test_extract_sni_too_short() {
        let short = [0x16, 0x03, 0x03, 0x00, 0x05, 0x01, 0x00, 0x00];
        assert_eq!(extract_sni(&short), None);
    }
}
```

**Step 5: Create policy.rs**

```rust
//! Domain and IP pattern matching for policy enforcement.

/// Check if a hostname matches a pattern.
pub fn matches_domain(host: &str, pattern: &str) -> bool {
    let host = host.split(':').next().unwrap_or(host);
    let pattern = pattern.split(':').next().unwrap_or(pattern);

    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.ends_with(&format!(".{}", suffix));
    }

    if pattern.ends_with(".*") {
        let prefix = &pattern[..pattern.len() - 1];
        return host.starts_with(prefix);
    }

    host == pattern
}

/// Check if a host is allowed based on allowed and denied pattern lists.
pub fn is_host_allowed(host: &str, allowed: &[String], denied: &[String]) -> bool {
    let host = host.split(':').next().unwrap_or(host);

    for deny in denied {
        if matches_domain(host, deny) {
            return false;
        }
    }

    if allowed.is_empty() {
        return true;
    }

    for allow in allowed {
        if matches_domain(host, allow) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_domain_exact() {
        assert!(matches_domain("example.com", "example.com"));
        assert!(!matches_domain("example.com", "other.com"));
    }

    #[test]
    fn test_matches_domain_wildcard() {
        assert!(matches_domain("api.github.com", "*.github.com"));
        assert!(!matches_domain("github.com", "*.github.com"));
    }

    #[test]
    fn test_matches_domain_ip_prefix() {
        assert!(matches_domain("10.0.0.1", "10.*"));
        assert!(!matches_domain("192.168.1.1", "10.*"));
    }

    #[test]
    fn test_is_host_allowed_allowlist() {
        let allowed = vec!["*.github.com".to_string(), "api.openai.com".to_string()];
        let denied: Vec<String> = vec![];

        assert!(is_host_allowed("api.github.com", &allowed, &denied));
        assert!(!is_host_allowed("google.com", &allowed, &denied));
    }

    #[test]
    fn test_is_host_allowed_deny_precedence() {
        let allowed = vec!["*.github.com".to_string()];
        let denied = vec!["evil.github.com".to_string()];

        assert!(is_host_allowed("api.github.com", &allowed, &denied));
        assert!(!is_host_allowed("evil.github.com", &allowed, &denied));
    }
}
```

**Step 6: Verify tests pass**

```bash
cd /Users/connor/Medica/clawdstrike-ws1-oss-repo && cargo test -p hush-proxy
```

**Step 7: Commit**

```bash
git add crates/hush-proxy/
git commit -m "feat(hush-proxy): add DNS, SNI, and policy utilities"
```

---

## Task 10: clawdstrike Crate - Core Structure

**Files:**
- Create: `crates/clawdstrike/Cargo.toml`
- Create: `crates/clawdstrike/src/lib.rs`
- Create: `crates/clawdstrike/src/error.rs`
- Create: `crates/clawdstrike/src/policy.rs`
- Create: `crates/clawdstrike/src/event.rs`
- Create: `crates/clawdstrike/src/decision.rs`

**Step 1: Create Cargo.toml**

```toml
[package]
name = "clawdstrike"
description = "Runtime security guards and policy enforcement for AI agents"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[dependencies]
hush-core.workspace = true
hush-proxy.workspace = true

serde.workspace = true
serde_json.workspace = true
serde_yaml.workspace = true
tokio.workspace = true
async-trait.workspace = true
regex.workspace = true
globset.workspace = true
ipnet.workspace = true
thiserror.workspace = true
tracing.workspace = true
chrono.workspace = true
uuid.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["rt-multi-thread", "macros"] }

[features]
default = ["all-guards"]
all-guards = []
```

**Step 2: Create lib.rs**

```rust
//! Clawdstrike - Runtime Security Guards for AI Agents
//!
//! This crate provides security policy enforcement for AI agent runtimes:
//! - Guard framework for modular security checks
//! - Policy loading and evaluation
//! - Event types for filesystem, network, and command operations

pub mod error;
pub mod policy;
pub mod event;
pub mod decision;
pub mod guards;
pub mod engine;

pub use error::{Error, Result, Severity};
pub use policy::{Policy, EgressMode, EgressPolicy, FilesystemPolicy, ExecutionPolicy, ToolPolicy, ViolationAction};
pub use event::{Event, EventType, EventData};
pub use decision::{Decision, GuardResult};
pub use guards::{Guard, GuardRegistry};
pub use engine::HushEngine;
```

**Step 3: Create error.rs**

```rust
//! Error types for clawdstrike

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Policy violation: {guard} - {reason}")]
    PolicyViolation {
        guard: String,
        reason: String,
        severity: Severity,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("Policy error: {0}")]
    Policy(String),
}

/// Severity level for policy violations
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
```

**Step 4: Create policy.rs**

```rust
//! Policy schema and loading

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{Error, Result};

/// Security policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub version: Option<String>,
    pub egress: EgressPolicy,
    pub filesystem: FilesystemPolicy,
    #[serde(default)]
    pub execution: ExecutionPolicy,
    #[serde(default)]
    pub tools: ToolPolicy,
    #[serde(default)]
    pub on_violation: ViolationAction,
}

impl Policy {
    /// Load policy from YAML file
    pub fn from_yaml_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&content)
    }

    /// Load policy from YAML string
    pub fn from_yaml_str(yaml: &str) -> Result<Self> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// Load policy from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: Some("clawdstrike-v1.0".to_string()),
            egress: EgressPolicy::default(),
            filesystem: FilesystemPolicy::default(),
            execution: ExecutionPolicy::default(),
            tools: ToolPolicy::default(),
            on_violation: ViolationAction::Cancel,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressPolicy {
    pub mode: EgressMode,
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    #[serde(default)]
    pub denied_domains: Vec<String>,
}

impl Default for EgressPolicy {
    fn default() -> Self {
        Self {
            mode: EgressMode::Allowlist,
            allowed_domains: vec![
                "api.anthropic.com".to_string(),
                "api.openai.com".to_string(),
                "pypi.org".to_string(),
                "registry.npmjs.org".to_string(),
                "crates.io".to_string(),
                "github.com".to_string(),
                "*.github.com".to_string(),
                "*.githubusercontent.com".to_string(),
            ],
            allowed_cidrs: vec![],
            denied_domains: vec![
                "*.onion".to_string(),
                "localhost".to_string(),
                "127.*".to_string(),
                "10.*".to_string(),
                "192.168.*".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressMode {
    DenyAll,
    #[default]
    Allowlist,
    Open,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub allowed_write_roots: Vec<String>,
    #[serde(default)]
    pub forbidden_paths: Vec<String>,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            allowed_write_roots: vec![
                "/workspace".to_string(),
                "/tmp".to_string(),
            ],
            forbidden_paths: vec![
                "~/.ssh".to_string(),
                "~/.aws".to_string(),
                "~/.gnupg".to_string(),
                "~/.config/gcloud".to_string(),
                "/etc/shadow".to_string(),
                "/etc/passwd".to_string(),
                ".env".to_string(),
                "*.pem".to_string(),
                "*.key".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    #[serde(default)]
    pub allowed_commands: Vec<String>,
    #[serde(default)]
    pub denied_patterns: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolPolicy {
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub denied: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationAction {
    #[default]
    Cancel,
    Warn,
    Isolate,
    Escalate,
}
```

**Step 5: Create event.rs**

```rust
//! Execution event types

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Execution event to be evaluated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub event_id: String,
    pub event_type: EventType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub data: EventData,
}

/// Type of execution event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    FileRead,
    FileWrite,
    CommandExec,
    NetworkEgress,
    ToolCall,
    SecretAccess,
    PatchApply,
}

/// Event-specific data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EventData {
    File(FileEventData),
    Command(CommandEventData),
    Network(NetworkEventData),
    Tool(ToolEventData),
    Patch(PatchEventData),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEventData {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEventData {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkEventData {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolEventData {
    pub tool_name: String,
    #[serde(default)]
    pub parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchEventData {
    pub file_path: String,
    pub patch_content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patch_hash: Option<String>,
}
```

**Step 6: Create decision.rs**

```rust
//! Decision types for policy evaluation

use serde::{Deserialize, Serialize};
use crate::error::Severity;

/// Result of policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Warn {
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        guard: Option<String>,
    },
    Deny {
        reason: String,
        guard: String,
        severity: Severity,
    },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow | Decision::Warn { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }

    pub fn severity(&self) -> Option<Severity> {
        match self {
            Decision::Deny { severity, .. } => Some(*severity),
            _ => None,
        }
    }
}

/// Result of a single guard check
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum GuardResult {
    Allow,
    Deny { reason: String, severity: Severity },
    Warn { message: String },
}

impl GuardResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, GuardResult::Allow | GuardResult::Warn { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, GuardResult::Deny { .. })
    }
}
```

**Step 7: Commit**

```bash
git add crates/clawdstrike/
git commit -m "feat(clawdstrike): add core types - error, policy, event, decision"
```

---

## Task 11: clawdstrike Guards Module

**Files:**
- Create: `crates/clawdstrike/src/guards/mod.rs`
- Create: `crates/clawdstrike/src/guards/forbidden_path.rs`
- Create: `crates/clawdstrike/src/guards/egress.rs`
- Create: `crates/clawdstrike/src/guards/secret_leak.rs`
- Create: `crates/clawdstrike/src/guards/patch_integrity.rs`
- Create: `crates/clawdstrike/src/guards/mcp_tool.rs`

This task is large - see continuing tasks for each guard implementation.

**Step 1: Create guards/mod.rs**

```rust
//! Security guards for policy enforcement

mod forbidden_path;
mod egress;
mod mcp_tool;
mod secret_leak;
mod patch_integrity;

pub use forbidden_path::ForbiddenPathGuard;
pub use egress::EgressAllowlistGuard;
pub use mcp_tool::McpToolGuard;
pub use secret_leak::SecretLeakGuard;
pub use patch_integrity::PatchIntegrityGuard;

use std::sync::Arc;
use async_trait::async_trait;

use crate::event::Event;
use crate::decision::GuardResult;
use crate::policy::Policy;

/// Guard trait for policy enforcement
#[async_trait]
pub trait Guard: Send + Sync {
    /// Guard name for identification
    fn name(&self) -> &str;

    /// Check an execution event against the policy
    async fn check(&self, event: &Event, policy: &Policy) -> GuardResult;

    /// Whether this guard is enabled
    fn is_enabled(&self) -> bool {
        true
    }
}

/// Configuration for which guards to enable
#[derive(Debug, Clone, Default)]
pub struct GuardsConfig {
    pub forbidden_path: bool,
    pub egress_allowlist: bool,
    pub mcp_tool: bool,
    pub secret_leak: bool,
    pub patch_integrity: bool,
}

impl GuardsConfig {
    pub fn all_enabled() -> Self {
        Self {
            forbidden_path: true,
            egress_allowlist: true,
            mcp_tool: true,
            secret_leak: true,
            patch_integrity: true,
        }
    }
}

/// Registry of all guards
pub struct GuardRegistry {
    guards: Vec<Arc<dyn Guard>>,
}

impl GuardRegistry {
    /// Create a new guard registry with the configured guards
    pub fn new(config: &GuardsConfig) -> Self {
        let mut guards: Vec<Arc<dyn Guard>> = Vec::new();

        if config.forbidden_path {
            guards.push(Arc::new(ForbiddenPathGuard::new()));
        }

        if config.egress_allowlist {
            guards.push(Arc::new(EgressAllowlistGuard::new()));
        }

        if config.mcp_tool {
            guards.push(Arc::new(McpToolGuard::new()));
        }

        if config.secret_leak {
            guards.push(Arc::new(SecretLeakGuard::new()));
        }

        if config.patch_integrity {
            guards.push(Arc::new(PatchIntegrityGuard::new()));
        }

        Self { guards }
    }

    /// Create with all guards enabled
    pub fn with_all_guards() -> Self {
        Self::new(&GuardsConfig::all_enabled())
    }

    /// Check an event against all guards
    pub async fn check_all(&self, event: &Event, policy: &Policy) -> Vec<(String, GuardResult)> {
        let mut results = Vec::new();

        for guard in &self.guards {
            if guard.is_enabled() {
                let result = guard.check(event, policy).await;
                results.push((guard.name().to_string(), result));
            }
        }

        results
    }

    /// Check if any guard denies the event
    pub async fn is_allowed(&self, event: &Event, policy: &Policy) -> (bool, Vec<(String, GuardResult)>) {
        let results = self.check_all(event, policy).await;
        let allowed = !results.iter().any(|(_, r)| r.is_denied());
        (allowed, results)
    }

    /// Get list of enabled guards
    pub fn enabled_guards(&self) -> Vec<&str> {
        self.guards.iter()
            .filter(|g| g.is_enabled())
            .map(|g| g.name())
            .collect()
    }
}
```

**Step 2: Commit mod.rs first**

```bash
mkdir -p crates/clawdstrike/src/guards
git add crates/clawdstrike/src/guards/mod.rs
git commit -m "feat(clawdstrike): add Guard trait and GuardRegistry"
```

---

## Task 12: Forbidden Path Guard

**Files:**
- Create: `crates/clawdstrike/src/guards/forbidden_path.rs`

**Step 1: Create forbidden_path.rs**

```rust
//! Forbidden Path Guard
//!
//! Blocks access to sensitive filesystem paths like /etc/shadow, ~/.ssh, etc.

use async_trait::async_trait;
use globset::{Glob, GlobSet, GlobSetBuilder};
use tracing::debug;

use super::Guard;
use crate::event::{Event, EventType, EventData};
use crate::decision::GuardResult;
use crate::policy::Policy;
use crate::error::Severity;

/// Guard that blocks access to forbidden filesystem paths
pub struct ForbiddenPathGuard {
    sensitive_globs: GlobSet,
}

impl ForbiddenPathGuard {
    pub fn new() -> Self {
        let mut builder = GlobSetBuilder::new();

        let patterns = [
            "**/etc/shadow",
            "**/etc/passwd",
            "**/etc/sudoers",
            "**/etc/sudoers.d/**",
            "**/.ssh/**",
            "**/id_rsa",
            "**/id_ed25519",
            "**/.gnupg/**",
            "**/private/**",
            "**/.aws/credentials",
            "**/.azure/**",
            "**/.kube/config",
        ];

        for pattern in patterns {
            if let Ok(glob) = Glob::new(pattern) {
                builder.add(glob);
            }
        }

        Self {
            sensitive_globs: builder.build().unwrap_or_else(|_| GlobSet::empty()),
        }
    }

    fn check_path_string(&self, path: &str, policy: &Policy) -> GuardResult {
        for forbidden in &policy.filesystem.forbidden_paths {
            if path.contains(forbidden) || path.starts_with(forbidden) {
                debug!("Path {} matches forbidden pattern {}", path, forbidden);
                return GuardResult::Deny {
                    reason: format!("Path '{}' is forbidden by policy", path),
                    severity: Severity::High,
                };
            }
        }

        if self.sensitive_globs.is_match(path) {
            return GuardResult::Deny {
                reason: format!("Path '{}' matches sensitive file pattern", path),
                severity: Severity::Critical,
            };
        }

        GuardResult::Allow
    }

    async fn check_path(&self, path: &str, policy: &Policy) -> GuardResult {
        let direct = self.check_path_string(path, policy);
        if direct.is_denied() {
            return direct;
        }

        match tokio::fs::canonicalize(path).await {
            Ok(real) => {
                let real = real.to_string_lossy().to_string();
                let resolved = self.check_path_string(&real, policy);
                if resolved.is_denied() {
                    return GuardResult::Deny {
                        reason: format!(
                            "Path '{}' resolves to forbidden target '{}'",
                            path, real
                        ),
                        severity: Severity::Critical,
                    };
                }
            }
            Err(_) => {}
        }

        GuardResult::Allow
    }
}

impl Default for ForbiddenPathGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for ForbiddenPathGuard {
    fn name(&self) -> &str {
        "forbidden_path"
    }

    async fn check(&self, event: &Event, policy: &Policy) -> GuardResult {
        match (&event.event_type, &event.data) {
            (EventType::FileRead | EventType::FileWrite, EventData::File(data)) => {
                self.check_path(&data.path, policy).await
            }
            (EventType::PatchApply, EventData::Patch(data)) => {
                self.check_path(&data.file_path, policy).await
            }
            _ => GuardResult::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::event::FileEventData;

    fn make_file_event(path: &str, write: bool) -> Event {
        Event {
            event_id: "test-event".to_string(),
            event_type: if write { EventType::FileWrite } else { EventType::FileRead },
            timestamp: Utc::now(),
            session_id: None,
            data: EventData::File(FileEventData {
                path: path.to_string(),
                content_hash: None,
            }),
        }
    }

    #[tokio::test]
    async fn test_allows_normal_paths() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/home/user/code/main.rs", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_blocks_etc_shadow() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/etc/shadow", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }

    #[tokio::test]
    async fn test_blocks_ssh_keys() {
        let guard = ForbiddenPathGuard::new();
        let policy = Policy::default();

        let event = make_file_event("/home/user/.ssh/id_rsa", false);
        let result = guard.check(&event, &policy).await;
        assert!(result.is_denied());
    }
}
```

**Step 2: Commit**

```bash
git add crates/clawdstrike/src/guards/forbidden_path.rs
git commit -m "feat(clawdstrike): add ForbiddenPathGuard"
```

---

## Task 13-16: Remaining Guards

Create the remaining guard files following the same pattern:
- `egress.rs` - EgressAllowlistGuard
- `secret_leak.rs` - SecretLeakGuard
- `patch_integrity.rs` - PatchIntegrityGuard
- `mcp_tool.rs` - McpToolGuard

(See source files in glia-fab for implementation details - adapt to use clawdstrike types)

---

## Task 17: HushEngine

**Files:**
- Create: `crates/clawdstrike/src/engine.rs`

**Step 1: Create engine.rs**

```rust
//! HushEngine - Core evaluation engine

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::Result;
use crate::policy::Policy;
use crate::event::Event;
use crate::decision::Decision;
use crate::guards::{GuardRegistry, GuardsConfig};

/// Core evaluation engine
pub struct HushEngine {
    policy: Arc<RwLock<Policy>>,
    guards: GuardRegistry,
}

impl HushEngine {
    /// Create a new engine with the given policy
    pub fn new(policy: Policy) -> Self {
        Self {
            policy: Arc::new(RwLock::new(policy)),
            guards: GuardRegistry::with_all_guards(),
        }
    }

    /// Create with specific guards enabled
    pub fn with_guards(policy: Policy, config: GuardsConfig) -> Self {
        Self {
            policy: Arc::new(RwLock::new(policy)),
            guards: GuardRegistry::new(&config),
        }
    }

    /// Evaluate an event against the policy
    pub async fn evaluate(&self, event: &Event) -> Decision {
        let policy = self.policy.read().await;
        let (allowed, results) = self.guards.is_allowed(event, &policy).await;

        if allowed {
            // Check for warnings
            for (guard_name, result) in &results {
                if let crate::decision::GuardResult::Warn { message } = result {
                    return Decision::Warn {
                        message: message.clone(),
                        guard: Some(guard_name.clone()),
                    };
                }
            }
            Decision::Allow
        } else {
            // Find the first denial
            for (guard_name, result) in results {
                if let crate::decision::GuardResult::Deny { reason, severity } = result {
                    return Decision::Deny {
                        reason,
                        guard: guard_name,
                        severity,
                    };
                }
            }
            Decision::Allow
        }
    }

    /// Reload policy
    pub async fn reload_policy(&self, new_policy: Policy) -> Result<()> {
        let mut policy = self.policy.write().await;
        *policy = new_policy;
        Ok(())
    }

    /// Get current policy
    pub async fn current_policy(&self) -> Policy {
        self.policy.read().await.clone()
    }

    /// Get list of enabled guards
    pub fn enabled_guards(&self) -> Vec<&str> {
        self.guards.enabled_guards()
    }
}
```

**Step 2: Commit**

```bash
git add crates/clawdstrike/src/engine.rs
git commit -m "feat(clawdstrike): add HushEngine evaluation core"
```

---

## Task 18: Default Rulesets

**Files:**
- Create: `rulesets/default/ruleset.yaml`
- Create: `rulesets/default/README.md`
- Create: `rulesets/strict/ruleset.yaml`
- Create: `rulesets/ai-agent/ruleset.yaml`
- Create: `rulesets/cicd/ruleset.yaml`

**Step 1: Create default ruleset**

```yaml
# clawdstrike default ruleset
version: "clawdstrike-v1.0"

egress:
  mode: allowlist
  allowed_domains:
    # AI providers
    - "api.anthropic.com"
    - "api.openai.com"
    # Package registries
    - "pypi.org"
    - "registry.npmjs.org"
    - "crates.io"
    # Source control
    - "*.github.com"
    - "*.githubusercontent.com"
  denied_domains:
    - "*.onion"
    - "localhost"
    - "127.*"
    - "10.*"
    - "192.168.*"

filesystem:
  allowed_write_roots:
    - "/workspace"
    - "/tmp"
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - "~/.gnupg"
    - "/etc/shadow"
    - "/etc/passwd"
    - ".env"
    - "*.pem"
    - "*.key"

on_violation: cancel
```

**Step 2: Commit**

```bash
git add rulesets/
git commit -m "feat: add default rulesets (default, strict, ai-agent, cicd)"
```

---

## Task 19: hush-cli Crate

**Files:**
- Create: `crates/hush-cli/Cargo.toml`
- Create: `crates/hush-cli/src/main.rs`

**Step 1: Create minimal CLI**

```toml
[package]
name = "hush-cli"
description = "Clawdstrike command-line interface"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[[bin]]
name = "hush"
path = "src/main.rs"

[dependencies]
hush-core.workspace = true
clawdstrike.workspace = true

clap.workspace = true
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
serde_json.workspace = true
```

```rust
//! Hush CLI - Command-line interface for clawdstrike

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "hush")]
#[command(about = "Clawdstrike security policy enforcement CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a policy file
    Validate {
        /// Path to policy file
        #[arg(short, long)]
        policy: PathBuf,
    },
    /// Show policy summary
    Show {
        /// Path to policy file
        #[arg(short, long)]
        policy: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Validate { policy } => {
            let policy = clawdstrike::Policy::from_yaml_file(&policy)?;
            println!("Policy is valid: {:?}", policy.version);
        }
        Commands::Show { policy } => {
            let policy = clawdstrike::Policy::from_yaml_file(&policy)?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
        }
    }

    Ok(())
}
```

**Step 2: Commit**

```bash
git add crates/hush-cli/
git commit -m "feat(hush-cli): add basic CLI with validate and show commands"
```

---

## Task 20: hushd Daemon Crate

**Files:**
- Create: `crates/hushd/Cargo.toml`
- Create: `crates/hushd/src/main.rs`

**Step 1: Create minimal daemon**

```toml
[package]
name = "hushd"
description = "Clawdstrike daemon for runtime enforcement"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[[bin]]
name = "hushd"
path = "src/main.rs"

[dependencies]
hush-core.workspace = true
clawdstrike.workspace = true

clap.workspace = true
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
```

```rust
//! Hushd - Clawdstrike security daemon

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "hushd")]
#[command(about = "Clawdstrike security enforcement daemon")]
struct Args {
    /// Path to policy file
    #[arg(short, long, default_value = "/etc/clawdstrike/policy.yaml")]
    policy: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(&args.log_level)
        .init();

    tracing::info!("Starting hushd with policy: {:?}", args.policy);

    let policy = if args.policy.exists() {
        clawdstrike::Policy::from_yaml_file(&args.policy)?
    } else {
        tracing::warn!("Policy file not found, using defaults");
        clawdstrike::Policy::default()
    };

    let engine = clawdstrike::HushEngine::new(policy);
    tracing::info!("Engine initialized with guards: {:?}", engine.enabled_guards());

    // TODO: Start gRPC/HTTP server for enforcement requests
    tracing::info!("Daemon ready (server not yet implemented)");

    // Keep running
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down");

    Ok(())
}
```

**Step 2: Commit**

```bash
git add crates/hushd/
git commit -m "feat(hushd): add minimal daemon skeleton"
```

---

## Task 21: CI/CD Workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Step 1: Create CI workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  check:
    name: Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --all-targets

  fmt:
    name: Format
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --all -- --check

  clippy:
    name: Clippy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo clippy --all-targets -- -D warnings

  test:
    name: Test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --all

  audit:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v1.4.1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

**Step 2: Commit**

```bash
git add .github/
git commit -m "ci: add GitHub Actions workflow for CI"
```

---

## Task 22: Documentation Files

**Files:**
- Update: `README.md`
- Create: `CONTRIBUTING.md`
- Create: `SECURITY.md`

**Step 1: Update README.md**

```markdown
# clawdstrike

Runtime security guards and policy enforcement for AI agents.

## Overview

Clawdstrike provides a modular security framework for AI agent runtimes:

- **Filesystem Protection**: Block access to sensitive paths (~/.ssh, ~/.aws, etc.)
- **Network Egress Control**: Allowlist/denylist for outbound connections
- **Secret Detection**: Prevent leaking API keys and credentials
- **Patch Integrity**: Block dangerous patterns in code modifications
- **Tool Control**: Allowlist/denylist for MCP tools and commands

## Quick Start

```bash
# Install CLI
cargo install hush-cli

# Validate a policy
hush validate --policy policy.yaml

# Run daemon
hushd --policy /etc/clawdstrike/policy.yaml
```

## Crates

| Crate | Description |
|-------|-------------|
| `hush-core` | Cryptographic primitives (Ed25519, SHA-256, Merkle trees) |
| `hush-proxy` | Network proxy utilities (DNS, SNI, policy matching) |
| `clawdstrike` | Runtime guards and policy engine |
| `hush-cli` | Command-line interface |
| `hushd` | Daemon for runtime enforcement |

## Policy Example

```yaml
version: "clawdstrike-v1.0"

egress:
  mode: allowlist
  allowed_domains:
    - "api.anthropic.com"
    - "api.openai.com"
    - "*.github.com"

filesystem:
  forbidden_paths:
    - "~/.ssh"
    - "~/.aws"
    - ".env"

on_violation: cancel
```

## License

MIT
```

**Step 2: Commit**

```bash
git add README.md CONTRIBUTING.md SECURITY.md
git commit -m "docs: add README, CONTRIBUTING, and SECURITY"
```

---

## Task 23: Final Build and Test

**Step 1: Run full build**

```bash
cd /Users/connor/Medica/clawdstrike-ws1-oss-repo
cargo build --all
```

**Step 2: Run all tests**

```bash
cargo test --all
```

**Step 3: Run clippy**

```bash
cargo clippy --all-targets -- -D warnings
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final cleanup and verification"
```

---

## Summary

This plan creates a complete clawdstrike OSS workspace with:

1. **hush-core**: Crypto primitives (signing, hashing, merkle, canonical JSON, receipts)
2. **hush-proxy**: Network utilities (DNS, SNI, policy matching)
3. **clawdstrike**: Guards + policy engine (5 guards, HushEngine)
4. **hush-cli**: Command-line tool
5. **hushd**: Daemon skeleton
6. **rulesets/**: Default policy templates
7. **CI/CD**: GitHub Actions workflow

Total estimated time: 4-6 hours of focused implementation.
