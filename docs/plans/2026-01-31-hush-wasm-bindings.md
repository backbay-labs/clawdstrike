# hush-wasm WASM Bindings Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create WebAssembly bindings for hush-core cryptographic primitives to enable browser and Node.js verification of receipts and signatures.

**Architecture:** The hush-wasm crate wraps hush-core functions using wasm-bindgen, exposing Ed25519 signature verification, SHA-256/Keccak-256 hashing, Merkle proof verification, and signed receipt verification. All functions accept/return JavaScript-friendly types (strings, Uint8Array, JsValue). Panic hook provides browser console error messages.

**Tech Stack:** Rust, wasm-bindgen, wasm-pack, js-sys, serde-wasm-bindgen, console_error_panic_hook

---

## Task 1: Create hush-wasm Crate Structure

**Files:**
- Create: `crates/hush-wasm/Cargo.toml`
- Create: `crates/hush-wasm/src/lib.rs` (minimal)
- Modify: `Cargo.toml` (workspace root - add member)

**Step 1: Create Cargo.toml for hush-wasm**

Create `crates/hush-wasm/Cargo.toml`:

```toml
[package]
name = "hush-wasm"
description = "WebAssembly bindings for hush-core cryptographic primitives"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
hush-core = { path = "../hush-core" }

# WASM bindings
wasm-bindgen = "0.2"
js-sys = "0.3"
web-sys = { version = "0.3", features = ["console"] }

# Serialization
serde = { workspace = true }
serde_json = { workspace = true }
serde-wasm-bindgen = "0.6"

# Encoding
hex = { workspace = true }

# Better panic messages in browser
console_error_panic_hook = "0.1"

# Cryptographic randomness in WASM
getrandom = { version = "0.2", features = ["js"] }

[dev-dependencies]
wasm-bindgen-test = "0.3"

[profile.release]
lto = true
opt-level = "z"
```

**Step 2: Create minimal lib.rs**

Create `crates/hush-wasm/src/lib.rs`:

```rust
//! WebAssembly bindings for hush-core cryptographic primitives
//!
//! This crate provides browser and Node.js verification of clawdstrike attestations.
//! It enables trustless verification where users can independently verify
//! that SignedReceipts are validly signed and Merkle proofs are correct.

use wasm_bindgen::prelude::*;

/// Initialize the WASM module (call once at startup)
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Get version information about this WASM module
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
```

**Step 3: Add hush-wasm to workspace**

Add `"crates/hush-wasm"` to workspace members in root `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = [
    "crates/hush-core",
    "crates/hush-proxy",
    "crates/clawdstrike",
    "crates/hush-cli",
    "crates/hushd",
    "crates/hush-wasm",
]
```

**Step 4: Verify it compiles**

Run: `cargo build -p hush-wasm`
Expected: Build succeeds

**Step 5: Commit**

```bash
git add crates/hush-wasm/ Cargo.toml
git commit -m "feat(hush-wasm): scaffold WASM bindings crate"
```

---

## Task 2: Add SHA-256 Hashing Function

**Files:**
- Modify: `crates/hush-wasm/src/lib.rs`
- Create: `crates/hush-wasm/tests/web.rs`

**Step 1: Write the failing WASM test**

Create `crates/hush-wasm/tests/web.rs`:

```rust
//! WASM tests for hush-wasm

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_hash_sha256() {
    let hash = hush_wasm::hash_sha256(b"hello");
    // Known SHA-256 hash of "hello"
    assert_eq!(
        hash,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[wasm_bindgen_test]
fn test_hash_sha256_empty() {
    let hash = hush_wasm::hash_sha256(b"");
    // Known SHA-256 hash of empty string
    assert_eq!(
        hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}
```

**Step 2: Run test to verify it fails**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: FAIL with "cannot find function `hash_sha256`"

**Step 3: Implement hash_sha256**

Add to `crates/hush-wasm/src/lib.rs`:

```rust
use hush_core::sha256;

/// Compute SHA-256 hash of data.
///
/// # Arguments
/// * `data` - The bytes to hash
///
/// # Returns
/// Hex-encoded hash (64 characters, no 0x prefix)
#[wasm_bindgen]
pub fn hash_sha256(data: &[u8]) -> String {
    sha256(data).to_hex()
}

/// Compute SHA-256 hash with 0x prefix.
///
/// # Arguments
/// * `data` - The bytes to hash
///
/// # Returns
/// Hex-encoded hash with 0x prefix (66 characters)
#[wasm_bindgen]
pub fn hash_sha256_prefixed(data: &[u8]) -> String {
    sha256(data).to_hex_prefixed()
}
```

**Step 4: Run test to verify it passes**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hush-wasm/
git commit -m "feat(hush-wasm): add hash_sha256 function"
```

---

## Task 3: Add Keccak-256 Hashing Function

**Files:**
- Modify: `crates/hush-wasm/src/lib.rs`
- Modify: `crates/hush-wasm/tests/web.rs`

**Step 1: Write the failing test**

Add to `crates/hush-wasm/tests/web.rs`:

```rust
#[wasm_bindgen_test]
fn test_hash_keccak256() {
    let hash = hush_wasm::hash_keccak256(b"hello");
    // Known Keccak-256 hash of "hello" with 0x prefix
    assert!(hash.starts_with("0x"));
    assert_eq!(hash.len(), 66);
    assert_eq!(
        hash,
        "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    );
}
```

**Step 2: Run test to verify it fails**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: FAIL with "cannot find function `hash_keccak256`"

**Step 3: Implement hash_keccak256**

Add to `crates/hush-wasm/src/lib.rs`:

```rust
use hush_core::keccak256;

/// Compute Keccak-256 hash of data (Ethereum-compatible).
///
/// # Arguments
/// * `data` - The bytes to hash
///
/// # Returns
/// Hex-encoded hash with 0x prefix (66 characters)
#[wasm_bindgen]
pub fn hash_keccak256(data: &[u8]) -> String {
    keccak256(data).to_hex_prefixed()
}
```

**Step 4: Run test to verify it passes**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hush-wasm/
git commit -m "feat(hush-wasm): add hash_keccak256 function"
```

---

## Task 4: Add Ed25519 Signature Verification

**Files:**
- Modify: `crates/hush-wasm/src/lib.rs`
- Modify: `crates/hush-wasm/tests/web.rs`

**Step 1: Write the failing test**

Add to `crates/hush-wasm/tests/web.rs`:

```rust
#[wasm_bindgen_test]
fn test_verify_ed25519_valid() {
    // Test vector: sign "hello" with a known keypair
    let message = b"hello";

    // Generate deterministic keypair from seed
    let seed = [42u8; 32];
    let keypair = hush_core::Keypair::from_seed(&seed);
    let pubkey_hex = keypair.public_key().to_hex();
    let signature = keypair.sign(message);
    let sig_hex = signature.to_hex();

    let result = hush_wasm::verify_ed25519(&pubkey_hex, message, &sig_hex);
    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[wasm_bindgen_test]
fn test_verify_ed25519_invalid_signature() {
    let message = b"hello";
    let seed = [42u8; 32];
    let keypair = hush_core::Keypair::from_seed(&seed);
    let pubkey_hex = keypair.public_key().to_hex();

    // Wrong signature (all zeros, 64 bytes)
    let bad_sig_hex = "0".repeat(128);

    let result = hush_wasm::verify_ed25519(&pubkey_hex, message, &bad_sig_hex);
    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[wasm_bindgen_test]
fn test_verify_ed25519_invalid_pubkey() {
    let message = b"hello";
    let bad_pubkey = "not-a-valid-hex-key";
    let sig_hex = "0".repeat(128);

    let result = hush_wasm::verify_ed25519(bad_pubkey, message, &sig_hex);
    assert!(result.is_err());
}
```

**Step 2: Run test to verify it fails**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: FAIL with "cannot find function `verify_ed25519`"

**Step 3: Implement verify_ed25519**

Add to `crates/hush-wasm/src/lib.rs`:

```rust
use hush_core::{PublicKey, Signature};

/// Verify an Ed25519 signature over a message.
///
/// # Arguments
/// * `public_key_hex` - Hex-encoded public key (32 bytes, with or without 0x prefix)
/// * `message` - The message bytes that were signed
/// * `signature_hex` - Hex-encoded signature (64 bytes, with or without 0x prefix)
///
/// # Returns
/// `true` if the signature is valid, `false` otherwise
#[wasm_bindgen]
pub fn verify_ed25519(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> Result<bool, JsError> {
    let pubkey = PublicKey::from_hex(public_key_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let sig = Signature::from_hex(signature_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(pubkey.verify(message, &sig))
}
```

**Step 4: Run test to verify it passes**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hush-wasm/
git commit -m "feat(hush-wasm): add verify_ed25519 function"
```

---

## Task 5: Add Merkle Proof Verification

**Files:**
- Modify: `crates/hush-wasm/src/lib.rs`
- Modify: `crates/hush-wasm/tests/web.rs`

**Step 1: Write the failing test**

Add to `crates/hush-wasm/tests/web.rs`:

```rust
#[wasm_bindgen_test]
fn test_verify_merkle_proof() {
    use hush_core::{MerkleTree, merkle::leaf_hash};

    // Build a tree from 4 leaves
    let leaves: Vec<&[u8]> = vec![b"leaf0", b"leaf1", b"leaf2", b"leaf3"];
    let tree = MerkleTree::from_leaves(&leaves).unwrap();
    let root = tree.root();

    // Get proof for leaf1
    let proof = tree.inclusion_proof(1).unwrap();
    let proof_json = serde_json::to_string(&proof).unwrap();

    // Get leaf hash
    let leaf1_hash = leaf_hash(b"leaf1");

    let result = hush_wasm::verify_merkle_proof(
        &leaf1_hash.to_hex(),
        &proof_json,
        &root.to_hex(),
    );

    assert!(result.is_ok());
    assert!(result.unwrap());
}

#[wasm_bindgen_test]
fn test_verify_merkle_proof_wrong_leaf() {
    use hush_core::{MerkleTree, merkle::leaf_hash};

    let leaves: Vec<&[u8]> = vec![b"leaf0", b"leaf1", b"leaf2", b"leaf3"];
    let tree = MerkleTree::from_leaves(&leaves).unwrap();
    let root = tree.root();

    // Get proof for leaf1
    let proof = tree.inclusion_proof(1).unwrap();
    let proof_json = serde_json::to_string(&proof).unwrap();

    // Use wrong leaf hash
    let wrong_hash = leaf_hash(b"wrong-leaf");

    let result = hush_wasm::verify_merkle_proof(
        &wrong_hash.to_hex(),
        &proof_json,
        &root.to_hex(),
    );

    assert!(result.is_ok());
    assert!(!result.unwrap());
}
```

**Step 2: Run test to verify it fails**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: FAIL with "cannot find function `verify_merkle_proof`"

**Step 3: Implement verify_merkle_proof**

Add to `crates/hush-wasm/src/lib.rs`:

```rust
use hush_core::{Hash, MerkleProof};

/// Verify a Merkle inclusion proof.
///
/// # Arguments
/// * `leaf_hash_hex` - Hex-encoded leaf hash (with or without 0x prefix)
/// * `proof_json` - JSON-serialized MerkleProof
/// * `root_hex` - Hex-encoded expected root hash (with or without 0x prefix)
///
/// # Returns
/// `true` if the proof is valid, `false` otherwise
#[wasm_bindgen]
pub fn verify_merkle_proof(
    leaf_hash_hex: &str,
    proof_json: &str,
    root_hex: &str,
) -> Result<bool, JsError> {
    let leaf = Hash::from_hex(leaf_hash_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let root = Hash::from_hex(root_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let proof: MerkleProof = serde_json::from_str(proof_json)
        .map_err(|e| JsError::new(&format!("Invalid proof JSON: {}", e)))?;

    Ok(proof.verify_hash(leaf, &root))
}

/// Compute Merkle root from leaf hashes.
///
/// # Arguments
/// * `leaf_hashes_json` - JSON array of hex-encoded leaf hashes
///
/// # Returns
/// Hex-encoded Merkle root (with 0x prefix)
#[wasm_bindgen]
pub fn compute_merkle_root(leaf_hashes_json: &str) -> Result<String, JsError> {
    let hashes_hex: Vec<String> = serde_json::from_str(leaf_hashes_json)
        .map_err(|e| JsError::new(&format!("Invalid JSON: {}", e)))?;

    let hashes: Vec<Hash> = hashes_hex
        .iter()
        .map(|h| Hash::from_hex(h))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| JsError::new(&e.to_string()))?;

    let tree = hush_core::MerkleTree::from_hashes(hashes)
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(tree.root().to_hex_prefixed())
}
```

**Step 4: Run test to verify it passes**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hush-wasm/
git commit -m "feat(hush-wasm): add Merkle proof verification"
```

---

## Task 6: Add Receipt Verification

**Files:**
- Modify: `crates/hush-wasm/src/lib.rs`
- Modify: `crates/hush-wasm/tests/web.rs`

**Step 1: Write the failing test**

Add to `crates/hush-wasm/tests/web.rs`:

```rust
#[wasm_bindgen_test]
fn test_verify_receipt_valid() {
    use hush_core::{Receipt, SignedReceipt, Verdict, Keypair, Hash};

    // Create a test receipt
    let receipt = Receipt::new(Hash::zero(), Verdict::pass());

    // Sign it
    let keypair = Keypair::generate();
    let signed = SignedReceipt::sign(receipt, &keypair).unwrap();
    let receipt_json = signed.to_json().unwrap();
    let pubkey_hex = keypair.public_key().to_hex();

    let result = hush_wasm::verify_receipt(&receipt_json, &pubkey_hex, None);

    assert!(result.is_ok());
    let verification: serde_json::Value = serde_wasm_bindgen::from_value(result.unwrap()).unwrap();
    assert_eq!(verification["valid"], true);
    assert_eq!(verification["signer_valid"], true);
}

#[wasm_bindgen_test]
fn test_verify_receipt_wrong_key() {
    use hush_core::{Receipt, SignedReceipt, Verdict, Keypair, Hash};

    let receipt = Receipt::new(Hash::zero(), Verdict::pass());
    let signer = Keypair::generate();
    let wrong_key = Keypair::generate();

    let signed = SignedReceipt::sign(receipt, &signer).unwrap();
    let receipt_json = signed.to_json().unwrap();
    let wrong_pubkey_hex = wrong_key.public_key().to_hex();

    let result = hush_wasm::verify_receipt(&receipt_json, &wrong_pubkey_hex, None);

    assert!(result.is_ok());
    let verification: serde_json::Value = serde_wasm_bindgen::from_value(result.unwrap()).unwrap();
    assert_eq!(verification["valid"], false);
    assert_eq!(verification["signer_valid"], false);
}
```

**Step 2: Run test to verify it fails**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: FAIL with "cannot find function `verify_receipt`"

**Step 3: Implement verify_receipt**

Add to `crates/hush-wasm/src/lib.rs`:

```rust
use hush_core::{SignedReceipt, receipt::PublicKeySet};

/// Verify a signed receipt.
///
/// # Arguments
/// * `receipt_json` - JSON-serialized SignedReceipt
/// * `signer_pubkey_hex` - Hex-encoded signer public key
/// * `cosigner_pubkey_hex` - Optional hex-encoded cosigner public key
///
/// # Returns
/// JavaScript object with verification result:
/// ```json
/// {
///   "valid": true,
///   "signer_valid": true,
///   "cosigner_valid": null,
///   "errors": []
/// }
/// ```
#[wasm_bindgen]
pub fn verify_receipt(
    receipt_json: &str,
    signer_pubkey_hex: &str,
    cosigner_pubkey_hex: Option<String>,
) -> Result<JsValue, JsError> {
    let signed: SignedReceipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("Invalid receipt JSON: {}", e)))?;

    let signer_pk = PublicKey::from_hex(signer_pubkey_hex)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let cosigner_pk = match cosigner_pubkey_hex {
        Some(hex) => Some(PublicKey::from_hex(&hex)
            .map_err(|e| JsError::new(&e.to_string()))?),
        None => None,
    };

    let keys = match cosigner_pk {
        Some(pk) => PublicKeySet::new(signer_pk).with_cosigner(pk),
        None => PublicKeySet::new(signer_pk),
    };

    let result = signed.verify(&keys);

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsError::new(&format!("Serialization failed: {}", e)))
}
```

**Step 4: Run test to verify it passes**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hush-wasm/
git commit -m "feat(hush-wasm): add verify_receipt function"
```

---

## Task 7: Add Receipt Hashing and Canonical JSON

**Files:**
- Modify: `crates/hush-wasm/src/lib.rs`
- Modify: `crates/hush-wasm/tests/web.rs`

**Step 1: Write the failing test**

Add to `crates/hush-wasm/tests/web.rs`:

```rust
#[wasm_bindgen_test]
fn test_hash_receipt() {
    use hush_core::{Receipt, Verdict, Hash};

    let receipt = Receipt {
        version: "1.0.0".to_string(),
        receipt_id: Some("test-001".to_string()),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        content_hash: Hash::zero(),
        verdict: Verdict::pass(),
        provenance: None,
        metadata: None,
    };

    let receipt_json = serde_json::to_string(&receipt).unwrap();

    let hash_sha = hush_wasm::hash_receipt(&receipt_json, "sha256");
    assert!(hash_sha.is_ok());
    let hash_sha = hash_sha.unwrap();
    assert!(hash_sha.starts_with("0x"));
    assert_eq!(hash_sha.len(), 66);

    let hash_keccak = hush_wasm::hash_receipt(&receipt_json, "keccak256");
    assert!(hash_keccak.is_ok());
    let hash_keccak = hash_keccak.unwrap();
    assert!(hash_keccak.starts_with("0x"));

    // Different algorithms should produce different hashes
    assert_ne!(hash_sha, hash_keccak);
}

#[wasm_bindgen_test]
fn test_get_canonical_json() {
    use hush_core::{Receipt, Verdict, Hash};

    let receipt = Receipt {
        version: "1.0.0".to_string(),
        receipt_id: Some("test-001".to_string()),
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        content_hash: Hash::zero(),
        verdict: Verdict::pass(),
        provenance: None,
        metadata: None,
    };

    let receipt_json = serde_json::to_string(&receipt).unwrap();

    let canonical = hush_wasm::get_canonical_json(&receipt_json);
    assert!(canonical.is_ok());
    let canonical = canonical.unwrap();

    // Canonical JSON should be deterministic
    let canonical2 = hush_wasm::get_canonical_json(&receipt_json).unwrap();
    assert_eq!(canonical, canonical2);

    // Keys should be sorted - "content_hash" before "version"
    let content_pos = canonical.find("\"content_hash\"").unwrap();
    let version_pos = canonical.find("\"version\"").unwrap();
    assert!(content_pos < version_pos);
}
```

**Step 2: Run test to verify it fails**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: FAIL with "cannot find function `hash_receipt`"

**Step 3: Implement hash_receipt and get_canonical_json**

Add to `crates/hush-wasm/src/lib.rs`:

```rust
use hush_core::Receipt;

/// Hash a Receipt to get its canonical hash.
///
/// # Arguments
/// * `receipt_json` - JSON-serialized Receipt (unsigned)
/// * `algorithm` - "sha256" or "keccak256"
///
/// # Returns
/// Hex-encoded hash with 0x prefix
#[wasm_bindgen]
pub fn hash_receipt(
    receipt_json: &str,
    algorithm: &str,
) -> Result<String, JsError> {
    let receipt: Receipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("Invalid receipt JSON: {}", e)))?;

    let hash = match algorithm {
        "sha256" => receipt.hash_sha256(),
        "keccak256" => receipt.hash_keccak256(),
        _ => return Err(JsError::new("Invalid algorithm: use 'sha256' or 'keccak256'")),
    }.map_err(|e| JsError::new(&e.to_string()))?;

    Ok(hash.to_hex_prefixed())
}

/// Get the canonical JSON representation of a receipt.
/// This is the exact bytes that are signed.
///
/// # Arguments
/// * `receipt_json` - JSON-serialized Receipt
///
/// # Returns
/// Canonical JSON string (sorted keys, no extra whitespace)
#[wasm_bindgen]
pub fn get_canonical_json(receipt_json: &str) -> Result<String, JsError> {
    let receipt: Receipt = serde_json::from_str(receipt_json)
        .map_err(|e| JsError::new(&format!("Invalid receipt JSON: {}", e)))?;

    receipt.to_canonical_json()
        .map_err(|e| JsError::new(&e.to_string()))
}
```

**Step 4: Run test to verify it passes**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/hush-wasm/
git commit -m "feat(hush-wasm): add hash_receipt and get_canonical_json"
```

---

## Task 8: Create Build Script

**Files:**
- Create: `crates/hush-wasm/build.sh`
- Create: `crates/hush-wasm/.gitignore`

**Step 1: Create build script**

Create `crates/hush-wasm/build.sh`:

```bash
#!/bin/bash
set -euo pipefail

# Build for web (browser) target
echo "Building for web target..."
wasm-pack build --target web --out-dir pkg --release

# Build for Node.js target
echo "Building for Node.js target..."
wasm-pack build --target nodejs --out-dir pkg-node --release

# Report bundle sizes
echo ""
echo "Bundle sizes:"
ls -lh pkg/*.wasm 2>/dev/null || true
ls -lh pkg-node/*.wasm 2>/dev/null || true

# Check if under 500KB target
WASM_SIZE=$(stat -f%z pkg/hush_wasm_bg.wasm 2>/dev/null || stat -c%s pkg/hush_wasm_bg.wasm 2>/dev/null)
if [ "$WASM_SIZE" -gt 512000 ]; then
    echo "WARNING: WASM bundle size ($WASM_SIZE bytes) exceeds 500KB target"
else
    echo "WASM bundle size ($WASM_SIZE bytes) is under 500KB target"
fi
```

**Step 2: Create .gitignore**

Create `crates/hush-wasm/.gitignore`:

```
pkg/
pkg-node/
*.wasm
```

**Step 3: Make build script executable and test**

Run: `chmod +x crates/hush-wasm/build.sh && crates/hush-wasm/build.sh`
Expected: Build succeeds, shows bundle sizes

**Step 4: Commit**

```bash
git add crates/hush-wasm/build.sh crates/hush-wasm/.gitignore
git commit -m "feat(hush-wasm): add build script for web and node targets"
```

---

## Task 9: Create npm Package Configuration

**Files:**
- Create: `crates/hush-wasm/package.json`
- Create: `crates/hush-wasm/README.npm.md`

**Step 1: Create package.json**

Create `crates/hush-wasm/package.json`:

```json
{
  "name": "@clawdstrike/wasm",
  "version": "0.1.0",
  "description": "WebAssembly bindings for clawdstrike cryptographic verification",
  "main": "hush_wasm.js",
  "module": "hush_wasm.js",
  "types": "hush_wasm.d.ts",
  "sideEffects": [
    "./snippets/*"
  ],
  "files": [
    "hush_wasm_bg.wasm",
    "hush_wasm.js",
    "hush_wasm.d.ts",
    "hush_wasm_bg.wasm.d.ts"
  ],
  "repository": {
    "type": "git",
    "url": "https://github.com/backbay-labs/clawdstrike"
  },
  "keywords": [
    "wasm",
    "webassembly",
    "crypto",
    "ed25519",
    "sha256",
    "keccak256",
    "merkle",
    "verification",
    "attestation"
  ],
  "author": "Clawdstrike Contributors",
  "license": "MIT",
  "bugs": {
    "url": "https://github.com/backbay-labs/clawdstrike/issues"
  },
  "homepage": "https://clawdstrike.dev"
}
```

**Step 2: Create npm README**

Create `crates/hush-wasm/README.npm.md`:

```markdown
# @clawdstrike/wasm

WebAssembly bindings for clawdstrike cryptographic verification.

## Installation

```bash
npm install @clawdstrike/wasm
```

## Usage

### Browser (ES Modules)

```javascript
import init, {
  verify_ed25519,
  hash_sha256,
  hash_keccak256,
  verify_receipt,
  verify_merkle_proof
} from '@clawdstrike/wasm';

// Initialize WASM module (required once)
await init();

// Hash data
const hash = hash_sha256(new TextEncoder().encode('hello'));
console.log(hash); // 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

// Verify Ed25519 signature
const valid = verify_ed25519(publicKeyHex, messageBytes, signatureHex);

// Verify a signed receipt
const result = verify_receipt(receiptJson, signerPubkeyHex, null);
console.log(result.valid, result.signer_valid);
```

### Node.js

```javascript
const { verify_ed25519, hash_sha256 } = require('@clawdstrike/wasm');

const hash = hash_sha256(Buffer.from('hello'));
```

## API

### Hashing

- `hash_sha256(data: Uint8Array): string` - SHA-256 hash (hex, no prefix)
- `hash_sha256_prefixed(data: Uint8Array): string` - SHA-256 hash (hex, 0x prefix)
- `hash_keccak256(data: Uint8Array): string` - Keccak-256 hash (hex, 0x prefix)

### Signatures

- `verify_ed25519(pubkey_hex: string, message: Uint8Array, sig_hex: string): boolean`

### Receipts

- `verify_receipt(receipt_json: string, signer_pubkey_hex: string, cosigner_pubkey_hex?: string): VerificationResult`
- `hash_receipt(receipt_json: string, algorithm: "sha256" | "keccak256"): string`
- `get_canonical_json(receipt_json: string): string`

### Merkle Trees

- `verify_merkle_proof(leaf_hash_hex: string, proof_json: string, root_hex: string): boolean`
- `compute_merkle_root(leaf_hashes_json: string): string`

## License

MIT
```

**Step 3: Commit**

```bash
git add crates/hush-wasm/package.json crates/hush-wasm/README.npm.md
git commit -m "feat(hush-wasm): add npm package configuration"
```

---

## Task 10: Create TypeScript Type Definitions

**Files:**
- Create: `crates/hush-wasm/hush_wasm.d.ts.template`

**Step 1: Create TypeScript definitions template**

Create `crates/hush-wasm/hush_wasm.d.ts.template`:

```typescript
/* tslint:disable */
/* eslint-disable */
/**
 * Initialize the WASM module (call once at startup).
 * This is called automatically by wasm-pack generated init().
 */
export function init(): void;

/**
 * Get version information about this WASM module.
 */
export function version(): string;

/**
 * Compute SHA-256 hash of data.
 * @param data - The bytes to hash
 * @returns Hex-encoded hash (64 characters, no 0x prefix)
 */
export function hash_sha256(data: Uint8Array): string;

/**
 * Compute SHA-256 hash with 0x prefix.
 * @param data - The bytes to hash
 * @returns Hex-encoded hash with 0x prefix (66 characters)
 */
export function hash_sha256_prefixed(data: Uint8Array): string;

/**
 * Compute Keccak-256 hash of data (Ethereum-compatible).
 * @param data - The bytes to hash
 * @returns Hex-encoded hash with 0x prefix (66 characters)
 */
export function hash_keccak256(data: Uint8Array): string;

/**
 * Verify an Ed25519 signature over a message.
 * @param public_key_hex - Hex-encoded public key (32 bytes, with or without 0x prefix)
 * @param message - The message bytes that were signed
 * @param signature_hex - Hex-encoded signature (64 bytes, with or without 0x prefix)
 * @returns true if the signature is valid, false otherwise
 * @throws Error if public key or signature format is invalid
 */
export function verify_ed25519(
  public_key_hex: string,
  message: Uint8Array,
  signature_hex: string
): boolean;

/**
 * Verify a Merkle inclusion proof.
 * @param leaf_hash_hex - Hex-encoded leaf hash (with or without 0x prefix)
 * @param proof_json - JSON-serialized MerkleProof
 * @param root_hex - Hex-encoded expected root hash (with or without 0x prefix)
 * @returns true if the proof is valid, false otherwise
 * @throws Error if hash format or proof JSON is invalid
 */
export function verify_merkle_proof(
  leaf_hash_hex: string,
  proof_json: string,
  root_hex: string
): boolean;

/**
 * Compute Merkle root from leaf hashes.
 * @param leaf_hashes_json - JSON array of hex-encoded leaf hashes
 * @returns Hex-encoded Merkle root (with 0x prefix)
 * @throws Error if JSON or hash format is invalid
 */
export function compute_merkle_root(leaf_hashes_json: string): string;

/**
 * Verification result from verify_receipt
 */
export interface VerificationResult {
  valid: boolean;
  signer_valid: boolean;
  cosigner_valid: boolean | null;
  errors: string[];
}

/**
 * Verify a signed receipt.
 * @param receipt_json - JSON-serialized SignedReceipt
 * @param signer_pubkey_hex - Hex-encoded signer public key
 * @param cosigner_pubkey_hex - Optional hex-encoded cosigner public key
 * @returns Verification result object
 * @throws Error if JSON or key format is invalid
 */
export function verify_receipt(
  receipt_json: string,
  signer_pubkey_hex: string,
  cosigner_pubkey_hex?: string | null
): VerificationResult;

/**
 * Hash a Receipt to get its canonical hash.
 * @param receipt_json - JSON-serialized Receipt (unsigned)
 * @param algorithm - "sha256" or "keccak256"
 * @returns Hex-encoded hash with 0x prefix
 * @throws Error if JSON is invalid or algorithm is unknown
 */
export function hash_receipt(
  receipt_json: string,
  algorithm: "sha256" | "keccak256"
): string;

/**
 * Get the canonical JSON representation of a receipt.
 * This is the exact bytes that are signed.
 * @param receipt_json - JSON-serialized Receipt
 * @returns Canonical JSON string (sorted keys, no extra whitespace)
 * @throws Error if JSON is invalid
 */
export function get_canonical_json(receipt_json: string): string;

/**
 * Default export: Initialize and return all exports
 */
export default function init(
  input?: RequestInfo | URL | Response | BufferSource | WebAssembly.Module
): Promise<typeof import("./hush_wasm")>;
```

**Step 2: Commit**

```bash
git add crates/hush-wasm/hush_wasm.d.ts.template
git commit -m "docs(hush-wasm): add TypeScript type definitions template"
```

---

## Task 11: Final Integration Test and Verification

**Files:**
- Modify: `crates/hush-wasm/tests/web.rs` (add integration test)

**Step 1: Add comprehensive integration test**

Add to `crates/hush-wasm/tests/web.rs`:

```rust
#[wasm_bindgen_test]
fn test_full_attestation_workflow() {
    use hush_core::{Receipt, SignedReceipt, Verdict, Keypair, MerkleTree, merkle::leaf_hash};

    // 1. Create content to attest
    let content = b"important task output";
    let content_hash = hush_core::sha256(content);

    // 2. Create leaves for merkle tree (simulating multiple outputs)
    let leaves: Vec<&[u8]> = vec![content, b"metadata", b"logs"];
    let tree = MerkleTree::from_leaves(&leaves).unwrap();
    let merkle_root = tree.root();

    // 3. Create receipt
    let receipt = Receipt::new(merkle_root, Verdict::pass());

    // 4. Sign receipt
    let signer = Keypair::generate();
    let signed = SignedReceipt::sign(receipt, &signer).unwrap();

    // 5. Serialize for transmission
    let receipt_json = signed.to_json().unwrap();
    let proof = tree.inclusion_proof(0).unwrap();
    let proof_json = serde_json::to_string(&proof).unwrap();

    // === Browser-side verification ===

    // 6. Verify receipt signature
    let verify_result = hush_wasm::verify_receipt(
        &receipt_json,
        &signer.public_key().to_hex(),
        None,
    ).unwrap();
    let verification: serde_json::Value = serde_wasm_bindgen::from_value(verify_result).unwrap();
    assert_eq!(verification["valid"], true);

    // 7. Verify content is in merkle tree
    let content_leaf_hash = leaf_hash(content);
    let proof_valid = hush_wasm::verify_merkle_proof(
        &content_leaf_hash.to_hex(),
        &proof_json,
        &merkle_root.to_hex(),
    ).unwrap();
    assert!(proof_valid);

    // 8. Verify content hash matches what we expect
    let computed_hash = hush_wasm::hash_sha256(content);
    assert_eq!(computed_hash, content_hash.to_hex());
}

#[wasm_bindgen_test]
fn test_version() {
    let v = hush_wasm::version();
    assert!(!v.is_empty());
    assert!(v.contains('.'));
}
```

**Step 2: Run all WASM tests**

Run: `wasm-pack test --headless --chrome crates/hush-wasm`
Expected: All tests PASS

**Step 3: Build and check bundle size**

Run: `crates/hush-wasm/build.sh`
Expected: Build succeeds, bundle < 500KB

**Step 4: Commit**

```bash
git add crates/hush-wasm/
git commit -m "test(hush-wasm): add full attestation workflow integration test"
```

---

## Task 12: Final Cleanup and Documentation

**Files:**
- Modify: `crates/hush-wasm/src/lib.rs` (organize imports)
- Update: `README.md` (add hush-wasm to crates table)

**Step 1: Organize lib.rs imports and exports**

Ensure `crates/hush-wasm/src/lib.rs` has clean organization:

```rust
//! WebAssembly bindings for hush-core cryptographic primitives
//!
//! This crate provides browser and Node.js verification of clawdstrike attestations.
//! It enables trustless verification where users can independently verify
//! that SignedReceipts are validly signed and Merkle proofs are correct.
//!
//! ## Usage (JavaScript/TypeScript)
//!
//! ```javascript
//! import init, { verify_ed25519, hash_sha256, verify_receipt } from '@clawdstrike/wasm';
//!
//! await init();
//!
//! // Verify a signature
//! const valid = verify_ed25519(publicKeyHex, message, signatureHex);
//!
//! // Hash data
//! const hash = hash_sha256(new Uint8Array([1, 2, 3]));
//!
//! // Verify a signed receipt
//! const result = verify_receipt(receiptJson, signerPubkeyHex, null);
//! console.log(result.valid);
//! ```

use wasm_bindgen::prelude::*;
use hush_core::{
    sha256, keccak256,
    Hash, PublicKey, Signature,
    Receipt, SignedReceipt,
    MerkleProof, MerkleTree,
    receipt::PublicKeySet,
};

// ... rest of implementations ...
```

**Step 2: Update root README**

Add hush-wasm to the crates table in `/Users/connor/Medica/clawdstrike-ws6-wasm/README.md`:

```markdown
| Crate | Description |
|-------|-------------|
| `hush-core` | Cryptographic primitives (Ed25519, SHA-256, Keccak-256, Merkle trees, receipts) |
| `hush-proxy` | Network proxy utilities (DNS/SNI extraction, domain policy) |
| `hush-wasm` | WebAssembly bindings for browser/Node.js verification |
| `clawdstrike` | Security guards and policy engine |
| `hush-cli` | Command-line interface |
| `hushd` | Security daemon (WIP) |
```

**Step 3: Final verification**

Run:
```bash
cargo fmt --all
cargo clippy -p hush-wasm -- -D warnings
wasm-pack test --headless --chrome crates/hush-wasm
crates/hush-wasm/build.sh
```
Expected: All pass, bundle < 500KB

**Step 4: Commit**

```bash
git add .
git commit -m "docs(hush-wasm): finalize documentation and organization"
```

---

## Summary

After completing all 12 tasks, the hush-wasm crate will provide:

| Function | Description |
|----------|-------------|
| `hash_sha256` | SHA-256 hash (hex) |
| `hash_sha256_prefixed` | SHA-256 hash (0x-prefixed hex) |
| `hash_keccak256` | Keccak-256 hash (0x-prefixed hex) |
| `verify_ed25519` | Ed25519 signature verification |
| `verify_merkle_proof` | Merkle inclusion proof verification |
| `compute_merkle_root` | Compute Merkle root from leaves |
| `verify_receipt` | SignedReceipt verification |
| `hash_receipt` | Hash a Receipt (SHA-256 or Keccak-256) |
| `get_canonical_json` | Get canonical JSON for signing |
| `version` | Get WASM module version |

**Acceptance Criteria:**
- [x] `wasm-pack build` succeeds
- [x] WASM tests pass in browser (wasm-bindgen-test)
- [x] TypeScript types are correct
- [x] Bundle size < 500KB
- [x] Works in both browser and Node.js
