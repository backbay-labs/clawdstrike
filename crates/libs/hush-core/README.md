# hush-core

Core cryptographic primitives for the Clawdstrike attestation system.

## Features

- **Ed25519** -- Key generation, signing, and verification
- **SHA-256** -- Standard cryptographic hashing
- **Keccak-256** -- Ethereum-compatible hashing
- **Merkle trees** -- RFC 6962-compatible construction and inclusion proof verification
- **Canonical JSON** -- RFC 8785 deterministic serialization for hashing and signing
- **Receipts** -- Signed attestation types (`Receipt`, `SignedReceipt`, `Verdict`, `Provenance`)
- **TPM support** -- Sealed seed signing via platform TPM (non-WASM targets)

## Quick Start

```rust
use hush_core::{sha256, keccak256, Keypair};

// Hash some data
let hash = sha256(b"hello world");
assert_eq!(hash.as_bytes().len(), 32);

// Keccak-256 (Ethereum-compatible)
let eth_hash = keccak256(b"hello world");
assert_eq!(eth_hash.as_bytes().len(), 32);

// Sign and verify
let keypair = Keypair::generate();
let message = b"important message";
let signature = keypair.sign(message);
assert!(keypair.public_key().verify(message, &signature));
```

## Merkle Trees

```rust
use hush_core::MerkleTree;

let leaves = vec![b"leaf1".to_vec(), b"leaf2".to_vec(), b"leaf3".to_vec()];
let tree = MerkleTree::from_leaves(&leaves).unwrap();

// Generate and verify inclusion proof
let proof = tree.inclusion_proof(1).unwrap();
assert!(proof.verify(&leaves[1], &tree.root()));
```

## Cargo Features

- `default` -- Core crypto primitives
- `wasm` -- WebAssembly target support (uses `getrandom` JS backend)

## License

Apache-2.0
