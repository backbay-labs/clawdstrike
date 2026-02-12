# @clawdstrike/wasm

WebAssembly bindings for clawdstrike cryptographic verification.

## Installation

```bash
npm install @clawdstrike/wasm
```

## Usage (Browser)

```javascript
import init, {
  hash_sha256,
  hash_keccak256,
  verify_ed25519,
  verify_receipt,
  verify_merkle_proof,
  compute_merkle_root,
  generate_merkle_proof,
  get_canonical_json,
  version
} from '@clawdstrike/wasm';

// Initialize WASM module
await init();

// Hash data
const sha256Hash = hash_sha256(new TextEncoder().encode('hello'));
console.log('SHA-256:', sha256Hash);

const keccakHash = hash_keccak256(new TextEncoder().encode('hello'));
console.log('Keccak-256:', keccakHash);

// Verify Ed25519 signature
const valid = verify_ed25519(publicKeyHex, message, signatureHex);
console.log('Signature valid:', valid);

// Verify a signed receipt
const result = verify_receipt(receiptJson, signerPubkeyHex);
console.log('Receipt verification:', result);

// Merkle tree operations
const root = compute_merkle_root(JSON.stringify(leafHashes));
const proof = generate_merkle_proof(JSON.stringify(leafHashes), 0);
const proofValid = verify_merkle_proof(leafHash, proof, root);
```

## Usage (Node.js)

```javascript
const {
  hash_sha256,
  verify_ed25519,
  verify_receipt
} = require('@clawdstrike/wasm');

// Functions work synchronously in Node.js
const hash = hash_sha256(Buffer.from('hello'));
```

## API

### Hashing

- `hash_sha256(data: Uint8Array): string` - SHA-256 hash (hex, no prefix)
- `hash_sha256_prefixed(data: Uint8Array): string` - SHA-256 hash (0x-prefixed hex)
- `hash_keccak256(data: Uint8Array): string` - Keccak-256 hash (0x-prefixed hex)

### Signatures

- `verify_ed25519(publicKeyHex: string, message: Uint8Array, signatureHex: string): boolean`

### Receipts

- `verify_receipt(receiptJson: string, signerPubkeyHex: string, cosignerPubkeyHex?: string): VerificationResult`
- `hash_receipt(receiptJson: string, algorithm: 'sha256' | 'keccak256'): string`
- `get_canonical_json(receiptJson: string): string`

### Merkle Trees

- `compute_merkle_root(leafHashesJson: string): string`
- `generate_merkle_proof(leafHashesJson: string, leafIndex: number): string`
- `verify_merkle_proof(leafHashHex: string, proofJson: string, rootHex: string): boolean`

### Utilities

- `version(): string` - Get WASM module version

## Building from Source

```bash
# Install wasm-pack
cargo install wasm-pack

# Build for web
./build.sh

# Or build manually
wasm-pack build --target web --out-dir pkg
```

## License

MIT
