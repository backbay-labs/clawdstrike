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
- `generate_merkle_proof(leaf_hashes_json: string, leaf_index: number): string`

## Bundle Size

- Uncompressed: ~268KB
- Gzipped: ~90KB

The WASM binary is automatically loaded when you call `init()`.

## TypeScript

Full TypeScript definitions are included. The `VerificationResult` type:

```typescript
interface VerificationResult {
  valid: boolean;
  signer_valid: boolean;
  cosigner_valid: boolean | null;
  errors: string[];
}
```

## License

MIT
