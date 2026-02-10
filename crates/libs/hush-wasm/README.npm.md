# @clawdstrike/wasm

WebAssembly distribution for Clawdstrike cryptographic verification.

## Install

```bash
npm install @clawdstrike/wasm
```

## Usage

```ts
import init, { verify_ed25519, hash_sha256 } from '@clawdstrike/wasm';

await init();
const hash = hash_sha256(new TextEncoder().encode('hello'));
const valid = verify_ed25519(publicKeyHex, messageBytes, signatureHex);
```

## Exports

- Hashing: `hash_sha256`, `hash_sha256_prefixed`, `hash_keccak256`
- Signatures: `verify_ed25519`
- Receipts: `verify_receipt`, `hash_receipt`, `get_canonical_json`
- Merkle: `verify_merkle_proof`, `compute_merkle_root`, `generate_merkle_proof`

TypeScript declarations are bundled.
