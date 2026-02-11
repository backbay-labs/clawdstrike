# @clawdstrike/wasm

WebAssembly package for Clawdstrike cryptographic verification primitives.

## Install

```bash
npm install @clawdstrike/wasm
```

## Browser usage

```ts
import init, { hash_sha256, verify_ed25519, verify_receipt } from '@clawdstrike/wasm';

await init();

const hash = hash_sha256(new TextEncoder().encode('hello'));
const isValid = verify_ed25519(publicKeyHex, messageBytes, signatureHex);
const receiptResult = verify_receipt(receiptJson, signerPubkeyHex);
```

## Node.js usage

```ts
import { hash_sha256 } from '@clawdstrike/wasm';

const hash = hash_sha256(Buffer.from('hello'));
```

## API surface

- Hashing: `hash_sha256`, `hash_sha256_prefixed`, `hash_keccak256`
- Signatures: `verify_ed25519`
- Receipts: `verify_receipt`, `hash_receipt`, `get_canonical_json`
- Merkle: `verify_merkle_proof`, `compute_merkle_root`, `generate_merkle_proof`
