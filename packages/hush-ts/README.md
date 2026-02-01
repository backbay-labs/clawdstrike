# @hushclaw/sdk

TypeScript SDK for hushclaw security verification.

## Installation

```bash
npm install @hushclaw/sdk
```

## Features

- **Cryptographic primitives**: SHA-256, Keccak-256, Ed25519 signatures
- **RFC 8785 Canonical JSON**: Deterministic JSON for hashing/signing
- **RFC 6962 Merkle Trees**: Certificate Transparency compatible
- **Receipt verification**: Sign and verify execution receipts
- **Security guards**: ForbiddenPath, EgressAllowlist, SecretLeak

## Usage

### Hashing

```typescript
import { sha256, keccak256, toHex } from "@hushclaw/sdk";

const hash = sha256("hello world");
console.log(toHex(hash));
```

### Signatures

```typescript
import { generateKeypair, signMessage, verifySignature } from "@hushclaw/sdk";

const { privateKey, publicKey } = await generateKeypair();
const message = new TextEncoder().encode("hello");
const signature = await signMessage(message, privateKey);
const isValid = await verifySignature(message, signature, publicKey);
```

### Canonical JSON

```typescript
import { canonicalize, canonicalHash } from "@hushclaw/sdk";

const obj = { z: 1, a: 2 };
const json = canonicalize(obj); // '{"a":2,"z":1}'
const hash = canonicalHash(obj); // SHA-256 of canonical JSON
```

### Merkle Trees

```typescript
import { MerkleTree, hashLeaf, toHex } from "@hushclaw/sdk";

const leaves = ["a", "b", "c"].map((s) =>
  hashLeaf(new TextEncoder().encode(s))
);
const tree = MerkleTree.fromHashes(leaves);

console.log("Root:", toHex(tree.root));

const proof = tree.inclusionProof(1);
console.log("Valid:", proof.verify(leaves[1], tree.root));
```

### Receipts

```typescript
import { Receipt, SignedReceipt, generateKeypair } from "@hushclaw/sdk";

const receipt = new Receipt({
  id: "run-123",
  artifactRoot: "0xabc...",
  eventCount: 42,
});

const { privateKey, publicKey } = await generateKeypair();
const signed = await SignedReceipt.sign(receipt, privateKey, publicKey);
const isValid = await signed.verify();
```

### Guards

```typescript
import {
  ForbiddenPathGuard,
  EgressAllowlistGuard,
  SecretLeakGuard,
  GuardAction,
  GuardContext,
} from "@hushclaw/sdk";

// Block access to sensitive paths
const pathGuard = new ForbiddenPathGuard();
const result = pathGuard.check(
  GuardAction.fileAccess("/home/user/.ssh/id_rsa"),
  new GuardContext()
);
console.log(result.allowed); // false

// Control network egress
const egressGuard = new EgressAllowlistGuard({
  allow: ["api.example.com", "*.trusted.com"],
});

// Detect secret leaks in output
const secretGuard = new SecretLeakGuard({
  secrets: ["API_KEY_12345"],
});
```

## API Reference

### Crypto

- `sha256(data: string | Uint8Array): Uint8Array`
- `keccak256(data: string | Uint8Array): Uint8Array`
- `toHex(bytes: Uint8Array): string`
- `fromHex(hex: string): Uint8Array`
- `generateKeypair(): Promise<Keypair>`
- `signMessage(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>`
- `verifySignature(message, signature, publicKey): Promise<boolean>`

### Canonical JSON

- `canonicalize(obj: JsonValue): string`
- `canonicalHash(obj: JsonValue, algorithm?: "sha256" | "keccak256"): Uint8Array`

### Merkle Tree

- `hashLeaf(data: Uint8Array): Uint8Array`
- `hashNode(left: Uint8Array, right: Uint8Array): Uint8Array`
- `computeRoot(leaves: Uint8Array[]): Uint8Array`
- `generateProof(leaves: Uint8Array[], index: number): MerkleProof`
- `MerkleTree.fromData(data: Uint8Array[]): MerkleTree`
- `MerkleTree.fromHashes(hashes: Uint8Array[]): MerkleTree`
- `MerkleProof.verify(leafHash: Uint8Array, root: Uint8Array): boolean`

### Receipt

- `Receipt`: Verification receipt class
- `SignedReceipt`: Receipt with Ed25519 signature

### Guards

- `ForbiddenPathGuard`: Block access to sensitive paths
- `EgressAllowlistGuard`: Control network egress
- `SecretLeakGuard`: Detect secrets in output

## License

MIT
