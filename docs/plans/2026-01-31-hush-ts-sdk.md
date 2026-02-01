# @hushclaw/sdk TypeScript Package Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a TypeScript SDK (`@hushclaw/sdk`) that provides verification utilities matching the Python SDK capabilities, including receipt verification, RFC 6962 Merkle trees, RFC 8785 canonical JSON, and security guards.

**Architecture:** Pure TypeScript implementation using @noble/hashes for SHA-256/Keccak-256 and @noble/ed25519 for Ed25519 signatures. The SDK mirrors the Python SDK's API surface with TypeScript idioms (classes, interfaces, union types). All cryptographic operations are deterministic and compatible with the Rust implementation.

**Tech Stack:** TypeScript 5.x, @noble/hashes ^1.3.0, @noble/ed25519 ^2.0.0, tsup ^8.0.0 (build), vitest ^1.0.0 (tests)

---

## Task 1: Package Scaffold

**Files:**
- Create: `packages/hush-ts/package.json`
- Create: `packages/hush-ts/tsconfig.json`
- Create: `packages/hush-ts/tsup.config.ts`
- Create: `packages/hush-ts/vitest.config.ts`
- Create: `packages/hush-ts/src/index.ts`

**Step 1: Create package.json**

```json
{
  "name": "@hushclaw/sdk",
  "version": "0.1.0",
  "description": "TypeScript SDK for hushclaw security verification",
  "type": "module",
  "main": "./dist/index.cjs",
  "module": "./dist/index.js",
  "types": "./dist/index.d.ts",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "require": "./dist/index.cjs",
      "types": "./dist/index.d.ts"
    }
  },
  "files": [
    "dist",
    "README.md"
  ],
  "scripts": {
    "build": "tsup",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "lint": "eslint src --ext .ts",
    "clean": "rm -rf dist"
  },
  "keywords": [
    "hushclaw",
    "security",
    "verification",
    "merkle",
    "ed25519",
    "receipts"
  ],
  "author": "Hushclaw Contributors",
  "license": "MIT",
  "repository": {
    "type": "git",
    "url": "https://github.com/hushclaw/hushclaw.git",
    "directory": "packages/hush-ts"
  },
  "dependencies": {
    "@noble/ed25519": "^2.0.0",
    "@noble/hashes": "^1.3.0"
  },
  "devDependencies": {
    "@types/node": "^20.10.0",
    "tsup": "^8.0.0",
    "typescript": "^5.3.0",
    "vitest": "^1.0.0"
  },
  "engines": {
    "node": ">=18"
  }
}
```

**Step 2: Create tsconfig.json**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "lib": ["ES2022"],
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "declaration": true,
    "declarationMap": true,
    "sourceMap": true,
    "outDir": "./dist",
    "rootDir": "./src",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "tests"]
}
```

**Step 3: Create tsup.config.ts**

```typescript
import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  minify: false,
});
```

**Step 4: Create vitest.config.ts**

```typescript
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
    },
  },
});
```

**Step 5: Create placeholder src/index.ts**

```typescript
/**
 * @hushclaw/sdk - TypeScript SDK for hushclaw security verification
 * @packageDocumentation
 */

export const VERSION = "0.1.0";
```

**Step 6: Install dependencies and verify build**

Run: `cd packages/hush-ts && npm install && npm run build`
Expected: Build succeeds, dist/ contains index.js, index.cjs, index.d.ts

**Step 7: Commit**

```bash
git add packages/hush-ts/
git commit -m "feat(hush-ts): scaffold @hushclaw/sdk package"
```

---

## Task 2: Crypto Module - Hash Functions

**Files:**
- Create: `packages/hush-ts/src/crypto/hash.ts`
- Create: `packages/hush-ts/tests/crypto/hash.test.ts`

**Step 1: Write failing tests for hash functions**

```typescript
// tests/crypto/hash.test.ts
import { describe, it, expect } from "vitest";
import { sha256, keccak256, toHex, fromHex } from "../src/crypto/hash";

describe("sha256", () => {
  it("hashes string input", () => {
    const result = sha256("hello");
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(32);
  });

  it("hashes Uint8Array input", () => {
    const input = new TextEncoder().encode("hello");
    const result = sha256(input);
    expect(result.length).toBe(32);
  });

  it("produces known hash for empty string", () => {
    // SHA-256("") = e3b0c442...
    const result = sha256("");
    const hex = toHex(result);
    expect(hex).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });

  it("produces known hash for 'hello'", () => {
    const result = sha256("hello");
    const hex = toHex(result);
    expect(hex).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
  });
});

describe("keccak256", () => {
  it("hashes string input", () => {
    const result = keccak256("hello");
    expect(result).toBeInstanceOf(Uint8Array);
    expect(result.length).toBe(32);
  });

  it("produces 32-byte output", () => {
    const result = keccak256("test");
    expect(result.length).toBe(32);
  });
});

describe("toHex/fromHex", () => {
  it("round-trips bytes", () => {
    const bytes = new Uint8Array([0, 127, 255, 1, 2, 3]);
    const hex = toHex(bytes);
    const restored = fromHex(hex);
    expect(restored).toEqual(bytes);
  });

  it("handles 0x prefix", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    const hex = "0x" + toHex(bytes);
    const restored = fromHex(hex);
    expect(restored).toEqual(bytes);
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd packages/hush-ts && npm test`
Expected: FAIL - module not found

**Step 3: Implement hash functions**

```typescript
// src/crypto/hash.ts
import { sha256 as nobleSha256 } from "@noble/hashes/sha256";
import { keccak_256 } from "@noble/hashes/sha3";

/**
 * Compute SHA-256 hash.
 * @param data - Input string or bytes
 * @returns 32-byte hash
 */
export function sha256(data: string | Uint8Array): Uint8Array {
  const input = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return nobleSha256(input);
}

/**
 * Compute Keccak-256 hash (Ethereum-compatible).
 * @param data - Input string or bytes
 * @returns 32-byte hash
 */
export function keccak256(data: string | Uint8Array): Uint8Array {
  const input = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return keccak_256(input);
}

/**
 * Convert bytes to hex string (no 0x prefix).
 */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Convert hex string to bytes (handles optional 0x prefix).
 */
export function fromHex(hex: string): Uint8Array {
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
```

**Step 4: Run tests to verify they pass**

Run: `cd packages/hush-ts && npm test`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-ts/src/crypto/hash.ts packages/hush-ts/tests/crypto/hash.test.ts
git commit -m "feat(hush-ts): add sha256, keccak256 hash functions"
```

---

## Task 3: Crypto Module - Ed25519 Signatures

**Files:**
- Create: `packages/hush-ts/src/crypto/sign.ts`
- Create: `packages/hush-ts/tests/crypto/sign.test.ts`
- Create: `packages/hush-ts/src/crypto/index.ts`

**Step 1: Write failing tests for Ed25519**

```typescript
// tests/crypto/sign.test.ts
import { describe, it, expect } from "vitest";
import { generateKeypair, signMessage, verifySignature } from "../src/crypto/sign";

describe("generateKeypair", () => {
  it("generates 32-byte private key", async () => {
    const { privateKey, publicKey } = await generateKeypair();
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(privateKey.length).toBe(32);
  });

  it("generates 32-byte public key", async () => {
    const { privateKey, publicKey } = await generateKeypair();
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(publicKey.length).toBe(32);
  });

  it("generates unique keys each time", async () => {
    const kp1 = await generateKeypair();
    const kp2 = await generateKeypair();
    expect(kp1.privateKey).not.toEqual(kp2.privateKey);
    expect(kp1.publicKey).not.toEqual(kp2.publicKey);
  });
});

describe("signMessage", () => {
  it("produces 64-byte signature", async () => {
    const { privateKey } = await generateKeypair();
    const message = new TextEncoder().encode("hello");
    const signature = await signMessage(message, privateKey);
    expect(signature).toBeInstanceOf(Uint8Array);
    expect(signature.length).toBe(64);
  });
});

describe("verifySignature", () => {
  it("verifies valid signature", async () => {
    const { privateKey, publicKey } = await generateKeypair();
    const message = new TextEncoder().encode("hello world");
    const signature = await signMessage(message, privateKey);

    const isValid = await verifySignature(message, signature, publicKey);
    expect(isValid).toBe(true);
  });

  it("rejects invalid signature", async () => {
    const { publicKey } = await generateKeypair();
    const message = new TextEncoder().encode("hello");
    const badSignature = new Uint8Array(64); // All zeros

    const isValid = await verifySignature(message, badSignature, publicKey);
    expect(isValid).toBe(false);
  });

  it("rejects tampered message", async () => {
    const { privateKey, publicKey } = await generateKeypair();
    const message = new TextEncoder().encode("original");
    const signature = await signMessage(message, privateKey);

    const tampered = new TextEncoder().encode("tampered");
    const isValid = await verifySignature(tampered, signature, publicKey);
    expect(isValid).toBe(false);
  });

  it("rejects wrong public key", async () => {
    const kp1 = await generateKeypair();
    const kp2 = await generateKeypair();
    const message = new TextEncoder().encode("hello");
    const signature = await signMessage(message, kp1.privateKey);

    const isValid = await verifySignature(message, signature, kp2.publicKey);
    expect(isValid).toBe(false);
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd packages/hush-ts && npm test`
Expected: FAIL - module not found

**Step 3: Implement Ed25519 functions**

```typescript
// src/crypto/sign.ts
import * as ed25519 from "@noble/ed25519";

export interface Keypair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

/**
 * Generate an Ed25519 keypair.
 * @returns Promise resolving to { privateKey, publicKey } (both 32 bytes)
 */
export async function generateKeypair(): Promise<Keypair> {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = await ed25519.getPublicKeyAsync(privateKey);
  return { privateKey, publicKey };
}

/**
 * Sign a message with Ed25519.
 * @param message - Message bytes to sign
 * @param privateKey - 32-byte private key
 * @returns 64-byte signature
 */
export async function signMessage(
  message: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  return ed25519.signAsync(message, privateKey);
}

/**
 * Verify an Ed25519 signature.
 * @param message - Original message bytes
 * @param signature - 64-byte signature
 * @param publicKey - 32-byte public key
 * @returns True if valid, false otherwise
 */
export async function verifySignature(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array
): Promise<boolean> {
  try {
    return await ed25519.verifyAsync(signature, message, publicKey);
  } catch {
    return false;
  }
}
```

**Step 4: Create crypto barrel export**

```typescript
// src/crypto/index.ts
export { sha256, keccak256, toHex, fromHex } from "./hash";
export { generateKeypair, signMessage, verifySignature, type Keypair } from "./sign";
```

**Step 5: Run tests to verify they pass**

Run: `cd packages/hush-ts && npm test`
Expected: PASS

**Step 6: Commit**

```bash
git add packages/hush-ts/src/crypto/ packages/hush-ts/tests/crypto/
git commit -m "feat(hush-ts): add Ed25519 signature functions"
```

---

## Task 4: RFC 8785 Canonical JSON

**Files:**
- Create: `packages/hush-ts/src/canonical.ts`
- Create: `packages/hush-ts/tests/canonical.test.ts`

**Step 1: Write failing tests for canonical JSON**

```typescript
// tests/canonical.test.ts
import { describe, it, expect } from "vitest";
import { canonicalize, canonicalHash } from "../src/canonical";
import { toHex } from "../src/crypto/hash";

describe("canonicalize", () => {
  it("sorts object keys lexicographically", () => {
    const obj = { z: 1, a: 2, m: 3 };
    const result = canonicalize(obj);
    expect(result).toBe('{"a":2,"m":3,"z":1}');
  });

  it("produces no whitespace", () => {
    const obj = { key: "value", list: [1, 2, 3] };
    const result = canonicalize(obj);
    expect(result).not.toContain(" ");
    expect(result).not.toContain("\n");
    expect(result).not.toContain("\t");
  });

  it("sorts nested object keys", () => {
    const obj = { outer: { z: 1, a: 2 }, inner: [3, 2, 1] };
    const result = canonicalize(obj);
    expect(result).toBe('{"inner":[3,2,1],"outer":{"a":2,"z":1}}');
  });

  it("sorts numeric string keys lexicographically", () => {
    const obj = { "2": "b", "10": "a", a: 0 };
    const result = canonicalize(obj);
    // "10" < "2" < "a" lexicographically
    expect(result).toBe('{"10":"a","2":"b","a":0}');
  });

  it("serializes primitives correctly", () => {
    expect(canonicalize(true)).toBe("true");
    expect(canonicalize(false)).toBe("false");
    expect(canonicalize(null)).toBe("null");
    expect(canonicalize("hello")).toBe('"hello"');
    expect(canonicalize(42)).toBe("42");
  });

  it("serializes empty structures", () => {
    expect(canonicalize({})).toBe("{}");
    expect(canonicalize([])).toBe("[]");
  });

  it("escapes control characters", () => {
    const obj = { newline: "\n", tab: "\t", quote: '"' };
    const result = canonicalize(obj);
    expect(result).toContain("\\n");
    expect(result).toContain("\\t");
    expect(result).toContain('\\"');
  });

  it("throws for NaN", () => {
    expect(() => canonicalize({ bad: NaN })).toThrow();
  });

  it("throws for Infinity", () => {
    expect(() => canonicalize({ bad: Infinity })).toThrow();
  });

  it("throws for -Infinity", () => {
    expect(() => canonicalize({ bad: -Infinity })).toThrow();
  });
});

describe("canonicalHash", () => {
  it("produces 32-byte SHA-256 hash", () => {
    const obj = { message: "hello" };
    const result = canonicalHash(obj, "sha256");
    expect(result.length).toBe(32);
  });

  it("produces consistent hash for same object", () => {
    const obj = { a: 1, b: 2 };
    const hash1 = canonicalHash(obj);
    const hash2 = canonicalHash(obj);
    expect(toHex(hash1)).toBe(toHex(hash2));
  });

  it("defaults to SHA-256", () => {
    const obj = { test: true };
    const defaultHash = canonicalHash(obj);
    const explicitHash = canonicalHash(obj, "sha256");
    expect(toHex(defaultHash)).toBe(toHex(explicitHash));
  });

  it("supports keccak256", () => {
    const obj = { test: true };
    const sha = canonicalHash(obj, "sha256");
    const keccak = canonicalHash(obj, "keccak256");
    expect(toHex(sha)).not.toBe(toHex(keccak));
  });

  it("throws for unknown algorithm", () => {
    expect(() => canonicalHash({ x: 1 }, "md5" as any)).toThrow("Unknown algorithm");
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd packages/hush-ts && npm test`
Expected: FAIL - module not found

**Step 3: Implement canonical JSON**

```typescript
// src/canonical.ts
import { sha256, keccak256 } from "./crypto/hash";

type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/**
 * Serialize object to canonical JSON per RFC 8785 (JCS).
 *
 * - No whitespace between elements
 * - Object keys sorted lexicographically
 * - Unicode preserved (except control characters escaped)
 *
 * @param obj - Object to serialize
 * @returns Canonical JSON string
 * @throws If object contains non-finite numbers (NaN, Infinity)
 */
export function canonicalize(obj: JsonValue): string {
  if (obj === null) {
    return "null";
  }

  if (typeof obj === "boolean") {
    return obj ? "true" : "false";
  }

  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) {
      throw new Error("Non-finite numbers are not valid JSON");
    }
    return String(obj);
  }

  if (typeof obj === "string") {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    const items = obj.map((item) => canonicalize(item));
    return "[" + items.join(",") + "]";
  }

  // Object: sort keys lexicographically
  const keys = Object.keys(obj).sort();
  const pairs = keys.map((key) => {
    const value = canonicalize(obj[key]);
    return JSON.stringify(key) + ":" + value;
  });
  return "{" + pairs.join(",") + "}";
}

/**
 * Hash object using canonical JSON serialization.
 *
 * @param obj - Object to serialize and hash
 * @param algorithm - Hash algorithm ("sha256" or "keccak256")
 * @returns 32-byte hash
 * @throws If algorithm is not supported
 */
export function canonicalHash(
  obj: JsonValue,
  algorithm: "sha256" | "keccak256" = "sha256"
): Uint8Array {
  const canonical = canonicalize(obj);
  const bytes = new TextEncoder().encode(canonical);

  switch (algorithm) {
    case "sha256":
      return sha256(bytes);
    case "keccak256":
      return keccak256(bytes);
    default:
      throw new Error(`Unknown algorithm: ${algorithm}`);
  }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd packages/hush-ts && npm test`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-ts/src/canonical.ts packages/hush-ts/tests/canonical.test.ts
git commit -m "feat(hush-ts): add RFC 8785 canonical JSON"
```

---

## Task 5: RFC 6962 Merkle Tree

**Files:**
- Create: `packages/hush-ts/src/merkle.ts`
- Create: `packages/hush-ts/tests/merkle.test.ts`

**Step 1: Write failing tests for Merkle tree**

```typescript
// tests/merkle.test.ts
import { describe, it, expect } from "vitest";
import {
  hashLeaf,
  hashNode,
  computeRoot,
  generateProof,
  MerkleTree,
  MerkleProof,
} from "../src/merkle";
import { toHex } from "../src/crypto/hash";

describe("hashLeaf", () => {
  it("produces 32 bytes", () => {
    const result = hashLeaf(new Uint8Array([1, 2, 3]));
    expect(result.length).toBe(32);
  });

  it("prefixes with 0x00", () => {
    // Leaf hash = SHA256(0x00 || data)
    const result = hashLeaf(new TextEncoder().encode("hello"));
    expect(result.length).toBe(32);
  });
});

describe("hashNode", () => {
  it("produces 32 bytes", () => {
    const left = hashLeaf(new Uint8Array([1]));
    const right = hashLeaf(new Uint8Array([2]));
    const result = hashNode(left, right);
    expect(result.length).toBe(32);
  });

  it("order matters", () => {
    const a = hashLeaf(new Uint8Array([1]));
    const b = hashLeaf(new Uint8Array([2]));
    const ab = hashNode(a, b);
    const ba = hashNode(b, a);
    expect(toHex(ab)).not.toBe(toHex(ba));
  });
});

describe("computeRoot", () => {
  it("single leaf: root equals leaf hash", () => {
    const leaf = hashLeaf(new TextEncoder().encode("single"));
    const root = computeRoot([leaf]);
    expect(toHex(root)).toBe(toHex(leaf));
  });

  it("two leaves: root is hashNode(left, right)", () => {
    const left = hashLeaf(new TextEncoder().encode("left"));
    const right = hashLeaf(new TextEncoder().encode("right"));
    const root = computeRoot([left, right]);
    const expected = hashNode(left, right);
    expect(toHex(root)).toBe(toHex(expected));
  });

  it("throws for empty array", () => {
    expect(() => computeRoot([])).toThrow("empty");
  });

  it("three leaves: last carried upward (not duplicated)", () => {
    const a = hashLeaf(new TextEncoder().encode("a"));
    const b = hashLeaf(new TextEncoder().encode("b"));
    const c = hashLeaf(new TextEncoder().encode("c"));
    const root = computeRoot([a, b, c]);
    // Level 0: [a, b, c]
    // Level 1: [hash(a,b), c] - c carried up
    // Level 2: [hash(hash(a,b), c)]
    const expected = hashNode(hashNode(a, b), c);
    expect(toHex(root)).toBe(toHex(expected));
  });
});

describe("MerkleProof", () => {
  it("verifies valid two-leaf proof (left)", () => {
    const left = hashLeaf(new TextEncoder().encode("left"));
    const right = hashLeaf(new TextEncoder().encode("right"));
    const root = hashNode(left, right);

    const proof = new MerkleProof(2, 0, [right]);
    expect(proof.verify(left, root)).toBe(true);
  });

  it("verifies valid two-leaf proof (right)", () => {
    const left = hashLeaf(new TextEncoder().encode("left"));
    const right = hashLeaf(new TextEncoder().encode("right"));
    const root = hashNode(left, right);

    const proof = new MerkleProof(2, 1, [left]);
    expect(proof.verify(right, root)).toBe(true);
  });

  it("rejects proof with wrong root", () => {
    const left = hashLeaf(new TextEncoder().encode("left"));
    const right = hashLeaf(new TextEncoder().encode("right"));
    const wrongRoot = hashLeaf(new TextEncoder().encode("wrong"));

    const proof = new MerkleProof(2, 0, [right]);
    expect(proof.verify(left, wrongRoot)).toBe(false);
  });
});

describe("generateProof", () => {
  it("generates valid proof for 2-leaf tree", () => {
    const leaves = [
      hashLeaf(new TextEncoder().encode("a")),
      hashLeaf(new TextEncoder().encode("b")),
    ];
    const root = computeRoot(leaves);

    const proof0 = generateProof(leaves, 0);
    const proof1 = generateProof(leaves, 1);

    expect(proof0.verify(leaves[0], root)).toBe(true);
    expect(proof1.verify(leaves[1], root)).toBe(true);
  });

  it("generates valid proofs for 8-leaf tree", () => {
    const leaves = Array.from({ length: 8 }, (_, i) =>
      hashLeaf(new TextEncoder().encode(`leaf${i}`))
    );
    const root = computeRoot(leaves);

    for (let i = 0; i < 8; i++) {
      const proof = generateProof(leaves, i);
      expect(proof.verify(leaves[i], root)).toBe(true);
    }
  });

  it("generates valid proofs for 7-leaf tree (odd count)", () => {
    const leaves = Array.from({ length: 7 }, (_, i) =>
      hashLeaf(new TextEncoder().encode(`leaf${i}`))
    );
    const root = computeRoot(leaves);

    for (let i = 0; i < 7; i++) {
      const proof = generateProof(leaves, i);
      expect(proof.verify(leaves[i], root)).toBe(true);
    }
  });

  it("throws for out-of-range index", () => {
    const leaves = [hashLeaf(new Uint8Array([1])), hashLeaf(new Uint8Array([2]))];
    expect(() => generateProof(leaves, 2)).toThrow("out of range");
    expect(() => generateProof(leaves, -1)).toThrow("out of range");
  });
});

describe("MerkleTree", () => {
  it("builds from raw data", () => {
    const tree = MerkleTree.fromData([
      new TextEncoder().encode("a"),
      new TextEncoder().encode("b"),
      new TextEncoder().encode("c"),
    ]);
    expect(tree.leafCount).toBe(3);
    expect(tree.root.length).toBe(32);
  });

  it("builds from pre-hashed leaves", () => {
    const leaves = [
      hashLeaf(new TextEncoder().encode("a")),
      hashLeaf(new TextEncoder().encode("b")),
    ];
    const tree = MerkleTree.fromHashes(leaves);
    expect(tree.leafCount).toBe(2);
    expect(toHex(tree.root)).toBe(toHex(computeRoot(leaves)));
  });

  it("generates valid inclusion proofs", () => {
    const leaves = Array.from({ length: 10 }, (_, i) =>
      hashLeaf(new TextEncoder().encode(`leaf${i}`))
    );
    const tree = MerkleTree.fromHashes(leaves);

    for (let i = 0; i < 10; i++) {
      const proof = tree.inclusionProof(i);
      expect(proof.verify(leaves[i], tree.root)).toBe(true);
    }
  });

  it("single leaf tree works", () => {
    const leaf = hashLeaf(new TextEncoder().encode("single"));
    const tree = MerkleTree.fromHashes([leaf]);

    expect(tree.leafCount).toBe(1);
    expect(toHex(tree.root)).toBe(toHex(leaf));

    const proof = tree.inclusionProof(0);
    expect(proof.verify(leaf, tree.root)).toBe(true);
    expect(proof.auditPath.length).toBe(0);
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd packages/hush-ts && npm test`
Expected: FAIL - module not found

**Step 3: Implement Merkle tree**

```typescript
// src/merkle.ts
import { sha256 } from "./crypto/hash";

/**
 * Compute leaf hash per RFC 6962: SHA256(0x00 || data)
 */
export function hashLeaf(data: Uint8Array): Uint8Array {
  const prefixed = new Uint8Array(1 + data.length);
  prefixed[0] = 0x00;
  prefixed.set(data, 1);
  return sha256(prefixed);
}

/**
 * Compute node hash per RFC 6962: SHA256(0x01 || left || right)
 */
export function hashNode(left: Uint8Array, right: Uint8Array): Uint8Array {
  const combined = new Uint8Array(1 + 32 + 32);
  combined[0] = 0x01;
  combined.set(left, 1);
  combined.set(right, 33);
  return sha256(combined);
}

/**
 * Compute Merkle root from leaf hashes.
 * Uses left-balanced semantics: odd node carried upward (not duplicated).
 */
export function computeRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) {
    throw new Error("Cannot compute root of empty tree");
  }

  if (leaves.length === 1) {
    return leaves[0];
  }

  let current = [...leaves];
  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(hashNode(current[i], current[i + 1]));
      } else {
        // Odd node: carry upward unchanged
        next.push(current[i]);
      }
    }
    current = next;
  }

  return current[0];
}

/**
 * Merkle inclusion proof.
 */
export class MerkleProof {
  constructor(
    public readonly treeSize: number,
    public readonly leafIndex: number,
    public readonly auditPath: Uint8Array[]
  ) {}

  /**
   * Compute root from leaf hash and proof.
   */
  computeRoot(leafHash: Uint8Array): Uint8Array {
    if (this.treeSize === 0 || this.leafIndex >= this.treeSize) {
      throw new Error("Invalid proof: index out of range");
    }

    let h = leafHash;
    let idx = this.leafIndex;
    let size = this.treeSize;
    let pathIdx = 0;

    while (size > 1) {
      if (idx % 2 === 0) {
        // Current is left child
        if (idx + 1 < size) {
          // Has sibling on right
          if (pathIdx >= this.auditPath.length) {
            throw new Error("Invalid proof: missing sibling");
          }
          h = hashNode(h, this.auditPath[pathIdx++]);
        }
        // else: no sibling, carry upward
      } else {
        // Current is right child
        if (pathIdx >= this.auditPath.length) {
          throw new Error("Invalid proof: missing sibling");
        }
        h = hashNode(this.auditPath[pathIdx++], h);
      }

      idx = Math.floor(idx / 2);
      size = Math.ceil(size / 2);
    }

    if (pathIdx !== this.auditPath.length) {
      throw new Error("Invalid proof: extra siblings");
    }

    return h;
  }

  /**
   * Verify proof against expected root.
   */
  verify(leafHash: Uint8Array, expectedRoot: Uint8Array): boolean {
    try {
      const computed = this.computeRoot(leafHash);
      return arrayEquals(computed, expectedRoot);
    } catch {
      return false;
    }
  }

  /**
   * Serialize to JSON-compatible object.
   */
  toJSON(): { treeSize: number; leafIndex: number; auditPath: string[] } {
    return {
      treeSize: this.treeSize,
      leafIndex: this.leafIndex,
      auditPath: this.auditPath.map((h) =>
        Array.from(h)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
      ),
    };
  }

  /**
   * Deserialize from JSON.
   */
  static fromJSON(json: {
    treeSize: number;
    leafIndex: number;
    auditPath: string[];
  }): MerkleProof {
    const auditPath = json.auditPath.map((hex) => {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      }
      return bytes;
    });
    return new MerkleProof(json.treeSize, json.leafIndex, auditPath);
  }
}

/**
 * Generate inclusion proof for a leaf at given index.
 */
export function generateProof(leaves: Uint8Array[], index: number): MerkleProof {
  if (leaves.length === 0) {
    throw new Error("Cannot generate proof for empty tree");
  }
  if (index < 0 || index >= leaves.length) {
    throw new Error(`Index ${index} out of range for ${leaves.length} leaves`);
  }

  // Build tree levels
  const levels: Uint8Array[][] = [[...leaves]];
  let current = [...leaves];

  while (current.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < current.length; i += 2) {
      if (i + 1 < current.length) {
        next.push(hashNode(current[i], current[i + 1]));
      } else {
        next.push(current[i]);
      }
    }
    levels.push(next);
    current = next;
  }

  // Collect audit path
  const auditPath: Uint8Array[] = [];
  let idx = index;

  for (const level of levels.slice(0, -1)) {
    if (level.length <= 1) break;

    if (idx % 2 === 0) {
      // Current is left, sibling is right
      const siblingIdx = idx + 1;
      if (siblingIdx < level.length) {
        auditPath.push(level[siblingIdx]);
      }
    } else {
      // Current is right, sibling is left
      auditPath.push(level[idx - 1]);
    }

    idx = Math.floor(idx / 2);
  }

  return new MerkleProof(leaves.length, index, auditPath);
}

/**
 * RFC 6962-compatible Merkle tree.
 */
export class MerkleTree {
  private levels: Uint8Array[][];

  private constructor(levels: Uint8Array[][]) {
    this.levels = levels;
  }

  /**
   * Build tree from raw leaf data (will be hashed).
   */
  static fromData(data: Uint8Array[]): MerkleTree {
    if (data.length === 0) {
      throw new Error("Cannot build tree from empty data");
    }
    const leaves = data.map((d) => hashLeaf(d));
    return MerkleTree.fromHashes(leaves);
  }

  /**
   * Build tree from pre-hashed leaves.
   */
  static fromHashes(leafHashes: Uint8Array[]): MerkleTree {
    if (leafHashes.length === 0) {
      throw new Error("Cannot build tree from empty leaves");
    }

    const levels: Uint8Array[][] = [[...leafHashes]];
    let current = [...leafHashes];

    while (current.length > 1) {
      const next: Uint8Array[] = [];
      for (let i = 0; i < current.length; i += 2) {
        if (i + 1 < current.length) {
          next.push(hashNode(current[i], current[i + 1]));
        } else {
          next.push(current[i]);
        }
      }
      levels.push(next);
      current = next;
    }

    return new MerkleTree(levels);
  }

  get leafCount(): number {
    return this.levels[0]?.length ?? 0;
  }

  get root(): Uint8Array {
    const lastLevel = this.levels[this.levels.length - 1];
    return lastLevel?.[0] ?? new Uint8Array(32);
  }

  /**
   * Generate inclusion proof for leaf at given index.
   */
  inclusionProof(leafIndex: number): MerkleProof {
    if (leafIndex < 0 || leafIndex >= this.leafCount) {
      throw new Error(`Index ${leafIndex} out of range for ${this.leafCount} leaves`);
    }

    const auditPath: Uint8Array[] = [];
    let idx = leafIndex;

    for (const level of this.levels.slice(0, -1)) {
      if (level.length <= 1) break;

      if (idx % 2 === 0) {
        const siblingIdx = idx + 1;
        if (siblingIdx < level.length) {
          auditPath.push(level[siblingIdx]);
        }
      } else {
        auditPath.push(level[idx - 1]);
      }

      idx = Math.floor(idx / 2);
    }

    return new MerkleProof(this.leafCount, leafIndex, auditPath);
  }
}

function arrayEquals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
```

**Step 4: Run tests to verify they pass**

Run: `cd packages/hush-ts && npm test`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-ts/src/merkle.ts packages/hush-ts/tests/merkle.test.ts
git commit -m "feat(hush-ts): add RFC 6962 Merkle tree"
```

---

## Task 6: Receipt Types

**Files:**
- Create: `packages/hush-ts/src/receipt.ts`
- Create: `packages/hush-ts/tests/receipt.test.ts`

**Step 1: Write failing tests for Receipt**

```typescript
// tests/receipt.test.ts
import { describe, it, expect } from "vitest";
import { Receipt, SignedReceipt } from "../src/receipt";
import { generateKeypair } from "../src/crypto/sign";
import { toHex } from "../src/crypto/hash";

describe("Receipt", () => {
  it("creates from fields", () => {
    const receipt = new Receipt({
      id: "run-123",
      artifactRoot: "0xabc123",
      eventCount: 42,
    });

    expect(receipt.id).toBe("run-123");
    expect(receipt.artifactRoot).toBe("0xabc123");
    expect(receipt.eventCount).toBe(42);
    expect(receipt.metadata).toEqual({});
  });

  it("includes optional metadata", () => {
    const receipt = new Receipt({
      id: "run-456",
      artifactRoot: "0xdef789",
      eventCount: 10,
      metadata: { agent: "test", timestamp: 1234567890 },
    });

    expect(receipt.metadata).toEqual({ agent: "test", timestamp: 1234567890 });
  });

  it("serializes to JSON", () => {
    const receipt = new Receipt({
      id: "run-123",
      artifactRoot: "0xabc",
      eventCount: 5,
    });

    const json = receipt.toJSON();
    expect(json).toContain('"id":"run-123"');
    expect(json).toContain('"artifact_root":"0xabc"');
    expect(json).toContain('"event_count":5');
  });

  it("deserializes from JSON", () => {
    const json = '{"artifact_root":"0xabc","event_count":5,"id":"run-123","metadata":{}}';
    const receipt = Receipt.fromJSON(json);

    expect(receipt.id).toBe("run-123");
    expect(receipt.artifactRoot).toBe("0xabc");
    expect(receipt.eventCount).toBe(5);
  });

  it("computes SHA-256 hash", () => {
    const receipt = new Receipt({
      id: "run-123",
      artifactRoot: "0xabc",
      eventCount: 5,
    });

    const hash = receipt.hash();
    expect(hash.length).toBe(32);
  });

  it("computes consistent hash", () => {
    const r1 = new Receipt({
      id: "run-123",
      artifactRoot: "0xabc",
      eventCount: 5,
    });
    const r2 = new Receipt({
      id: "run-123",
      artifactRoot: "0xabc",
      eventCount: 5,
    });

    expect(toHex(r1.hash())).toBe(toHex(r2.hash()));
  });

  it("returns hex hash with 0x prefix", () => {
    const receipt = new Receipt({
      id: "run-123",
      artifactRoot: "0xabc",
      eventCount: 5,
    });

    const hashHex = receipt.hashHex();
    expect(hashHex.startsWith("0x")).toBe(true);
    expect(hashHex.length).toBe(66); // 0x + 64 hex chars
  });
});

describe("SignedReceipt", () => {
  it("signs a receipt", async () => {
    const receipt = new Receipt({
      id: "run-signed",
      artifactRoot: "0xabc",
      eventCount: 10,
    });

    const { privateKey, publicKey } = await generateKeypair();
    const signed = await SignedReceipt.sign(receipt, privateKey, publicKey);

    expect(signed.receipt).toBe(receipt);
    expect(signed.signature.length).toBe(64);
    expect(signed.publicKey).toEqual(publicKey);
  });

  it("verifies valid signature", async () => {
    const receipt = new Receipt({
      id: "run-verify",
      artifactRoot: "0xdef",
      eventCount: 20,
    });

    const { privateKey, publicKey } = await generateKeypair();
    const signed = await SignedReceipt.sign(receipt, privateKey, publicKey);

    const isValid = await signed.verify();
    expect(isValid).toBe(true);
  });

  it("rejects tampered receipt", async () => {
    const receipt = new Receipt({
      id: "run-tamper",
      artifactRoot: "0xabc",
      eventCount: 10,
    });

    const { privateKey, publicKey } = await generateKeypair();
    const signed = await SignedReceipt.sign(receipt, privateKey, publicKey);

    // Tamper with the receipt
    (signed as any).receipt = new Receipt({
      id: "run-tamper",
      artifactRoot: "0xabc",
      eventCount: 999, // Changed!
    });

    const isValid = await signed.verify();
    expect(isValid).toBe(false);
  });

  it("serializes to JSON", async () => {
    const receipt = new Receipt({
      id: "run-json",
      artifactRoot: "0xabc",
      eventCount: 5,
    });

    const { privateKey, publicKey } = await generateKeypair();
    const signed = await SignedReceipt.sign(receipt, privateKey, publicKey);

    const json = signed.toJSON();
    expect(json).toContain('"receipt"');
    expect(json).toContain('"signature"');
    expect(json).toContain('"public_key"');
  });

  it("deserializes from JSON", async () => {
    const receipt = new Receipt({
      id: "run-roundtrip",
      artifactRoot: "0xdef",
      eventCount: 15,
    });

    const { privateKey, publicKey } = await generateKeypair();
    const signed = await SignedReceipt.sign(receipt, privateKey, publicKey);

    const json = signed.toJSON();
    const restored = SignedReceipt.fromJSON(json);

    expect(restored.receipt.id).toBe("run-roundtrip");
    expect(restored.signature.length).toBe(64);
    expect(await restored.verify()).toBe(true);
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd packages/hush-ts && npm test`
Expected: FAIL - module not found

**Step 3: Implement Receipt types**

```typescript
// src/receipt.ts
import { sha256, toHex } from "./crypto/hash";
import { signMessage, verifySignature } from "./crypto/sign";
import { canonicalize } from "./canonical";

export interface ReceiptData {
  id: string;
  artifactRoot: string;
  eventCount: number;
  metadata?: Record<string, unknown>;
}

/**
 * Verification receipt for a run or task.
 */
export class Receipt {
  readonly id: string;
  readonly artifactRoot: string;
  readonly eventCount: number;
  readonly metadata: Record<string, unknown>;

  constructor(data: ReceiptData) {
    this.id = data.id;
    this.artifactRoot = data.artifactRoot;
    this.eventCount = data.eventCount;
    this.metadata = data.metadata ?? {};
  }

  /**
   * Convert to plain object (snake_case keys for compatibility).
   */
  toObject(): Record<string, unknown> {
    return {
      id: this.id,
      artifact_root: this.artifactRoot,
      event_count: this.eventCount,
      metadata: this.metadata,
    };
  }

  /**
   * Convert to canonical JSON string.
   */
  toJSON(): string {
    return canonicalize(this.toObject());
  }

  /**
   * Create from plain object.
   */
  static fromObject(obj: Record<string, unknown>): Receipt {
    return new Receipt({
      id: obj.id as string,
      artifactRoot: obj.artifact_root as string,
      eventCount: obj.event_count as number,
      metadata: (obj.metadata as Record<string, unknown>) ?? {},
    });
  }

  /**
   * Create from JSON string.
   */
  static fromJSON(json: string): Receipt {
    return Receipt.fromObject(JSON.parse(json));
  }

  /**
   * Compute SHA-256 hash of canonical JSON.
   */
  hash(): Uint8Array {
    return sha256(this.toJSON());
  }

  /**
   * Compute SHA-256 hash as hex string with 0x prefix.
   */
  hashHex(): string {
    return "0x" + toHex(this.hash());
  }
}

/**
 * Receipt with Ed25519 signature.
 */
export class SignedReceipt {
  constructor(
    readonly receipt: Receipt,
    readonly signature: Uint8Array,
    readonly publicKey: Uint8Array
  ) {}

  /**
   * Sign a receipt.
   */
  static async sign(
    receipt: Receipt,
    privateKey: Uint8Array,
    publicKey: Uint8Array
  ): Promise<SignedReceipt> {
    const message = new TextEncoder().encode(receipt.toJSON());
    const signature = await signMessage(message, privateKey);
    return new SignedReceipt(receipt, signature, publicKey);
  }

  /**
   * Verify the signature.
   */
  async verify(): Promise<boolean> {
    const message = new TextEncoder().encode(this.receipt.toJSON());
    return verifySignature(message, this.signature, this.publicKey);
  }

  /**
   * Convert to plain object.
   */
  toObject(): Record<string, unknown> {
    return {
      receipt: this.receipt.toObject(),
      signature: base64Encode(this.signature),
      public_key: base64Encode(this.publicKey),
    };
  }

  /**
   * Convert to JSON string.
   */
  toJSON(): string {
    return canonicalize(this.toObject());
  }

  /**
   * Create from plain object.
   */
  static fromObject(obj: Record<string, unknown>): SignedReceipt {
    const receiptObj = obj.receipt as Record<string, unknown>;
    return new SignedReceipt(
      Receipt.fromObject(receiptObj),
      base64Decode(obj.signature as string),
      base64Decode(obj.public_key as string)
    );
  }

  /**
   * Create from JSON string.
   */
  static fromJSON(json: string): SignedReceipt {
    return SignedReceipt.fromObject(JSON.parse(json));
  }
}

// Base64 helpers
function base64Encode(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  // Browser fallback
  return btoa(String.fromCharCode(...bytes));
}

function base64Decode(str: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(str, "base64"));
  }
  // Browser fallback
  return new Uint8Array(
    atob(str)
      .split("")
      .map((c) => c.charCodeAt(0))
  );
}
```

**Step 4: Run tests to verify they pass**

Run: `cd packages/hush-ts && npm test`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-ts/src/receipt.ts packages/hush-ts/tests/receipt.test.ts
git commit -m "feat(hush-ts): add Receipt and SignedReceipt types"
```

---

## Task 7: Guard Types and Base Classes

**Files:**
- Create: `packages/hush-ts/src/guards/types.ts`
- Create: `packages/hush-ts/tests/guards/types.test.ts`

**Step 1: Write failing tests for guard types**

```typescript
// tests/guards/types.test.ts
import { describe, it, expect } from "vitest";
import {
  Severity,
  GuardResult,
  GuardContext,
  GuardAction,
} from "../src/guards/types";

describe("Severity", () => {
  it("has expected values", () => {
    expect(Severity.INFO).toBe("info");
    expect(Severity.WARNING).toBe("warning");
    expect(Severity.ERROR).toBe("error");
    expect(Severity.CRITICAL).toBe("critical");
  });
});

describe("GuardResult", () => {
  it("creates allow result", () => {
    const result = GuardResult.allow("test-guard");
    expect(result.allowed).toBe(true);
    expect(result.guard).toBe("test-guard");
    expect(result.severity).toBe(Severity.INFO);
  });

  it("creates block result", () => {
    const result = GuardResult.block("test-guard", Severity.ERROR, "Blocked for testing");
    expect(result.allowed).toBe(false);
    expect(result.guard).toBe("test-guard");
    expect(result.severity).toBe(Severity.ERROR);
    expect(result.message).toBe("Blocked for testing");
  });

  it("creates warn result", () => {
    const result = GuardResult.warn("test-guard", "Warning message");
    expect(result.allowed).toBe(true);
    expect(result.severity).toBe(Severity.WARNING);
    expect(result.message).toBe("Warning message");
  });

  it("adds details", () => {
    const result = GuardResult.block("test-guard", Severity.CRITICAL, "Critical issue")
      .withDetails({ path: "/etc/passwd", reason: "forbidden" });

    expect(result.details).toEqual({ path: "/etc/passwd", reason: "forbidden" });
  });
});

describe("GuardAction", () => {
  it("creates file access action", () => {
    const action = GuardAction.fileAccess("/path/to/file");
    expect(action.actionType).toBe("file_access");
    expect(action.path).toBe("/path/to/file");
  });

  it("creates file write action", () => {
    const content = new TextEncoder().encode("content");
    const action = GuardAction.fileWrite("/path/to/file", content);
    expect(action.actionType).toBe("file_write");
    expect(action.path).toBe("/path/to/file");
    expect(action.content).toBe(content);
  });

  it("creates network egress action", () => {
    const action = GuardAction.networkEgress("api.example.com", 443);
    expect(action.actionType).toBe("network_egress");
    expect(action.host).toBe("api.example.com");
    expect(action.port).toBe(443);
  });

  it("creates shell command action", () => {
    const action = GuardAction.shellCommand("ls -la");
    expect(action.actionType).toBe("shell_command");
    expect(action.command).toBe("ls -la");
  });

  it("creates MCP tool action", () => {
    const action = GuardAction.mcpTool("read_file", { path: "/etc/passwd" });
    expect(action.actionType).toBe("mcp_tool");
    expect(action.tool).toBe("read_file");
    expect(action.args).toEqual({ path: "/etc/passwd" });
  });

  it("creates patch action", () => {
    const action = GuardAction.patch("/src/file.ts", "+console.log('hi')");
    expect(action.actionType).toBe("patch");
    expect(action.path).toBe("/src/file.ts");
    expect(action.diff).toBe("+console.log('hi')");
  });

  it("creates custom action", () => {
    const action = GuardAction.custom("output", { content: "secret data" });
    expect(action.actionType).toBe("custom");
    expect(action.customType).toBe("output");
    expect(action.customData).toEqual({ content: "secret data" });
  });
});

describe("GuardContext", () => {
  it("creates with defaults", () => {
    const ctx = new GuardContext();
    expect(ctx.cwd).toBeUndefined();
    expect(ctx.sessionId).toBeUndefined();
  });

  it("creates with values", () => {
    const ctx = new GuardContext({
      cwd: "/home/user",
      sessionId: "session-123",
      agentId: "agent-456",
      metadata: { key: "value" },
    });

    expect(ctx.cwd).toBe("/home/user");
    expect(ctx.sessionId).toBe("session-123");
    expect(ctx.agentId).toBe("agent-456");
    expect(ctx.metadata).toEqual({ key: "value" });
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd packages/hush-ts && npm test`
Expected: FAIL - module not found

**Step 3: Implement guard types**

```typescript
// src/guards/types.ts

/**
 * Severity level for guard violations.
 */
export enum Severity {
  INFO = "info",
  WARNING = "warning",
  ERROR = "error",
  CRITICAL = "critical",
}

/**
 * Result of a guard check.
 */
export class GuardResult {
  constructor(
    public readonly allowed: boolean,
    public readonly guard: string,
    public readonly severity: Severity,
    public readonly message: string,
    public details?: Record<string, unknown>
  ) {}

  /**
   * Create an allow result.
   */
  static allow(guard: string): GuardResult {
    return new GuardResult(true, guard, Severity.INFO, "Allowed");
  }

  /**
   * Create a block result.
   */
  static block(guard: string, severity: Severity, message: string): GuardResult {
    return new GuardResult(false, guard, severity, message);
  }

  /**
   * Create a warning result (allowed but logged).
   */
  static warn(guard: string, message: string): GuardResult {
    return new GuardResult(true, guard, Severity.WARNING, message);
  }

  /**
   * Add details to the result.
   */
  withDetails(details: Record<string, unknown>): GuardResult {
    this.details = details;
    return this;
  }
}

/**
 * Context passed to guards for evaluation.
 */
export class GuardContext {
  readonly cwd?: string;
  readonly sessionId?: string;
  readonly agentId?: string;
  readonly metadata?: Record<string, unknown>;

  constructor(
    data: {
      cwd?: string;
      sessionId?: string;
      agentId?: string;
      metadata?: Record<string, unknown>;
    } = {}
  ) {
    this.cwd = data.cwd;
    this.sessionId = data.sessionId;
    this.agentId = data.agentId;
    this.metadata = data.metadata;
  }
}

/**
 * Action to be checked by guards.
 */
export class GuardAction {
  constructor(
    public readonly actionType: string,
    public readonly path?: string,
    public readonly content?: Uint8Array,
    public readonly host?: string,
    public readonly port?: number,
    public readonly tool?: string,
    public readonly args?: Record<string, unknown>,
    public readonly command?: string,
    public readonly diff?: string,
    public readonly customType?: string,
    public readonly customData?: Record<string, unknown>
  ) {}

  /**
   * Create a file access action.
   */
  static fileAccess(path: string): GuardAction {
    return new GuardAction("file_access", path);
  }

  /**
   * Create a file write action.
   */
  static fileWrite(path: string, content: Uint8Array): GuardAction {
    return new GuardAction("file_write", path, content);
  }

  /**
   * Create a network egress action.
   */
  static networkEgress(host: string, port: number): GuardAction {
    return new GuardAction("network_egress", undefined, undefined, host, port);
  }

  /**
   * Create a shell command action.
   */
  static shellCommand(command: string): GuardAction {
    return new GuardAction(
      "shell_command",
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      command
    );
  }

  /**
   * Create an MCP tool action.
   */
  static mcpTool(tool: string, args: Record<string, unknown>): GuardAction {
    return new GuardAction(
      "mcp_tool",
      undefined,
      undefined,
      undefined,
      undefined,
      tool,
      args
    );
  }

  /**
   * Create a patch action.
   */
  static patch(path: string, diff: string): GuardAction {
    return new GuardAction(
      "patch",
      path,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      diff
    );
  }

  /**
   * Create a custom action.
   */
  static custom(customType: string, data: Record<string, unknown>): GuardAction {
    return new GuardAction(
      "custom",
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      customType,
      data
    );
  }
}

/**
 * Abstract base interface for security guards.
 */
export interface Guard {
  /**
   * Name of the guard.
   */
  readonly name: string;

  /**
   * Check if this guard handles the given action type.
   */
  handles(action: GuardAction): boolean;

  /**
   * Evaluate the action.
   */
  check(action: GuardAction, context: GuardContext): GuardResult;
}
```

**Step 4: Run tests to verify they pass**

Run: `cd packages/hush-ts && npm test`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-ts/src/guards/types.ts packages/hush-ts/tests/guards/types.test.ts
git commit -m "feat(hush-ts): add guard base types"
```

---

## Task 8: ForbiddenPathGuard

**Files:**
- Create: `packages/hush-ts/src/guards/forbidden-path.ts`
- Create: `packages/hush-ts/tests/guards/forbidden-path.test.ts`

**Step 1: Write failing tests**

```typescript
// tests/guards/forbidden-path.test.ts
import { describe, it, expect } from "vitest";
import { ForbiddenPathGuard, ForbiddenPathConfig } from "../src/guards/forbidden-path";
import { GuardAction, GuardContext, Severity } from "../src/guards/types";

describe("ForbiddenPathGuard", () => {
  it("has correct name", () => {
    const guard = new ForbiddenPathGuard();
    expect(guard.name).toBe("forbidden_path");
  });

  it("handles file_access, file_write, patch actions", () => {
    const guard = new ForbiddenPathGuard();

    expect(guard.handles(GuardAction.fileAccess("/path"))).toBe(true);
    expect(guard.handles(GuardAction.fileWrite("/path", new Uint8Array()))).toBe(true);
    expect(guard.handles(GuardAction.patch("/path", "diff"))).toBe(true);
    expect(guard.handles(GuardAction.networkEgress("host", 80))).toBe(false);
  });

  it("blocks SSH key access by default", () => {
    const guard = new ForbiddenPathGuard();
    const action = GuardAction.fileAccess("/home/user/.ssh/id_rsa");
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.message).toContain("forbidden");
  });

  it("blocks AWS credentials by default", () => {
    const guard = new ForbiddenPathGuard();
    const action = GuardAction.fileAccess("/home/user/.aws/credentials");
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
  });

  it("blocks .env files by default", () => {
    const guard = new ForbiddenPathGuard();
    const action = GuardAction.fileAccess("/project/.env");
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
  });

  it("allows non-sensitive paths", () => {
    const guard = new ForbiddenPathGuard();
    const action = GuardAction.fileAccess("/home/user/project/src/app.ts");
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(true);
  });

  it("uses custom patterns", () => {
    const config: ForbiddenPathConfig = {
      patterns: ["**/secrets/**", "**/private/**"],
    };
    const guard = new ForbiddenPathGuard(config);

    expect(guard.check(GuardAction.fileAccess("/data/secrets/key.json"), new GuardContext()).allowed).toBe(false);
    expect(guard.check(GuardAction.fileAccess("/data/public/key.json"), new GuardContext()).allowed).toBe(true);
  });

  it("respects exceptions", () => {
    const config: ForbiddenPathConfig = {
      patterns: ["**/.env", "**/.env.*"],
      exceptions: ["**/test/.env.test"],
    };
    const guard = new ForbiddenPathGuard(config);

    expect(guard.check(GuardAction.fileAccess("/project/.env"), new GuardContext()).allowed).toBe(false);
    expect(guard.check(GuardAction.fileAccess("/project/test/.env.test"), new GuardContext()).allowed).toBe(true);
  });

  it("includes details on block", () => {
    const guard = new ForbiddenPathGuard();
    const action = GuardAction.fileAccess("/home/user/.ssh/id_rsa");
    const result = guard.check(action, new GuardContext());

    expect(result.details?.path).toBe("/home/user/.ssh/id_rsa");
    expect(result.details?.reason).toBe("matches_forbidden_pattern");
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd packages/hush-ts && npm test`
Expected: FAIL - module not found

**Step 3: Implement ForbiddenPathGuard**

```typescript
// src/guards/forbidden-path.ts
import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

const DEFAULT_FORBIDDEN_PATTERNS = [
  // SSH keys
  "**/.ssh/**",
  "**/id_rsa*",
  "**/id_ed25519*",
  "**/id_ecdsa*",
  // AWS credentials
  "**/.aws/**",
  // Environment files
  "**/.env",
  "**/.env.*",
  // Git credentials
  "**/.git-credentials",
  "**/.gitconfig",
  // GPG keys
  "**/.gnupg/**",
  // Kubernetes
  "**/.kube/**",
  // Docker
  "**/.docker/**",
  // NPM tokens
  "**/.npmrc",
  // Password stores
  "**/.password-store/**",
  "**/pass/**",
  // 1Password
  "**/.1password/**",
  // System paths
  "/etc/shadow",
  "/etc/passwd",
  "/etc/sudoers",
];

export interface ForbiddenPathConfig {
  patterns?: string[];
  exceptions?: string[];
}

/**
 * Guard that blocks access to sensitive paths.
 */
export class ForbiddenPathGuard implements Guard {
  readonly name = "forbidden_path";
  private patterns: string[];
  private exceptions: string[];

  constructor(config: ForbiddenPathConfig = {}) {
    this.patterns = config.patterns ?? DEFAULT_FORBIDDEN_PATTERNS;
    this.exceptions = config.exceptions ?? [];
  }

  handles(action: GuardAction): boolean {
    return ["file_access", "file_write", "patch"].includes(action.actionType);
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (!this.handles(action)) {
      return GuardResult.allow(this.name);
    }

    const path = action.path;
    if (!path) {
      return GuardResult.allow(this.name);
    }

    if (this.isForbidden(path)) {
      return GuardResult.block(
        this.name,
        Severity.CRITICAL,
        `Access to forbidden path: ${path}`
      ).withDetails({
        path,
        reason: "matches_forbidden_pattern",
      });
    }

    return GuardResult.allow(this.name);
  }

  private isForbidden(path: string): boolean {
    // Normalize path (handle Windows paths)
    const normalized = path.replace(/\\/g, "/");

    // Check exceptions first
    for (const exception of this.exceptions) {
      if (matchGlob(normalized, exception)) {
        return false;
      }
    }

    // Check forbidden patterns
    for (const pattern of this.patterns) {
      if (matchGlob(normalized, pattern)) {
        return true;
      }
    }

    return false;
  }
}

/**
 * Simple glob matcher supporting:
 * - * matches any characters except /
 * - ** matches any characters including /
 * - ? matches any single character
 */
function matchGlob(path: string, pattern: string): boolean {
  // Convert glob to regex
  let regex = pattern
    .replace(/\*\*/g, "\u0000") // Placeholder for **
    .replace(/\*/g, "[^/]*")
    .replace(/\u0000/g, ".*")
    .replace(/\?/g, ".")
    .replace(/\./g, "\\.");

  // Anchor the pattern
  if (!regex.startsWith(".*") && !regex.startsWith("/")) {
    regex = "(^|.*/)" + regex;
  }
  regex = "^" + regex + "$";

  return new RegExp(regex).test(path);
}
```

**Step 4: Run tests to verify they pass**

Run: `cd packages/hush-ts && npm test`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-ts/src/guards/forbidden-path.ts packages/hush-ts/tests/guards/forbidden-path.test.ts
git commit -m "feat(hush-ts): add ForbiddenPathGuard"
```

---

## Task 9: EgressAllowlistGuard

**Files:**
- Create: `packages/hush-ts/src/guards/egress-allowlist.ts`
- Create: `packages/hush-ts/tests/guards/egress-allowlist.test.ts`

**Step 1: Write failing tests**

```typescript
// tests/guards/egress-allowlist.test.ts
import { describe, it, expect } from "vitest";
import { EgressAllowlistGuard, EgressAllowlistConfig } from "../src/guards/egress-allowlist";
import { GuardAction, GuardContext, Severity } from "../src/guards/types";

describe("EgressAllowlistGuard", () => {
  it("has correct name", () => {
    const guard = new EgressAllowlistGuard();
    expect(guard.name).toBe("egress_allowlist");
  });

  it("handles network_egress actions only", () => {
    const guard = new EgressAllowlistGuard();

    expect(guard.handles(GuardAction.networkEgress("host", 80))).toBe(true);
    expect(guard.handles(GuardAction.fileAccess("/path"))).toBe(false);
  });

  it("blocks by default with empty allowlist", () => {
    const guard = new EgressAllowlistGuard();
    const action = GuardAction.networkEgress("api.example.com", 443);
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
    expect(result.message).toContain("unlisted");
  });

  it("allows hosts in allowlist", () => {
    const config: EgressAllowlistConfig = {
      allow: ["api.example.com", "cdn.example.com"],
    };
    const guard = new EgressAllowlistGuard(config);

    expect(guard.check(GuardAction.networkEgress("api.example.com", 443), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("cdn.example.com", 80), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("other.com", 443), new GuardContext()).allowed).toBe(false);
  });

  it("supports wildcard subdomain patterns", () => {
    const config: EgressAllowlistConfig = {
      allow: ["*.example.com"],
    };
    const guard = new EgressAllowlistGuard(config);

    expect(guard.check(GuardAction.networkEgress("api.example.com", 443), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("sub.api.example.com", 443), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("example.com", 443), new GuardContext()).allowed).toBe(false);
  });

  it("supports subdomain matching", () => {
    const config: EgressAllowlistConfig = {
      allow: ["example.com"],
    };
    const guard = new EgressAllowlistGuard(config);

    expect(guard.check(GuardAction.networkEgress("example.com", 443), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("api.example.com", 443), new GuardContext()).allowed).toBe(true);
  });

  it("block list takes precedence", () => {
    const config: EgressAllowlistConfig = {
      allow: ["*.example.com"],
      block: ["evil.example.com"],
    };
    const guard = new EgressAllowlistGuard(config);

    expect(guard.check(GuardAction.networkEgress("api.example.com", 443), new GuardContext()).allowed).toBe(true);
    expect(guard.check(GuardAction.networkEgress("evil.example.com", 443), new GuardContext()).allowed).toBe(false);
  });

  it("respects default action", () => {
    const config: EgressAllowlistConfig = {
      defaultAction: "allow",
    };
    const guard = new EgressAllowlistGuard(config);

    expect(guard.check(GuardAction.networkEgress("any.host.com", 443), new GuardContext()).allowed).toBe(true);
  });

  it("includes details on block", () => {
    const guard = new EgressAllowlistGuard();
    const action = GuardAction.networkEgress("malicious.com", 8080);
    const result = guard.check(action, new GuardContext());

    expect(result.details?.host).toBe("malicious.com");
    expect(result.details?.port).toBe(8080);
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd packages/hush-ts && npm test`
Expected: FAIL - module not found

**Step 3: Implement EgressAllowlistGuard**

```typescript
// src/guards/egress-allowlist.ts
import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

export interface EgressAllowlistConfig {
  allow?: string[];
  block?: string[];
  defaultAction?: "allow" | "block";
}

/**
 * Guard that controls outbound network access.
 */
export class EgressAllowlistGuard implements Guard {
  readonly name = "egress_allowlist";
  private allow: string[];
  private block: string[];
  private defaultAction: "allow" | "block";

  constructor(config: EgressAllowlistConfig = {}) {
    this.allow = config.allow ?? [];
    this.block = config.block ?? [];
    this.defaultAction = config.defaultAction ?? "block";
  }

  handles(action: GuardAction): boolean {
    return action.actionType === "network_egress";
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    if (!this.handles(action)) {
      return GuardResult.allow(this.name);
    }

    const host = action.host;
    if (!host) {
      return GuardResult.allow(this.name);
    }

    // Check block list first (takes precedence)
    if (this.matchesAny(host, this.block)) {
      return GuardResult.block(
        this.name,
        Severity.ERROR,
        `Egress to blocked destination: ${host}`
      ).withDetails({
        host,
        port: action.port,
        reason: "explicitly_blocked",
      });
    }

    // Check allow list
    if (this.matchesAny(host, this.allow)) {
      return GuardResult.allow(this.name);
    }

    // Apply default action
    if (this.defaultAction === "allow") {
      return GuardResult.allow(this.name);
    }

    return GuardResult.block(
      this.name,
      Severity.ERROR,
      `Egress to unlisted destination: ${host}`
    ).withDetails({
      host,
      port: action.port,
      reason: "not_in_allowlist",
    });
  }

  private matchesAny(host: string, patterns: string[]): boolean {
    return patterns.some((p) => this.matchPattern(host, p));
  }

  private matchPattern(host: string, pattern: string): boolean {
    if (!pattern) return false;

    // Exact match
    if (host === pattern) return true;

    // Wildcard pattern: *.example.com
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1); // ".example.com"
      return host.endsWith(suffix);
    }

    // Subdomain matching: host ends with .pattern
    if (host.endsWith("." + pattern)) {
      return true;
    }

    return false;
  }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd packages/hush-ts && npm test`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-ts/src/guards/egress-allowlist.ts packages/hush-ts/tests/guards/egress-allowlist.test.ts
git commit -m "feat(hush-ts): add EgressAllowlistGuard"
```

---

## Task 10: SecretLeakGuard

**Files:**
- Create: `packages/hush-ts/src/guards/secret-leak.ts`
- Create: `packages/hush-ts/tests/guards/secret-leak.test.ts`

**Step 1: Write failing tests**

```typescript
// tests/guards/secret-leak.test.ts
import { describe, it, expect } from "vitest";
import { SecretLeakGuard, SecretLeakConfig } from "../src/guards/secret-leak";
import { GuardAction, GuardContext, Severity } from "../src/guards/types";

describe("SecretLeakGuard", () => {
  it("has correct name", () => {
    const guard = new SecretLeakGuard();
    expect(guard.name).toBe("secret_leak");
  });

  it("handles custom output actions", () => {
    const guard = new SecretLeakGuard();

    expect(guard.handles(GuardAction.custom("output", {}))).toBe(true);
    expect(guard.handles(GuardAction.custom("bash_output", {}))).toBe(true);
    expect(guard.handles(GuardAction.custom("tool_result", {}))).toBe(true);
    expect(guard.handles(GuardAction.custom("response", {}))).toBe(true);
    expect(guard.handles(GuardAction.fileAccess("/path"))).toBe(false);
  });

  it("allows when no secrets configured", () => {
    const guard = new SecretLeakGuard();
    const action = GuardAction.custom("output", { content: "secret data" });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(true);
  });

  it("blocks when secret is found in output", () => {
    const config: SecretLeakConfig = {
      secrets: ["super-secret-key-12345"],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", {
      content: "Found: super-secret-key-12345",
    });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
    expect(result.severity).toBe(Severity.CRITICAL);
    expect(result.message).toContain("Secret");
  });

  it("allows when secret not present", () => {
    const config: SecretLeakConfig = {
      secrets: ["super-secret-key-12345"],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", {
      content: "Normal output without secrets",
    });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(true);
  });

  it("checks multiple content fields", () => {
    const config: SecretLeakConfig = {
      secrets: ["the-secret"],
    };
    const guard = new SecretLeakGuard(config);

    expect(
      guard.check(
        GuardAction.custom("output", { output: "the-secret leaked" }),
        new GuardContext()
      ).allowed
    ).toBe(false);

    expect(
      guard.check(
        GuardAction.custom("output", { result: "the-secret found" }),
        new GuardContext()
      ).allowed
    ).toBe(false);

    expect(
      guard.check(
        GuardAction.custom("output", { error: "the-secret in error" }),
        new GuardContext()
      ).allowed
    ).toBe(false);
  });

  it("provides secret hint in details", () => {
    const config: SecretLeakConfig = {
      secrets: ["super-secret-key"],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", { content: "super-secret-key" });
    const result = guard.check(action, new GuardContext());

    expect(result.details?.secret_hint).toBe("supe...");
  });

  it("respects enabled flag", () => {
    const config: SecretLeakConfig = {
      secrets: ["secret"],
      enabled: false,
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", { content: "secret" });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(true);
  });

  it("ignores empty secrets", () => {
    const config: SecretLeakConfig = {
      secrets: ["", "  ", "valid-secret"],
    };
    const guard = new SecretLeakGuard(config);
    const action = GuardAction.custom("output", { content: "valid-secret" });
    const result = guard.check(action, new GuardContext());

    expect(result.allowed).toBe(false);
  });
});
```

**Step 2: Run tests to verify they fail**

Run: `cd packages/hush-ts && npm test`
Expected: FAIL - module not found

**Step 3: Implement SecretLeakGuard**

```typescript
// src/guards/secret-leak.ts
import { Guard, GuardAction, GuardContext, GuardResult, Severity } from "./types";

const OUTPUT_ACTION_TYPES = new Set(["output", "bash_output", "tool_result", "response"]);

export interface SecretLeakConfig {
  secrets?: string[];
  enabled?: boolean;
}

/**
 * Guard that detects secret values in output.
 */
export class SecretLeakGuard implements Guard {
  readonly name = "secret_leak";
  private secrets: string[];
  private enabled: boolean;

  constructor(config: SecretLeakConfig = {}) {
    // Filter out empty/whitespace-only secrets
    this.secrets = (config.secrets ?? []).filter((s) => s && s.trim());
    this.enabled = config.enabled ?? true;
  }

  handles(action: GuardAction): boolean {
    if (action.actionType === "custom" && action.customType) {
      return OUTPUT_ACTION_TYPES.has(action.customType);
    }
    return false;
  }

  check(action: GuardAction, _context: GuardContext): GuardResult {
    // Skip if disabled or no secrets configured
    if (!this.enabled || this.secrets.length === 0) {
      return GuardResult.allow(this.name);
    }

    if (!this.handles(action)) {
      return GuardResult.allow(this.name);
    }

    const text = this.extractText(action.customData);
    if (!text) {
      return GuardResult.allow(this.name);
    }

    // Check for any secret in the output
    for (const secret of this.secrets) {
      if (text.includes(secret)) {
        // Create hint (first 4 chars + "...")
        const hint = secret.length > 4 ? secret.slice(0, 4) + "..." : secret.slice(0, 2) + "...";

        return GuardResult.block(
          this.name,
          Severity.CRITICAL,
          "Secret value exposed in output"
        ).withDetails({
          secret_hint: hint,
          action_type: action.customType,
        });
      }
    }

    return GuardResult.allow(this.name);
  }

  private extractText(data?: Record<string, unknown>): string {
    if (!data) return "";

    // Check common content field names
    for (const key of ["content", "output", "result", "error", "text"]) {
      const value = data[key];
      if (typeof value === "string" && value) {
        return value;
      }
    }

    return "";
  }
}
```

**Step 4: Run tests to verify they pass**

Run: `cd packages/hush-ts && npm test`
Expected: PASS

**Step 5: Commit**

```bash
git add packages/hush-ts/src/guards/secret-leak.ts packages/hush-ts/tests/guards/secret-leak.test.ts
git commit -m "feat(hush-ts): add SecretLeakGuard"
```

---

## Task 11: Guards Barrel Export & Main Index

**Files:**
- Create: `packages/hush-ts/src/guards/index.ts`
- Modify: `packages/hush-ts/src/index.ts`

**Step 1: Create guards barrel export**

```typescript
// src/guards/index.ts
export {
  Severity,
  GuardResult,
  GuardContext,
  GuardAction,
  type Guard,
} from "./types";
export { ForbiddenPathGuard, type ForbiddenPathConfig } from "./forbidden-path";
export { EgressAllowlistGuard, type EgressAllowlistConfig } from "./egress-allowlist";
export { SecretLeakGuard, type SecretLeakConfig } from "./secret-leak";
```

**Step 2: Update main index.ts with all exports**

```typescript
// src/index.ts
/**
 * @hushclaw/sdk - TypeScript SDK for hushclaw security verification
 * @packageDocumentation
 */

export const VERSION = "0.1.0";

// Crypto
export {
  sha256,
  keccak256,
  toHex,
  fromHex,
} from "./crypto/hash";
export {
  generateKeypair,
  signMessage,
  verifySignature,
  type Keypair,
} from "./crypto/sign";

// Canonical JSON
export { canonicalize, canonicalHash } from "./canonical";

// Merkle tree
export {
  hashLeaf,
  hashNode,
  computeRoot,
  generateProof,
  MerkleTree,
  MerkleProof,
} from "./merkle";

// Receipt
export { Receipt, SignedReceipt, type ReceiptData } from "./receipt";

// Guards
export {
  Severity,
  GuardResult,
  GuardContext,
  GuardAction,
  type Guard,
  ForbiddenPathGuard,
  type ForbiddenPathConfig,
  EgressAllowlistGuard,
  type EgressAllowlistConfig,
  SecretLeakGuard,
  type SecretLeakConfig,
} from "./guards";
```

**Step 3: Build and verify exports work**

Run: `cd packages/hush-ts && npm run build && npm run typecheck`
Expected: No errors

**Step 4: Commit**

```bash
git add packages/hush-ts/src/guards/index.ts packages/hush-ts/src/index.ts
git commit -m "feat(hush-ts): add barrel exports for all modules"
```

---

## Task 12: CI Integration

**Files:**
- Modify: `.github/workflows/ci.yml`

**Step 1: Add TypeScript SDK job to CI**

Add the following job after the `wasm` job in `.github/workflows/ci.yml`:

```yaml
  typescript-sdk:
    name: TypeScript SDK
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: packages/hush-ts
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: packages/hush-ts/package-lock.json

      - name: Install dependencies
        run: npm ci

      - name: Type check
        run: npm run typecheck

      - name: Build
        run: npm run build

      - name: Test
        run: npm test

      - name: Verify package exports
        run: |
          node -e "const sdk = require('./dist/index.cjs'); console.log('CJS exports:', Object.keys(sdk).slice(0, 10))"
          node --input-type=module -e "import * as sdk from './dist/index.js'; console.log('ESM exports:', Object.keys(sdk).slice(0, 10))"
```

**Step 2: Verify CI config is valid YAML**

Run: `cd /Users/connor/Medica/hushclaw-ws19-typescript-sdk && python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`
Expected: No errors

**Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add TypeScript SDK job to CI"
```

---

## Task 13: Release Workflow Integration

**Files:**
- Modify: `.github/workflows/release.yml`

**Step 1: Add publish-hush-ts job**

Add the following job after `publish-npm` in `.github/workflows/release.yml`:

```yaml
  # Publish @hushclaw/sdk to npm
  publish-hush-ts:
    name: Publish @hushclaw/sdk to npm
    runs-on: ubuntu-latest
    needs: preflight
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          registry-url: 'https://registry.npmjs.org'

      - name: Install and build
        working-directory: packages/hush-ts
        run: |
          npm ci
          npm run build

      - name: Set version from tag
        working-directory: packages/hush-ts
        run: |
          VERSION=${GITHUB_REF#refs/tags/v}
          npm version $VERSION --no-git-tag-version --allow-same-version

      - name: Publish to npm
        working-directory: packages/hush-ts
        run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

**Step 2: Verify release config is valid YAML**

Run: `cd /Users/connor/Medica/hushclaw-ws19-typescript-sdk && python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`
Expected: No errors

**Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add @hushclaw/sdk to release workflow"
```

---

## Task 14: README Documentation

**Files:**
- Create: `packages/hush-ts/README.md`

**Step 1: Create README**

```markdown
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
import { MerkleTree, hashLeaf } from "@hushclaw/sdk";

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
```

**Step 2: Commit**

```bash
git add packages/hush-ts/README.md
git commit -m "docs(hush-ts): add README with usage examples"
```

---

## Task 15: Final Verification

**Step 1: Run full build and test**

Run: `cd packages/hush-ts && npm run clean && npm install && npm run build && npm test`
Expected: All tests pass, build succeeds

**Step 2: Verify package structure**

Run: `cd packages/hush-ts && ls -la dist/`
Expected: Contains index.js, index.cjs, index.d.ts

**Step 3: Test import in Node**

Run: `cd packages/hush-ts && node -e "const sdk = require('./dist/index.cjs'); console.log('Exports:', Object.keys(sdk).join(', '))"`
Expected: Lists all exported symbols

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore(hush-ts): final verification pass"
```

---

**Plan complete and saved to `docs/plans/2026-01-31-hush-ts-sdk.md`. Two execution options:**

**1. Subagent-Driven (this session)** - I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** - Open new session with executing-plans, batch execution with checkpoints

**Which approach?**
