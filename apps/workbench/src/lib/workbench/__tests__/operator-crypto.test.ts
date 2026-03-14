import { describe, expect, it } from "vitest";
import {
  generateOperatorKeypair,
  deriveFingerprint,
  createOperatorIdentity,
  canonicalizeJson,
  signCanonical,
  verifyCanonical,
  signOwnershipProof,
  verifyOwnershipProof,
  exportKey,
  importKey,
  hexToBytes,
  toHex,
} from "../operator-crypto";

describe("generateOperatorKeypair", () => {
  it("returns 64-char hex public key and 64-char secret key", async () => {
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();

    expect(publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(secretKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  it("generates distinct keypairs on successive calls", async () => {
    const a = await generateOperatorKeypair();
    const b = await generateOperatorKeypair();

    expect(a.publicKeyHex).not.toBe(b.publicKeyHex);
    expect(a.secretKeyHex).not.toBe(b.secretKeyHex);
  });
});

describe("deriveFingerprint", () => {
  it("returns a 16-char hex string", async () => {
    const { publicKeyHex } = await generateOperatorKeypair();
    const fingerprint = await deriveFingerprint(publicKeyHex);

    expect(fingerprint).toMatch(/^[0-9a-f]{16}$/);
  });

  it("is deterministic for the same input", async () => {
    const { publicKeyHex } = await generateOperatorKeypair();
    const fp1 = await deriveFingerprint(publicKeyHex);
    const fp2 = await deriveFingerprint(publicKeyHex);

    expect(fp1).toBe(fp2);
  });
});

describe("createOperatorIdentity", () => {
  it("returns a complete identity with all fields", async () => {
    const { identity, secretKeyHex } = await createOperatorIdentity("Test Operator");

    expect(identity.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(identity.fingerprint).toMatch(/^[0-9a-f]{16}$/);
    expect(typeof identity.sigil).toBe("string");
    expect(identity.sigil.length).toBeGreaterThan(0);
    expect(identity.nickname).toBe("test-operator");
    expect(identity.displayName).toBe("Test Operator");
    expect(identity.idpClaims).toBeNull();
    expect(identity.createdAt).toBeGreaterThan(0);
    expect(identity.originDeviceId).toMatch(/^[0-9a-f]{16}$/);
    expect(identity.devices).toHaveLength(1);
    expect(identity.devices[0].deviceName).toBe("primary");
    expect(secretKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  it("sanitizes special characters in nickname", async () => {
    const { identity } = await createOperatorIdentity("Alice O'Brien (admin)");
    expect(identity.nickname).toBe("alice-obrien-admin");
  });
});

describe("canonicalizeJson", () => {
  it("produces deterministic output for different key orderings", () => {
    const a = { z: 1, a: 2, m: 3 };
    const b = { a: 2, m: 3, z: 1 };
    const c = { m: 3, z: 1, a: 2 };

    const result = canonicalizeJson(a);
    expect(result).toBe(canonicalizeJson(b));
    expect(result).toBe(canonicalizeJson(c));
    expect(result).toBe('{"a":2,"m":3,"z":1}');
  });

  it("handles nested objects", () => {
    const obj = { b: { d: 1, c: 2 }, a: 3 };
    expect(canonicalizeJson(obj)).toBe('{"a":3,"b":{"c":2,"d":1}}');
  });

  it("preserves arrays in order", () => {
    const obj = { items: [3, 1, 2] };
    expect(canonicalizeJson(obj)).toBe('{"items":[3,1,2]}');
  });
});

describe("signCanonical + verifyCanonical", () => {
  it("round-trips: sign then verify with correct key", async () => {
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
    const payload = { action: "test", timestamp: 12345 };

    const signature = await signCanonical(payload, secretKeyHex);
    expect(signature).toMatch(/^[0-9a-f]+$/);
    expect(signature.length).toBeGreaterThanOrEqual(64);

    const valid = await verifyCanonical(payload, signature, publicKeyHex);
    expect(valid).toBe(true);
  });

  it("returns false when verifying with the wrong key", async () => {
    const signer = await generateOperatorKeypair();
    const stranger = await generateOperatorKeypair();
    const payload = { data: "hello" };

    const signature = await signCanonical(payload, signer.secretKeyHex);
    const valid = await verifyCanonical(payload, signature, stranger.publicKeyHex);

    expect(valid).toBe(false);
  });
});

describe("signOwnershipProof + verifyOwnershipProof", () => {
  it("round-trips: sign then verify ownership proof", async () => {
    const operator = await generateOperatorKeypair();
    const sentinelPublicKey = toHex(crypto.getRandomValues(new Uint8Array(32)));

    const proof = await signOwnershipProof(sentinelPublicKey, operator.secretKeyHex);
    expect(proof.signature).toMatch(/^[0-9a-f]+$/);
    expect(proof.timestamp).toBeGreaterThan(0);

    const valid = await verifyOwnershipProof(sentinelPublicKey, proof, operator.publicKeyHex);
    expect(valid).toBe(true);
  });

  it("rejects proof verified with wrong operator key", async () => {
    const operator = await generateOperatorKeypair();
    const stranger = await generateOperatorKeypair();
    const sentinelPublicKey = toHex(crypto.getRandomValues(new Uint8Array(32)));

    const proof = await signOwnershipProof(sentinelPublicKey, operator.secretKeyHex);
    const valid = await verifyOwnershipProof(sentinelPublicKey, proof, stranger.publicKeyHex);

    expect(valid).toBe(false);
  });

  it("rejects expired proofs (older than maxAgeMs)", async () => {
    const operator = await generateOperatorKeypair();
    const sentinelPublicKey = toHex(crypto.getRandomValues(new Uint8Array(32)));

    // Create proof with a timestamp 25 hours in the past
    const oldTimestamp = Date.now() - 25 * 60 * 60 * 1000;
    const proof = await signOwnershipProof(sentinelPublicKey, operator.secretKeyHex, oldTimestamp);

    const valid = await verifyOwnershipProof(sentinelPublicKey, proof, operator.publicKeyHex);
    expect(valid).toBe(false);
  });

  it("accepts proofs within maxAgeMs window", async () => {
    const operator = await generateOperatorKeypair();
    const sentinelPublicKey = toHex(crypto.getRandomValues(new Uint8Array(32)));

    // Create proof with a timestamp 1 hour in the past
    const recentTimestamp = Date.now() - 60 * 60 * 1000;
    const proof = await signOwnershipProof(sentinelPublicKey, operator.secretKeyHex, recentTimestamp);

    const valid = await verifyOwnershipProof(sentinelPublicKey, proof, operator.publicKeyHex);
    expect(valid).toBe(true);
  });

  it("rejects proofs far in the future (clock skew)", async () => {
    const operator = await generateOperatorKeypair();
    const sentinelPublicKey = toHex(crypto.getRandomValues(new Uint8Array(32)));

    // Create proof with a timestamp 5 minutes in the future (beyond 60s tolerance)
    const futureTimestamp = Date.now() + 5 * 60 * 1000;
    const proof = await signOwnershipProof(sentinelPublicKey, operator.secretKeyHex, futureTimestamp);

    const valid = await verifyOwnershipProof(sentinelPublicKey, proof, operator.publicKeyHex);
    expect(valid).toBe(false);
  });

  it("bypasses expiry check with Infinity maxAgeMs", async () => {
    const operator = await generateOperatorKeypair();
    const sentinelPublicKey = toHex(crypto.getRandomValues(new Uint8Array(32)));

    // Create proof with a very old timestamp
    const oldTimestamp = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const proof = await signOwnershipProof(sentinelPublicKey, operator.secretKeyHex, oldTimestamp);

    const valid = await verifyOwnershipProof(sentinelPublicKey, proof, operator.publicKeyHex, Infinity);
    expect(valid).toBe(true);
  });
});

describe("exportKey + importKey", () => {
  it("round-trips with the correct passphrase", async () => {
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
    const passphrase = "correct-horse-battery-staple";

    const exported = await exportKey(secretKeyHex, publicKeyHex, passphrase);
    expect(typeof exported).toBe("string");
    expect(exported.length).toBeGreaterThan(0);

    const imported = await importKey(exported, passphrase);
    expect(imported.secretKeyHex).toBe(secretKeyHex);
    expect(imported.publicKeyHex).toBe(publicKeyHex);
  });

  it("returns the same publicKeyHex after round-trip", async () => {
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
    const exported = await exportKey(secretKeyHex, publicKeyHex, "test-passphrase");
    const imported = await importKey(exported, "test-passphrase");

    expect(imported.publicKeyHex).toBe(publicKeyHex);
    expect(imported.secretKeyHex).toBe(secretKeyHex);
  });

  it("throws with the wrong passphrase", async () => {
    const { publicKeyHex, secretKeyHex } = await generateOperatorKeypair();
    const exported = await exportKey(secretKeyHex, publicKeyHex, "right-passphrase");

    await expect(importKey(exported, "wrong-passphrase")).rejects.toThrow();
  });
});

describe("hexToBytes", () => {
  it("converts hex to bytes and back", () => {
    const original = new Uint8Array([0, 1, 127, 128, 255]);
    const hex = toHex(original);
    const roundTripped = hexToBytes(hex);
    expect(roundTripped).toEqual(original);
  });

  it("throws on odd-length input", () => {
    expect(() => hexToBytes("abc")).toThrow("even length");
  });

  it("throws on non-hex characters", () => {
    expect(() => hexToBytes("zzzz")).toThrow("invalid hex");
  });
});
