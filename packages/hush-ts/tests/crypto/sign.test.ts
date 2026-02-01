import { describe, it, expect } from "vitest";
import { generateKeypair, signMessage, verifySignature } from "../../src/crypto/sign";

describe("generateKeypair", () => {
  it("generates 32-byte private key", async () => {
    const { privateKey } = await generateKeypair();
    expect(privateKey).toBeInstanceOf(Uint8Array);
    expect(privateKey.length).toBe(32);
  });

  it("generates 32-byte public key", async () => {
    const { publicKey } = await generateKeypair();
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
