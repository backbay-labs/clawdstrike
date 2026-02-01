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

    // Create a new SignedReceipt with tampered data
    const tampered = new SignedReceipt(
      new Receipt({
        id: "run-tamper",
        artifactRoot: "0xabc",
        eventCount: 999, // Changed!
      }),
      signed.signature,
      signed.publicKey
    );

    const isValid = await tampered.verify();
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
