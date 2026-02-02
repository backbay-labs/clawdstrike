import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  RECEIPT_SCHEMA_VERSION,
  Receipt,
  SignedReceipt,
  validateReceiptVersion,
} from "../src/receipt";
import { generateKeypair } from "../src/crypto/sign";
import { toHex } from "../src/crypto/hash";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "../../..");
const ZERO_HASH = `0x${"00".repeat(32)}`;

describe("validateReceiptVersion (golden vectors)", () => {
  const casesPath = path.join(REPO_ROOT, "fixtures/receipts/version_cases.json");
  const cases = JSON.parse(fs.readFileSync(casesPath, "utf8")) as Array<{
    version: string;
    supported: boolean;
    error_contains?: string;
  }>;

  for (const c of cases) {
    it(c.version, () => {
      if (c.supported) {
        expect(() => validateReceiptVersion(c.version)).not.toThrow();
      } else {
        expect(() => validateReceiptVersion(c.version)).toThrow(
          c.error_contains ?? "Invalid receipt version"
        );
      }
    });
  }
});

describe("Receipt", () => {
  it("creates a valid receipt and canonicalizes deterministically", () => {
    const receipt = new Receipt({
      contentHash: ZERO_HASH,
      verdict: { passed: true, gate_id: "unit-test" },
      timestamp: "2026-01-01T00:00:00Z",
      receiptId: "test-receipt-001",
    });

    expect(receipt.version).toBe(RECEIPT_SCHEMA_VERSION);
    expect(receipt.contentHash).toBe(ZERO_HASH);
    expect(receipt.receiptId).toBe("test-receipt-001");

    const json = receipt.toCanonicalJSON();
    expect(json).toContain('"version":"1.0.0"');
    expect(json).toContain('"receipt_id":"test-receipt-001"');
    expect(json).toContain('"content_hash":"0x0000000000000000000000000000000000000000000000000000000000000000"');
  });

  it("fails closed on unknown fields", () => {
    expect(() =>
      Receipt.fromObject({
        version: RECEIPT_SCHEMA_VERSION,
        timestamp: "2026-01-01T00:00:00Z",
        content_hash: ZERO_HASH,
        verdict: { passed: true },
        extra_field: 1,
      })
    ).toThrow(/Unknown receipt field/);
  });

  it("computes stable receipt hashes", () => {
    const receipt = new Receipt({
      contentHash: ZERO_HASH,
      verdict: { passed: true },
      timestamp: "2026-01-01T00:00:00Z",
    });
    expect(receipt.hashSha256()).toMatch(/^0x[0-9a-f]{64}$/);
    expect(receipt.hashKeccak256()).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

describe("SignedReceipt", () => {
  it("signs and verifies a receipt", async () => {
    const receipt = new Receipt({
      contentHash: ZERO_HASH,
      verdict: { passed: true, gate_id: "gate" },
      timestamp: "2026-01-01T00:00:00Z",
    });

    const { privateKey, publicKey } = await generateKeypair();
    const signed = await SignedReceipt.sign(receipt, privateKey);

    expect(signed.signatures.signer).toMatch(/^[0-9a-f]{128}$/);

    const result = await signed.verify({ signer: toHex(publicKey) });
    expect(result.valid).toBe(true);
    expect(result.signer_valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("rejects tampering", async () => {
    const receipt = new Receipt({
      contentHash: ZERO_HASH,
      verdict: { passed: true },
      timestamp: "2026-01-01T00:00:00Z",
    });

    const { privateKey, publicKey } = await generateKeypair();
    const signed = await SignedReceipt.sign(receipt, privateKey);

    const tamperedReceipt = new Receipt({
      contentHash: ZERO_HASH,
      verdict: { passed: false },
      timestamp: "2026-01-01T00:00:00Z",
    });

    const tampered = new SignedReceipt(tamperedReceipt, signed.signatures);
    const result = await tampered.verify({ signer: toHex(publicKey) });
    expect(result.valid).toBe(false);
    expect(result.signer_valid).toBe(false);
  });

  it("roundtrips JSON deterministically", async () => {
    const receipt = new Receipt({
      contentHash: ZERO_HASH,
      verdict: { passed: true },
      timestamp: "2026-01-01T00:00:00Z",
    });

    const { privateKey, publicKey } = await generateKeypair();
    const signed = await SignedReceipt.sign(receipt, privateKey);

    const json = signed.toJSON();
    const parsed = SignedReceipt.fromJSON(json);

    expect(parsed.receipt.version).toBe(RECEIPT_SCHEMA_VERSION);
    const result = await parsed.verify({ signer: toHex(publicKey) });
    expect(result.valid).toBe(true);
  });
});
