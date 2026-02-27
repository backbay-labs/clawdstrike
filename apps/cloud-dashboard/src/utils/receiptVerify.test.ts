import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { verifyReceipt } from "./receiptVerify";

// Helper: build a valid receipt JSON object
function makeReceipt(overrides: Record<string, unknown> = {}) {
  return {
    public_key: btoa("fake-ed25519-public-key-32by"),
    signature: btoa("fake-signature-bytes-here1234"),
    decision: "allow",
    action_type: "file_read",
    target: "/tmp/test.txt",
    guard: "ForbiddenPathGuard",
    policy_hash: "sha256:abc123",
    timestamp: "2026-02-26T00:00:00Z",
    ...overrides,
  };
}

// Stubs for crypto.subtle that we swap per-test
let importKeyStub: ReturnType<typeof vi.fn>;
let verifyStub: ReturnType<typeof vi.fn>;
let originalCrypto: Crypto;

beforeEach(() => {
  importKeyStub = vi.fn();
  verifyStub = vi.fn();

  originalCrypto = globalThis.crypto;

  // Replace crypto.subtle with our mocks while preserving other crypto methods
  Object.defineProperty(globalThis, "crypto", {
    value: {
      ...originalCrypto,
      subtle: {
        ...originalCrypto.subtle,
        importKey: importKeyStub,
        verify: verifyStub,
      },
    },
    writable: true,
    configurable: true,
  });
});

afterEach(() => {
  Object.defineProperty(globalThis, "crypto", {
    value: originalCrypto,
    writable: true,
    configurable: true,
  });
  vi.restoreAllMocks();
});

describe("verifyReceipt", () => {
  // ---- (a) Invalid JSON input ----
  it("returns error for non-JSON input", async () => {
    const result = await verifyReceipt("this is not json");
    expect(result).toEqual({ valid: false, error: "Invalid JSON" });
  });

  it("returns error for empty string", async () => {
    const result = await verifyReceipt("");
    expect(result).toEqual({ valid: false, error: "Invalid JSON" });
  });

  // ---- (b) Missing signature field ----
  it("returns error when signature is missing", async () => {
    const { signature: _, ...receipt } = makeReceipt();
    const result = await verifyReceipt(JSON.stringify(receipt));
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Missing signature or public_key/);
  });

  it("returns error when signature is empty string", async () => {
    const result = await verifyReceipt(
      JSON.stringify(makeReceipt({ signature: "" })),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Missing signature or public_key/);
  });

  // ---- (c) Missing publicKey field ----
  it("returns error when public_key is missing", async () => {
    const receipt = makeReceipt();
    delete (receipt as Record<string, unknown>).public_key;
    const result = await verifyReceipt(JSON.stringify(receipt));
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Missing signature or public_key/);
  });

  it("returns error when public_key is empty string", async () => {
    const result = await verifyReceipt(
      JSON.stringify(makeReceipt({ public_key: "" })),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Missing signature or public_key/);
  });

  // ---- (d) Valid receipt — happy path ----
  it("returns valid:true when crypto.subtle.verify returns true", async () => {
    importKeyStub.mockResolvedValue({ type: "public" });
    verifyStub.mockResolvedValue(true);

    const receipt = makeReceipt();
    const result = await verifyReceipt(JSON.stringify(receipt));

    expect(result.valid).toBe(true);
    expect(result.receipt).toBeDefined();
    expect(result.receipt!.decision).toBe("allow");
    expect(result.receipt!.action_type).toBe("file_read");
    expect(result.receipt!.signer_public_key).toBe(receipt.public_key);
    expect(result.receipt!.signature).toBe(receipt.signature);

    // Verify importKey was called with Ed25519
    expect(importKeyStub).toHaveBeenCalledWith(
      "raw",
      expect.any(Uint8Array),
      { name: "Ed25519" },
      false,
      ["verify"],
    );

    // Verify crypto.subtle.verify was called with Ed25519
    expect(verifyStub).toHaveBeenCalledOnce();
    const verifyArgs = verifyStub.mock.calls[0];
    expect(verifyArgs[0]).toBe("Ed25519");
    expect(verifyArgs[1]).toEqual({ type: "public" });
  });

  // ---- (e) Tampered payload ----
  it("returns valid:false when crypto.subtle.verify returns false", async () => {
    importKeyStub.mockResolvedValue({ type: "public" });
    verifyStub.mockResolvedValue(false);

    const result = await verifyReceipt(JSON.stringify(makeReceipt()));

    expect(result.valid).toBe(false);
    expect(result.receipt).toBeDefined();
    expect(result.error).toBeUndefined();
  });

  // ---- (f) Corrupted base64 in signature ----
  it("returns error for corrupted base64 in signature", async () => {
    const result = await verifyReceipt(
      JSON.stringify(makeReceipt({ signature: "!!!not-base64!!!" })),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  // ---- (g) Corrupted base64 in publicKey ----
  it("returns error for corrupted base64 in public_key", async () => {
    const result = await verifyReceipt(
      JSON.stringify(makeReceipt({ public_key: "!!!not-base64!!!" })),
    );
    expect(result.valid).toBe(false);
    expect(result.error).toBeDefined();
  });

  // ---- (h) Ed25519 not supported ----
  it("returns Ed25519 not supported error when importKey throws", async () => {
    importKeyStub.mockRejectedValue(new Error("Ed25519 is not supported"));

    const result = await verifyReceipt(JSON.stringify(makeReceipt()));

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Ed25519 not supported/);
    expect(result.receipt).toBeDefined();
  });

  it("returns Ed25519 not supported error for Unrecognized algorithm", async () => {
    importKeyStub.mockRejectedValue(
      new Error("Unrecognized algorithm name"),
    );

    const result = await verifyReceipt(JSON.stringify(makeReceipt()));

    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Ed25519 not supported/);
  });

  it("returns generic error for non-Ed25519 crypto failures", async () => {
    importKeyStub.mockRejectedValue(new Error("Something else went wrong"));

    const result = await verifyReceipt(JSON.stringify(makeReceipt()));

    expect(result.valid).toBe(false);
    expect(result.error).toBe("Something else went wrong");
  });

  // ---- (i) Canonical JSON ordering ----
  it("produces the same verification regardless of field order", async () => {
    importKeyStub.mockResolvedValue({ type: "public" });

    // Capture the data buffer passed to verify() in each call
    const dataBuffers: ArrayBuffer[] = [];
    verifyStub.mockImplementation(
      (_algo: string, _key: unknown, _sig: ArrayBuffer, data: ArrayBuffer) => {
        dataBuffers.push(data);
        return Promise.resolve(true);
      },
    );

    const fields = {
      public_key: btoa("fake-ed25519-public-key-32by"),
      signature: btoa("fake-signature-bytes-here1234"),
      decision: "allow",
      action_type: "file_read",
      policy_hash: "sha256:abc123",
      timestamp: "2026-02-26T00:00:00Z",
    };

    // Order 1: natural order
    await verifyReceipt(JSON.stringify(fields));

    // Order 2: reversed key order
    const reversed: Record<string, unknown> = {};
    for (const key of Object.keys(fields).reverse()) {
      reversed[key] = (fields as Record<string, string>)[key];
    }
    await verifyReceipt(JSON.stringify(reversed));

    expect(dataBuffers).toHaveLength(2);

    // Both calls should have produced the same canonical payload
    const buf1 = new Uint8Array(dataBuffers[0]);
    const buf2 = new Uint8Array(dataBuffers[1]);
    expect(buf1).toEqual(buf2);
  });

  // ---- Edge cases ----
  it("handles receipt with missing optional fields", async () => {
    importKeyStub.mockResolvedValue({ type: "public" });
    verifyStub.mockResolvedValue(true);

    const { target: _t, guard: _g, ...receipt } = makeReceipt();

    const result = await verifyReceipt(JSON.stringify(receipt));
    expect(result.valid).toBe(true);
    expect(result.receipt!.target).toBeUndefined();
    expect(result.receipt!.guard).toBeUndefined();
  });

  it("handles non-Error throw from crypto", async () => {
    importKeyStub.mockRejectedValue("string error");

    const result = await verifyReceipt(JSON.stringify(makeReceipt()));
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Verification failed");
  });
});
