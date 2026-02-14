import { describe, it, expect, afterEach } from "vitest";
import {
  getBackend,
  setBackend,
  isWasmBackend,
  type CryptoBackend,
} from "../../src/crypto/backend";
import { createNobleBackend } from "../../src/crypto/noble-backend";

// Reset backend to noble after each test to avoid leaking state
afterEach(() => {
  setBackend(createNobleBackend());
});

describe("getBackend", () => {
  it("returns noble by default", () => {
    const backend = getBackend();
    expect(backend.name).toBe("noble");
  });
});

describe("setBackend", () => {
  it("switches active backend", () => {
    const mockBackend: CryptoBackend = {
      name: "wasm",
      sha256: () => new Uint8Array(32),
      keccak256: () => new Uint8Array(32),
      generateKeypair: async () => ({
        privateKey: new Uint8Array(32),
        publicKey: new Uint8Array(32),
      }),
      signMessage: async () => new Uint8Array(64),
      verifySignature: async () => true,
      publicKeyFromPrivate: async () => new Uint8Array(32),
    };

    setBackend(mockBackend);
    expect(getBackend().name).toBe("wasm");
  });
});

describe("isWasmBackend", () => {
  it("returns false when noble is active", () => {
    expect(isWasmBackend()).toBe(false);
  });

  it("returns true when a wasm-named backend is active", () => {
    const mockBackend: CryptoBackend = {
      name: "wasm",
      sha256: () => new Uint8Array(32),
      keccak256: () => new Uint8Array(32),
      generateKeypair: async () => ({
        privateKey: new Uint8Array(32),
        publicKey: new Uint8Array(32),
      }),
      signMessage: async () => new Uint8Array(64),
      verifySignature: async () => true,
      publicKeyFromPrivate: async () => new Uint8Array(32),
    };

    setBackend(mockBackend);
    expect(isWasmBackend()).toBe(true);
  });
});

describe("noble backend crypto operations", () => {
  it("sha256 produces 32-byte output", () => {
    const data = new TextEncoder().encode("hello");
    const hash = getBackend().sha256(data);
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });

  it("keccak256 produces 32-byte output", () => {
    const data = new TextEncoder().encode("hello");
    const hash = getBackend().keccak256(data);
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });

  it("generateKeypair returns 32-byte keys", async () => {
    const { privateKey, publicKey } = await getBackend().generateKeypair();
    expect(privateKey.length).toBe(32);
    expect(publicKey.length).toBe(32);
  });

  it("sign + verify roundtrip", async () => {
    const backend = getBackend();
    const { privateKey, publicKey } = await backend.generateKeypair();
    const message = new TextEncoder().encode("test message");
    const signature = await backend.signMessage(message, privateKey);
    expect(signature.length).toBe(64);

    const valid = await backend.verifySignature(message, signature, publicKey);
    expect(valid).toBe(true);
  });

  it("publicKeyFromPrivate matches generateKeypair", async () => {
    const backend = getBackend();
    const { privateKey, publicKey } = await backend.generateKeypair();
    const derived = await backend.publicKeyFromPrivate(privateKey);
    expect(derived).toEqual(publicKey);
  });
});
