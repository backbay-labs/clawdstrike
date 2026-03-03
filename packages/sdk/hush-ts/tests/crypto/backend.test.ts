import { describe, it, expect, afterEach } from "vitest";
import {
  getBackend,
  setBackend,
  initWasm,
  isWasmBackend,
  type CryptoBackend,
} from "../../src/crypto/backend";
import { createNobleBackend } from "../../src/crypto/noble-backend";

const initialBackend = getBackend();

// Reset backend after each test to avoid leaking state.
afterEach(() => {
  setBackend(initialBackend);
});

describe("getBackend", () => {
  it("returns a valid backend after setup", () => {
    const name = getBackend().name;
    expect(name === "wasm" || name === "noble").toBe(true);
  });
});

describe("setBackend", () => {
  it("switches active backend", () => {
    const nobleBackend = createNobleBackend();
    setBackend(nobleBackend);
    expect(getBackend().name).toBe("noble");
  });
});

describe("isWasmBackend", () => {
  it("returns false when noble is active", () => {
    setBackend(createNobleBackend());
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

describe("crypto operations", () => {
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

describe("optional wasm backend", () => {
  if (process.env.WASM_AVAILABLE !== "1") {
    it.skip("is skipped unless WASM_AVAILABLE=1", () => {
      // Environment-gated test to keep CI control in command-only mode.
    });
    return;
  }

  it("attempts to initialize the wasm backend", async () => {
    const ok = await initWasm();
    expect(ok).toBeTypeOf("boolean");
    if (ok) {
      expect(isWasmBackend()).toBe(true);
    }
  });
});
