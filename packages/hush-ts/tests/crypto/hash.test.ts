import { describe, it, expect } from "vitest";
import { sha256, keccak256, toHex, fromHex } from "../../src/crypto/hash";

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
