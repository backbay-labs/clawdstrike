import { describe, it, expect } from "vitest";
import { sha256, keccak256, toHex } from "../../src/crypto/hash";

describe("crypto determinism (known test vectors)", () => {
  it("SHA-256 of empty string", () => {
    const hash = sha256("");
    expect(toHex(hash)).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
  });

  it("SHA-256 of 'hello'", () => {
    const hash = sha256("hello");
    expect(toHex(hash)).toBe(
      "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
  });

  it("SHA-256 of 'hello world'", () => {
    const hash = sha256("hello world");
    expect(toHex(hash)).toBe(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
  });

  it("Keccak-256 of empty string", () => {
    const hash = keccak256("");
    expect(toHex(hash)).toBe(
      "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
  });

  it("Keccak-256 of 'hello'", () => {
    const hash = keccak256("hello");
    expect(toHex(hash)).toBe(
      "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    );
  });

  it("SHA-256 produces 32-byte Uint8Array", () => {
    const hash = sha256("test");
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });

  it("Keccak-256 produces 32-byte Uint8Array", () => {
    const hash = keccak256("test");
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });

  it("SHA-256 binary input matches string input", () => {
    const fromStr = sha256("hello");
    const fromBytes = sha256(new TextEncoder().encode("hello"));
    expect(toHex(fromStr)).toBe(toHex(fromBytes));
  });

  it("Keccak-256 binary input matches string input", () => {
    const fromStr = keccak256("hello");
    const fromBytes = keccak256(new TextEncoder().encode("hello"));
    expect(toHex(fromStr)).toBe(toHex(fromBytes));
  });
});
