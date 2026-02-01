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
    expect(() => canonicalHash({ x: 1 }, "md5" as "sha256")).toThrow("Unknown algorithm");
  });
});
