import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { canonicalize, canonicalHash } from "../src/canonical";
import { toHex } from "../src/crypto/hash";

describe("canonicalize", () => {
  const HERE = path.dirname(fileURLToPath(import.meta.url));
  const REPO_ROOT = path.resolve(HERE, "../../..");

  it("matches repo golden vectors (RFC 8785)", () => {
    const vectorsPath = path.join(REPO_ROOT, "fixtures/canonical/jcs_vectors.json");
    const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8")) as Array<{
      name: string;
      input: unknown;
      expected: string;
    }>;

    for (const v of vectors) {
      expect(canonicalize(v.input as Parameters<typeof canonicalize>[0]), v.name).toBe(
        v.expected
      );
    }
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
