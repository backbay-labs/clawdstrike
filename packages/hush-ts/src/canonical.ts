import { sha256, keccak256 } from "./crypto/hash";

type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/**
 * Serialize object to canonical JSON per RFC 8785 (JCS).
 *
 * - No whitespace between elements
 * - Object keys sorted lexicographically
 * - Unicode preserved (except control characters escaped)
 *
 * @param obj - Object to serialize
 * @returns Canonical JSON string
 * @throws If object contains non-finite numbers (NaN, Infinity)
 */
export function canonicalize(obj: JsonValue): string {
  if (obj === null) {
    return "null";
  }

  if (typeof obj === "boolean") {
    return obj ? "true" : "false";
  }

  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) {
      throw new Error("Non-finite numbers are not valid JSON");
    }
    // RFC 8785 references ECMAScript JSON number serialization rules.
    return JSON.stringify(obj);
  }

  if (typeof obj === "string") {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    const items = obj.map((item) => canonicalize(item));
    return "[" + items.join(",") + "]";
  }

  // Object: sort keys lexicographically
  const keys = Object.keys(obj).sort();
  const pairs = keys.map((key) => {
    const value = canonicalize(obj[key]);
    return JSON.stringify(key) + ":" + value;
  });
  return "{" + pairs.join(",") + "}";
}

/**
 * Hash object using canonical JSON serialization.
 *
 * @param obj - Object to serialize and hash
 * @param algorithm - Hash algorithm ("sha256" or "keccak256")
 * @returns 32-byte hash
 * @throws If algorithm is not supported
 */
export function canonicalHash(
  obj: JsonValue,
  algorithm: "sha256" | "keccak256" = "sha256"
): Uint8Array {
  const canonical = canonicalize(obj);
  const bytes = new TextEncoder().encode(canonical);

  switch (algorithm) {
    case "sha256":
      return sha256(bytes);
    case "keccak256":
      return keccak256(bytes);
    default:
      throw new Error(`Unknown algorithm: ${algorithm}`);
  }
}
