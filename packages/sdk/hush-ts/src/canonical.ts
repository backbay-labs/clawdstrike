import { getWasmModule } from "./crypto/backend";
import { sha256, keccak256 } from "./crypto/hash";

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

/**
 * Serialize object to canonical JSON per RFC 8785 (JCS).
 *
 * Uses WASM when available, otherwise falls back to a pure-TS implementation.
 */
export function canonicalize(obj: JsonValue): string {
  // Validate and serialize in a single pass.
  const serialized = JSON.stringify(obj, (_, value) => {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error(`RFC 8785 does not support non-finite numbers: ${value}`);
    }
    return value;
  });
  const wasm = getWasmModule();
  if (wasm?.canonicalize_json) {
    return wasm.canonicalize_json(serialized);
  }
  return jcsSerialize(obj);
}

/** Pure-TS RFC 8785 serialization (sorted keys, ES6 number formatting). */
function jcsSerialize(value: JsonValue): string {
  if (value === null || typeof value === "boolean" || typeof value === "number") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(jcsSerialize).join(",") + "]";
  }
  // Object — sort keys lexicographically by UTF-16 code units (default JS sort).
  const keys = Object.keys(value).sort();
  const members = keys.map((k) => JSON.stringify(k) + ":" + jcsSerialize(value[k]));
  return "{" + members.join(",") + "}";
}

/**
 * Hash object using canonical JSON serialization.
 *
 * @param obj - Object to serialize and hash
 * @param algorithm - Hash algorithm ("sha256" or "keccak256")
 * @returns 32-byte hash
 */
export function canonicalHash(
  obj: JsonValue,
  algorithm: "sha256" | "keccak256" = "sha256",
): Uint8Array {
  if (algorithm !== "sha256" && algorithm !== "keccak256") {
    throw new Error(`Unknown algorithm: ${algorithm}`);
  }
  const canonical = canonicalize(obj);
  const bytes = new TextEncoder().encode(canonical);
  return algorithm === "sha256" ? sha256(bytes) : keccak256(bytes);
}
