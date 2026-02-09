import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

/**
 * Compute SHA-256 hash.
 * @param data - Input string or bytes
 * @returns 32-byte hash
 */
export function sha256(data: string | Uint8Array): Uint8Array {
  const input = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return nobleSha256(input);
}

/**
 * Compute Keccak-256 hash (Ethereum-compatible).
 * @param data - Input string or bytes
 * @returns 32-byte hash
 */
export function keccak256(data: string | Uint8Array): Uint8Array {
  const input = typeof data === "string" ? new TextEncoder().encode(data) : data;
  return keccak_256(input);
}

/**
 * Convert bytes to hex string (no 0x prefix).
 */
export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Convert hex string to bytes (handles optional 0x prefix).
 */
export function fromHex(hex: string): Uint8Array {
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(cleaned.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}
