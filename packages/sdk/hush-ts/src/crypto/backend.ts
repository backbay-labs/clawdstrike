/**
 * Pluggable crypto backend interface.
 *
 * Default: noble (pure-JS, always available).
 * Optional: WASM (hush-core via @clawdstrike/wasm, opt-in via `initWasm()`).
 */

import { createNobleBackend } from "./noble-backend";

export interface CryptoBackend {
  readonly name: "wasm" | "noble";
  sha256(data: Uint8Array): Uint8Array;
  keccak256(data: Uint8Array): Uint8Array;
  generateKeypair(): Promise<{ privateKey: Uint8Array; publicKey: Uint8Array }>;
  signMessage(message: Uint8Array, privateKey: Uint8Array): Promise<Uint8Array>;
  verifySignature(
    message: Uint8Array,
    signature: Uint8Array,
    publicKey: Uint8Array
  ): Promise<boolean>;
  publicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array>;
}

let currentBackend: CryptoBackend = createNobleBackend();

/**
 * Get the current crypto backend.
 */
export function getBackend(): CryptoBackend {
  return currentBackend;
}

/**
 * Override the crypto backend. Mainly for testing; prefer `initWasm()` for production.
 */
export function setBackend(backend: CryptoBackend): void {
  currentBackend = backend;
}

/**
 * Returns true if the active backend is the WASM backend.
 */
export function isWasmBackend(): boolean {
  return currentBackend.name === "wasm";
}

/**
 * Attempt to load the WASM crypto backend from `@clawdstrike/wasm`.
 * If the package is not installed, silently falls back to noble and returns `false`.
 *
 * @returns `true` if WASM was loaded successfully, `false` otherwise.
 */
export async function initWasm(): Promise<boolean> {
  try {
    const { createWasmBackend } = await import("./wasm-backend");
    const wasm = await import("@clawdstrike/wasm" as string);
    currentBackend = createWasmBackend(wasm);
    return true;
  } catch {
    // WASM not available — noble remains active
    return false;
  }
}
