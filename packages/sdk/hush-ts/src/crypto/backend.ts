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
    publicKey: Uint8Array,
  ): Promise<boolean>;
  publicKeyFromPrivate(privateKey: Uint8Array): Promise<Uint8Array>;
}

let currentBackend: CryptoBackend = createNobleBackend();

/**
 * Raw WASM module reference, stored when `initWasm()` succeeds.
 * Detection code (JailbreakDetector, OutputSanitizer, etc.) accesses
 * this via `getWasmModule()` rather than re-importing `@clawdstrike/wasm`.
 */
// biome-ignore lint/suspicious/noExplicitAny: WASM module shape is dynamic
let wasmModule: any = null;

/**
 * Return the raw WASM module, or `null` if `initWasm()` has not been called
 * (or failed).
 */
// biome-ignore lint/suspicious/noExplicitAny: WASM module shape is dynamic
export function getWasmModule(): any {
  return wasmModule;
}

function isCompatibleWasmModule(wasm: unknown): boolean {
  // Keep this in sync with `packages/sdk/hush-ts/src/crypto/wasm-backend.ts`.
  const required = [
    "hash_sha256_bytes",
    "hash_keccak256_bytes",
    "generate_keypair",
    "sign_ed25519",
    "verify_ed25519",
    "public_key_from_private",
  ] as const;

  for (const key of required) {
    if (typeof (wasm as any)?.[key] !== "function") return false;
  }
  return true;
}

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
    // The web target requires calling the default export (init) to instantiate
    // the WASM module before any other exports are usable.
    if (typeof wasm.default === "function") {
      await wasm.default();
    }
    if (!isCompatibleWasmModule(wasm)) {
      // The package is installed but too old / incompatible.
      return false;
    }
    wasmModule = wasm;
    currentBackend = createWasmBackend(wasm);
    return true;
  } catch {
    // WASM not available — noble remains active
    return false;
  }
}
