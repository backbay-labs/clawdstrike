/**
 * Pluggable crypto backend interface.
 *
 * Default: noble (pure-JS, always available).
 * Optional: WASM (hush-core via @clawdstrike/wasm), auto-initialized on demand.
 * `initWasm()` remains available for optional startup prewarm.
 */

import { createNobleBackend } from "./noble-backend";
import { createWasmBackend } from "./wasm-backend";
import type { HushWasmModule } from "../types/wasm.js";

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
 * Sync WASM-only APIs may also populate this via `ensureWasmSync()`.
 * Detection code (JailbreakDetector, OutputSanitizer, etc.) accesses
 * this via `getWasmModule()` rather than re-importing `@clawdstrike/wasm`.
 */
let wasmModule: HushWasmModule | null = null;
let wasmInitPromise: Promise<boolean> | null = null;

/**
 * Return the raw WASM module, or `null` if initialization has not happened
 * yet (or failed).
 */
export function getWasmModule(): HushWasmModule | null {
  return wasmModule;
}

function isCompatibleWasmModule(wasm: unknown): wasm is HushWasmModule {
  // Keep this in sync with `packages/sdk/hush-ts/src/crypto/wasm-backend.ts`.
  const required = [
    "hash_sha256_bytes",
    "hash_keccak256_bytes",
    "generate_keypair",
    "sign_ed25519",
    "verify_ed25519",
    "public_key_from_private",
  ] as const;

  if (!wasm || typeof wasm !== "object") return false;
  for (const key of required) {
    if (typeof (wasm as Record<string, unknown>)[key] !== "function") return false;
  }
  return true;
}

// Some package shapes expose function stubs before the underlying wasm bytes
// are initialized. This cheap probe avoids activating those broken modules.
function isOperationalWasmModule(wasm: unknown): wasm is HushWasmModule {
  if (!isCompatibleWasmModule(wasm)) {
    return false;
  }
  try {
    const digest = wasm.hash_sha256_bytes(new Uint8Array());
    return digest instanceof Uint8Array && digest.length === 32;
  } catch {
    return false;
  }
}

// Some WASM bundles are published as CJS and are surfaced under `default`
// when imported from ESM; normalize to a plain function-bearing object.
function normalizeWasmModule(wasm: unknown): HushWasmModule | unknown {
  if (isCompatibleWasmModule(wasm)) return wasm;
  const nested = (wasm as { default?: unknown } | null | undefined)?.default;
  if (isCompatibleWasmModule(nested)) return nested;
  return wasm;
}

// Node require type is not available in browser builds; widen via unknown.
type NodeRequire = ((id: string) => unknown) & {
  resolve?: (id: string) => string;
};

interface NodeProcessLike {
  getBuiltinModule?: (name: string) => unknown;
}

interface NodeModuleLike {
  createRequire?: (filename: string | URL) => NodeRequire;
}

function getBuiltinModuleFn(): ((name: string) => unknown) | null {
  // Prefer process.getBuiltinModule so we can create require() in ESM without
  // statically importing node:module (which breaks browser bundlers).
  const proc = (globalThis as { process?: NodeProcessLike }).process;
  const getBuiltin = proc?.getBuiltinModule;
  return typeof getBuiltin === "function" ? getBuiltin.bind(proc) : null;
}

function nodeRequire(): NodeRequire | null {
  const getBuiltin = getBuiltinModuleFn();
  if (!getBuiltin) return null;
  try {
    const mod = (getBuiltin("node:module") ?? getBuiltin("module")) as NodeModuleLike | null;
    if (mod && typeof mod.createRequire === "function") {
      return mod.createRequire(import.meta.url);
    }
  } catch {
    // Node builtin module not accessible in this runtime.
  }
  return null;
}

function nodeBuiltinModule(name: string): unknown {
  const getBuiltin = getBuiltinModuleFn();
  if (!getBuiltin) return null;
  try {
    return getBuiltin(name);
  } catch {
    return null;
  }
}

interface FsLike {
  readFileSync(path: string): Uint8Array;
}

interface PathLike {
  join(...parts: string[]): string;
  dirname(p: string): string;
}

// Older @clawdstrike/wasm builds require explicit initSync(wasmBytes) in Node.
// Attempt that path before giving up on module activation.
function tryLegacyInitSync(
  requireFn: NodeRequire,
  imported: unknown,
): boolean {
  type WithInitSync = { initSync?: (args: { module: Uint8Array }) => unknown };
  const importedAsObj = (imported ?? {}) as WithInitSync & { default?: WithInitSync };
  const initSync =
    typeof importedAsObj.initSync === "function"
      ? importedAsObj.initSync
      : typeof importedAsObj.default?.initSync === "function"
        ? importedAsObj.default!.initSync!
        : null;
  if (!initSync || typeof requireFn.resolve !== "function") {
    return false;
  }

  const fs = (nodeBuiltinModule("node:fs") ?? nodeBuiltinModule("fs")) as FsLike | null;
  const path = (nodeBuiltinModule("node:path") ?? nodeBuiltinModule("path")) as PathLike | null;
  if (typeof fs?.readFileSync !== "function" || typeof path?.join !== "function") {
    return false;
  }

  try {
    const pkgJsonPath = requireFn.resolve("@clawdstrike/wasm/package.json");
    const wasmPath = path.join(path.dirname(pkgJsonPath), "hush_wasm_bg.wasm");
    const wasmBytes = fs.readFileSync(wasmPath);
    initSync({ module: wasmBytes });
    return true;
  } catch {
    return false;
  }
}

function activateWasmModule(wasm: unknown): boolean {
  const normalized = normalizeWasmModule(wasm);
  if (!isOperationalWasmModule(normalized)) {
    return false;
  }
  wasmModule = normalized;
  currentBackend = createWasmBackend(normalized);
  return true;
}

function initializeWasmSync(): boolean {
  if (wasmModule && isWasmBackend()) {
    return true;
  }
  if (wasmModule && !isWasmBackend()) {
    currentBackend = createWasmBackend(wasmModule);
    return true;
  }

  const requireFn = nodeRequire();
  if (!requireFn) {
    return false;
  }

  const candidates = [
    "@clawdstrike/wasm/pkg-node/hush_wasm.js",
    "@clawdstrike/wasm",
  ] as const;

  for (const specifier of candidates) {
    try {
      const imported = requireFn(specifier);
      if (activateWasmModule(imported)) {
        return true;
      }
      if (tryLegacyInitSync(requireFn, imported) && activateWasmModule(imported)) {
        return true;
      }
    } catch {
      // Try next candidate.
    }
  }
  return false;
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

async function initializeWasm(): Promise<boolean> {
  const candidates = [
    // Node fast-path first (sync fs-backed loader, no fetch()).
    "@clawdstrike/wasm/pkg-node/hush_wasm.js",
    // Browser/web target fallback.
    "@clawdstrike/wasm",
  ] as const;

  for (const specifier of candidates) {
    try {
      // Dynamic ESM/CJS namespace — `as unknown` because the static import-type
      // graph cannot guarantee the optional `@clawdstrike/wasm` shape.
      const imported = (await import(specifier as string)) as unknown;
      // Web-target bundles expose an async default init function.
      const importedDefault = (imported as { default?: unknown }).default;
      if (typeof importedDefault === "function") {
        await (importedDefault as () => unknown)();
      }
      if (activateWasmModule(imported)) {
        return true;
      }
      const requireFn = nodeRequire();
      if (requireFn && tryLegacyInitSync(requireFn, imported) && activateWasmModule(imported)) {
        return true;
      }
    } catch {
      // Try next candidate.
    }
  }

  return false;
}

/**
 * Attempt to load the WASM crypto backend from `@clawdstrike/wasm`.
 * If the package is not installed, silently falls back to noble and returns `false`.
 *
 * @returns `true` if WASM was loaded successfully, `false` otherwise.
 */
export async function initWasm(): Promise<boolean> {
  if (initializeWasmSync()) {
    return true;
  }

  if (wasmModule && isWasmBackend()) {
    return true;
  }
  if (wasmModule && !isWasmBackend()) {
    const { createWasmBackend } = await import("./wasm-backend");
    currentBackend = createWasmBackend(wasmModule);
    return true;
  }

  if (wasmInitPromise === null) {
    wasmInitPromise = initializeWasm();
  }
  return wasmInitPromise;
}

/**
 * Ensure WASM is available for APIs that require WASM-only exports.
 *
 * Throws when WASM cannot be initialized.
 */
export async function ensureWasm(): Promise<void> {
  const ok = await initWasm();
  if (!ok) {
    throw new Error(
      "WASM backend unavailable. Install @clawdstrike/wasm.",
    );
  }
}

/**
 * Ensure WASM is available for synchronous WASM-only APIs.
 *
 * This path attempts Node sync loading first and throws if unavailable.
 */
export function ensureWasmSync(): void {
  if (initializeWasmSync()) {
    return;
  }
  throw new Error(
    "WASM backend unavailable. Install @clawdstrike/wasm for this runtime.",
  );
}
