'use client';

import type initWasm from './wasm-glue/hush_wasm';

type WasmExports = typeof import('./wasm-glue/hush_wasm');

let wasmModule: WasmExports | null = null;
let wasmPromise: Promise<WasmExports> | null = null;
let wasmError: Error | null = null;

export type WasmModule = WasmExports;

export async function getWasm(): Promise<WasmModule> {
  if (wasmModule) return wasmModule;
  if (wasmError) throw wasmError;
  if (!wasmPromise) {
    wasmPromise = (async () => {
      try {
        const mod = await import('./wasm-glue/hush_wasm');
        await (mod.default as typeof initWasm)('/wasm/hush_wasm_bg.wasm');
        wasmModule = mod;
        return mod;
      } catch (err) {
        wasmError = err instanceof Error ? err : new Error(String(err));
        wasmPromise = null; // Allow retry on next call
        throw wasmError;
      }
    })();
  }
  return wasmPromise;
}

export function getWasmError(): Error | null {
  return wasmError;
}

export function isWasmLoaded(): boolean {
  return wasmModule !== null;
}

export function resetWasmError(): void {
  wasmError = null;
  wasmPromise = null;
}
