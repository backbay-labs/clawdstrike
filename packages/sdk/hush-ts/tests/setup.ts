import { initWasm, isWasmBackend } from "../src/crypto/backend";

// Try to initialize WASM.  When @clawdstrike/wasm is not installed (e.g. in
// CI without a prior WASM build step), fall back to noble and expose a flag
// so WASM-dependent test suites can skip gracefully.
const ok = await initWasm();
const wasmAvailable = ok && isWasmBackend();

// biome-ignore lint/suspicious/noExplicitAny: vitest global injection
(globalThis as any).__WASM_AVAILABLE__ = wasmAvailable;

if (!wasmAvailable) {
  // biome-ignore lint/suspicious/noConsole: setup diagnostics
  console.warn(
    "[test setup] WASM crypto backend unavailable — falling back to noble (pure-JS). " +
      "WASM-dependent test suites will be skipped. Install @clawdstrike/wasm for full coverage.",
  );
}
