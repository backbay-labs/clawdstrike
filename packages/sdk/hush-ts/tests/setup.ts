import { getWasmModule, initWasm, isWasmBackend } from "../src/crypto/backend";

// Try to initialize WASM.  When @clawdstrike/wasm is not installed (e.g. in
// CI without a prior WASM build step), fall back to noble and expose a flag
// so WASM-dependent test suites can skip gracefully.
const ok = await initWasm();
const wasmAvailable = ok && isWasmBackend();
const wasm = getWasmModule();
const wasmSpiderSenseAvailable =
  wasmAvailable && typeof wasm?.WasmSpiderSenseDetector === "function";
const wasmAdvancedAvailable =
  wasmAvailable &&
  typeof wasm?.WasmOutputSanitizer === "function" &&
  typeof wasm?.WasmJailbreakDetector === "function" &&
  typeof wasm?.WasmInstructionHierarchyEnforcer === "function" &&
  typeof wasm?.detect_prompt_injection === "function";

// biome-ignore lint/suspicious/noExplicitAny: vitest global injection
(globalThis as any).__WASM_AVAILABLE__ = wasmAvailable;
// biome-ignore lint/suspicious/noExplicitAny: vitest global injection
(globalThis as any).__WASM_ADVANCED_AVAILABLE__ = wasmAdvancedAvailable;
// biome-ignore lint/suspicious/noExplicitAny: vitest global injection
(globalThis as any).__WASM_SPIDER_SENSE_AVAILABLE__ = wasmSpiderSenseAvailable;

if (!wasmAvailable) {
  // biome-ignore lint/suspicious/noConsole: setup diagnostics
  console.warn(
    "[test setup] WASM crypto backend unavailable — falling back to noble (pure-JS). " +
      "WASM-dependent test suites will be skipped. Install @clawdstrike/wasm for full coverage.",
  );
} else if (!wasmAdvancedAvailable) {
  // biome-ignore lint/suspicious/noConsole: setup diagnostics
  console.warn(
    "[test setup] Advanced WASM APIs unavailable in installed @clawdstrike/wasm package. " +
      "Advanced WASM suites will be skipped.",
  );
} else if (!wasmSpiderSenseAvailable) {
  // biome-ignore lint/suspicious/noConsole: setup diagnostics
  console.warn(
    "[test setup] Spider-Sense WASM API unavailable in installed @clawdstrike/wasm package. " +
      "Spider-Sense WASM suites will be skipped.",
  );
}
