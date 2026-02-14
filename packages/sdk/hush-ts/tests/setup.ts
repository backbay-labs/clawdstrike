import { initWasm, isWasmBackend } from "../src/crypto/backend";

// `npm run test:wasm` sets `WASM_AVAILABLE=1`. When enabled, we want the entire
// test suite to exercise the WASM crypto backend (and fail fast if it's missing).
if (process.env.WASM_AVAILABLE === "1") {
  const ok = await initWasm();
  if (!ok || !isWasmBackend()) {
    throw new Error(
      "WASM_AVAILABLE=1 but failed to initialize the WASM crypto backend. Ensure @clawdstrike/wasm is installed and compatible with this SDK."
    );
  }
}
