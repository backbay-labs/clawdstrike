import { initWasm, isWasmBackend } from "@clawdstrike/sdk";

const ok = await initWasm();
if (!ok || !isWasmBackend()) {
  throw new Error(
    "Failed to initialize WASM backend. Ensure @clawdstrike/wasm is installed.",
  );
}
