import react from "@vitejs/plugin-react";
import { resolve } from "path";
import { defineConfig } from "vitest/config";

const SUPPRESSED_CONSOLE_PATTERNS = [
  "not wrapped in act(...)",
  "Not implemented: navigation to another Document",
  "[tauri-commands] get_mcp_status failed:",
  "[secure-store] Stronghold unavailable;",
  "[AgentSessionNode] terminal tile render error:",
  "ghostty exploded",
  "[fleet-client]",
  "[threat-intel-bootstrap]",
  "[swarm-store] Invalid persisted swarm data, using defaults",
  "[EnrichmentOrchestrator] Source bad-source failed",
] as const;

function shouldSuppressConsoleLog(log: string): boolean {
  return SUPPRESSED_CONSOLE_PATTERNS.some((pattern) => log.includes(pattern));
}

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/__tests__/**/*.test.ts", "src/**/__tests__/**/*.test.tsx"],
    setupFiles: ["./src/test/setup.ts"],
    css: true,
    onConsoleLog(log) {
      if (shouldSuppressConsoleLog(log)) {
        return false;
      }
    },
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/**/*.test.{ts,tsx}",
        "src/**/*.spec.{ts,tsx}",
        "src/test/**",
      ],
    },
  },
});
