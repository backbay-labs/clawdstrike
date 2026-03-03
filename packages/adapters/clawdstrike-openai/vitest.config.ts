import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

const ROOT = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@clawdstrike/claude": resolve(ROOT, "../clawdstrike-claude/src/index.ts"),
      "@clawdstrike/adapter-core": resolve(
        ROOT,
        "../clawdstrike-adapter-core/src/index.ts",
      ),
    },
  },
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
    },
  },
});
