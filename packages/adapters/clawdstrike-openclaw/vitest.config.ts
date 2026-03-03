import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const ROOT = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@clawdstrike/adapter-core": resolve(
        ROOT,
        "../clawdstrike-adapter-core/src/index.ts",
      ),
      "@clawdstrike/policy": resolve(ROOT, "../../policy/clawdstrike-policy/src/index.ts"),
    },
  },
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.ts", "tests/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
    },
  },
});
