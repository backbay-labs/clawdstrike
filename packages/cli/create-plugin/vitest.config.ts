import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    root: import.meta.dirname,
    globals: true,
    environment: "node",
    include: ["tests/**/*.test.ts"],
  },
});
