import { readFileSync } from "node:fs";
import { defineConfig } from "tsup";

const pkg = JSON.parse(readFileSync("./package.json", "utf-8"));

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  minify: false,
  noExternal: ["@clawdstrike/adapter-core"],
  external: ["@clawdstrike/wasm"],
  define: {
    __SDK_VERSION__: JSON.stringify(pkg.version),
  },
});
