import { cpSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const src = path.join(ROOT, "src", "guards", "patterns", "s2bench-v1.json");
const outDirs = [
  // Runtime lookup used by bundled dist/index.js (`new URL("./patterns/...", import.meta.url)`).
  path.join(ROOT, "dist", "patterns"),
  // Keep legacy location for compatibility with existing package layouts/tests.
  path.join(ROOT, "dist", "guards", "patterns"),
];

for (const outDir of outDirs) {
  const dest = path.join(outDir, "s2bench-v1.json");
  mkdirSync(outDir, { recursive: true });
  cpSync(src, dest);
}
