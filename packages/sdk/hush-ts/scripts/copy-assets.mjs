import { cpSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, "..");
const src = path.join(ROOT, "src", "guards", "patterns", "s2bench-v1.json");
const outDir = path.join(ROOT, "dist", "guards", "patterns");
const dest = path.join(outDir, "s2bench-v1.json");

mkdirSync(outDir, { recursive: true });
cpSync(src, dest);
