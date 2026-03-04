import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = path.resolve(TEST_DIR, "..");

describe("copy-assets script", () => {
  it("copies spider-sense builtin DB to runtime and compatibility dist paths", async () => {
    const scriptPath = path.join(PACKAGE_ROOT, "scripts", "copy-assets.mjs");
    const sourcePath = path.join(PACKAGE_ROOT, "src", "guards", "patterns", "s2bench-v1.json");
    const runtimePath = path.join(PACKAGE_ROOT, "dist", "patterns", "s2bench-v1.json");
    const compatibilityPath = path.join(
      PACKAGE_ROOT,
      "dist",
      "guards",
      "patterns",
      "s2bench-v1.json",
    );

    execFileSync(process.execPath, [scriptPath], { cwd: PACKAGE_ROOT, stdio: "inherit" });

    const source = (await readFile(sourcePath, "utf8")).trim();
    expect((await readFile(runtimePath, "utf8")).trim()).toBe(source);
    expect((await readFile(compatibilityPath, "utf8")).trim()).toBe(source);
  });
});
