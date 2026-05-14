import { chmodSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const workbenchDir = join(scriptDir, "..");
const mcpEntry = join(workbenchDir, "mcp-server", "index.ts");
const bundledBinary = join(
  workbenchDir,
  "src-tauri",
  "resources",
  "bin",
  process.platform === "win32" ? "workbench-mcp.exe" : "workbench-mcp",
);
const bunExecutable = process.execPath || "bun";

function runStep(label: string, args: string[], cwd = workbenchDir) {
  console.log(`[tauri:prepare] ${label}`);
  const result = spawnSync(bunExecutable, args, {
    cwd,
    env: process.env,
    stdio: "inherit",
  });

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

mkdirSync(dirname(bundledBinary), { recursive: true });

runStep("building frontend", ["run", "build"]);
runStep("compiling bundled MCP sidecar", [
  "build",
  mcpEntry,
  "--compile",
  "--outfile",
  bundledBinary,
]);

if (process.platform !== "win32") {
  chmodSync(bundledBinary, 0o755);
}
