import { describe, expect, it } from "vitest";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Clawdstrike } from "../src/clawdstrike";

interface ConformanceCheck {
  kind: string;
  path?: string;
  host?: string;
  port?: number;
  tool?: string;
  args?: Record<string, unknown>;
  diff?: string;
  expected_status: "allow" | "warn" | "deny";
  expected_guard?: string;
}

interface ConformanceVector {
  name: string;
  entry: string;
  files: Record<string, string>;
  checks: ConformanceCheck[];
}

async function runCheck(cs: Clawdstrike, check: ConformanceCheck) {
  switch (check.kind) {
    case "file_access":
      return cs.check("file_access", { path: check.path });
    case "network_egress":
      return cs.check("network_egress", { host: check.host, port: check.port });
    case "mcp_tool":
      return cs.check("mcp_tool", { tool: check.tool, args: check.args ?? {} });
    case "patch":
      return cs.check("patch", { path: check.path, diff: check.diff });
    default:
      throw new Error(`unsupported check kind: ${check.kind}`);
  }
}

describe("policy conformance vectors", () => {
  const HERE = path.dirname(fileURLToPath(import.meta.url));
  const REPO_ROOT = path.resolve(HERE, "../../../../");

  it("matches shared policy conformance vectors", async () => {
    const vectorsPath = path.join(REPO_ROOT, "fixtures/policy/conformance_vectors.json");
    const vectors = JSON.parse(fs.readFileSync(vectorsPath, "utf8")) as ConformanceVector[];

    for (const vector of vectors) {
      const dir = await fsp.mkdtemp(path.join(os.tmpdir(), `clawdstrike-ts-${vector.name}-`));
      for (const [filename, content] of Object.entries(vector.files)) {
        await fsp.writeFile(path.join(dir, filename), content);
      }

      const cs = await Clawdstrike.fromPolicy(path.join(dir, vector.entry));
      for (const check of vector.checks) {
        const decision = await runCheck(cs, check);
        expect(decision.status, `${vector.name}:${check.kind}`).toBe(check.expected_status);
        if (check.expected_guard) {
          expect(decision.guard, `${vector.name}:${check.kind}:guard`).toBe(check.expected_guard);
        }
      }
    }
  });
});
