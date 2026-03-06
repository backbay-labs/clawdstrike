import { afterEach, describe, expect, test } from "bun:test"
import * as fs from "node:fs/promises"
import * as os from "node:os"
import * as path from "node:path"
import {
  extractHuntEnvelopeData,
  findRepoHuntBinary,
  resolveDefaultWatchRules,
  resolveHuntBinary,
  spawnHuntStream,
} from "../src/hunt/bridge"
import { normalizeScanResults } from "../src/hunt/bridge-scan"

const HUNT_BINARY_ENV = "CLAWDSTRIKE_TUI_HUNT_BINARY"

async function writeExecutableScript(dir: string, name: string, contents: string): Promise<string> {
  const scriptPath = path.join(dir, name)
  await fs.writeFile(scriptPath, contents, { mode: 0o755 })
  await fs.chmod(scriptPath, 0o755)
  return scriptPath
}

afterEach(() => {
  delete process.env[HUNT_BINARY_ENV]
})

describe("hunt bridge", () => {
  test("finds a repo-built hunt binary from a nested path", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-hunt-bridge-"))
    const nestedDir = path.join(tempDir, "apps", "terminal")
    const binaryPath = path.join(tempDir, "target", "debug", process.platform === "win32" ? "clawdstrike.exe" : "clawdstrike")

    await fs.mkdir(path.dirname(binaryPath), { recursive: true })
    await fs.mkdir(nestedDir, { recursive: true })
    await fs.writeFile(binaryPath, "")

    expect(findRepoHuntBinary(nestedDir)).toBe(binaryPath)

    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test("prefers an explicit hunt binary override", () => {
    process.env[HUNT_BINARY_ENV] = "/tmp/custom-clawdstrike"
    expect(resolveHuntBinary("/tmp/project")).toBe("/tmp/custom-clawdstrike")
  })

  test("uses project rules before falling back to bundled defaults", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-watch-rules-"))
    const rulesDir = path.join(tempDir, ".clawdstrike", "rules")
    const localRule = path.join(rulesDir, "custom.yaml")

    await fs.mkdir(rulesDir, { recursive: true })
    await fs.writeFile(localRule, "schema: test\n")

    expect(resolveDefaultWatchRules(tempDir)).toEqual([localRule])

    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test("falls back to the bundled default watch rule", () => {
    const rules = resolveDefaultWatchRules(path.join(os.tmpdir(), "clawdstrike-no-rules"))
    expect(rules.length).toBeGreaterThan(0)
    expect(rules[0]).toEndWith(path.join("src", "hunt", "rules", "default-watch.yaml"))
  })

  test("unwraps hunt command envelope payloads", () => {
    const payload = extractHuntEnvelopeData<{ events: string[] }>({
      version: 1,
      command: "hunt timeline",
      exit_code: 0,
      data: { events: ["a", "b"] },
    })

    expect(payload).toEqual({ events: ["a", "b"] })
    expect(extractHuntEnvelopeData<string[]>(["legacy"])).toEqual(["legacy"])
  })

  test("waits for stdout consumption before surfacing stream errors", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-watch-stream-"))
    const scriptPath = await writeExecutableScript(
      tempDir,
      "fake-clawdstrike",
      `#!/usr/bin/env bash
set -euo pipefail
printf 'line one\\n'
printf 'line two\\n'
`,
    )

    process.env[HUNT_BINARY_ENV] = scriptPath

    const errorPromise = new Promise<string>((resolve) => {
      spawnHuntStream(
        ["watch"],
        () => {},
        (error) => resolve(error),
      )
    })

    await expect(errorPromise).resolves.toContain("line two")
    await fs.rm(tempDir, { recursive: true, force: true })
  })

  test("normalizes scan results from the hunt CLI envelope shape", () => {
    const normalized = normalizeScanResults([
      {
        client: "cursor",
        path: "/tmp/mcp.json",
        issues: [
          {
            severity: "warning",
            code: "path_warning",
            message: "Path-level issue",
          },
        ],
        servers: [
          {
            name: "blender",
            server: {
              command: "/usr/local/bin/blender-mcp",
              args: ["--stdio"],
              env: { MODE: "dev" },
            },
            signature: {
              metadata: {
                serverInfo: {
                  name: "BlenderMCP",
                  version: "1.0.0",
                },
              },
              tools: [
                {
                  name: "search_blender_docs",
                  description: "Search docs",
                  inputSchema: { type: "object" },
                },
              ],
              prompts: [{ name: "asset_creation_strategy" }],
              resources: [{ uri: "resource://scene" }],
            },
            issues: [],
            policy_violations: [],
          },
        ],
        error: {
          category: "file_not_found",
          exception: "FileNotFoundConfig",
          message: "missing",
        },
      },
    ])

    expect(normalized[0].client).toBe("cursor")
    expect(normalized[0].issues).toHaveLength(1)
    expect(normalized[0].servers[0].command).toBe("/usr/local/bin/blender-mcp")
    expect(normalized[0].servers[0].signature?.tools[0].input_schema).toEqual({ type: "object" })
    expect(normalized[0].errors[0]?.error).toContain("file_not_found")
    expect(normalized[0].servers[0].error).toBeUndefined()
  })
})
