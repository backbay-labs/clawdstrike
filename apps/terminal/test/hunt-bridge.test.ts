import { afterEach, describe, expect, test } from "bun:test"
import * as fs from "node:fs/promises"
import * as os from "node:os"
import * as path from "node:path"
import { findRepoHuntBinary, resolveDefaultWatchRules, resolveHuntBinary } from "../src/hunt/bridge"

const HUNT_BINARY_ENV = "CLAWDSTRIKE_TUI_HUNT_BINARY"

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
})
