/**
 * Config module tests
 *
 * Tests for project configuration loading, saving, detection, and schema validation.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import { join } from "path"
import { mkdtemp, rm, readFile } from "fs/promises"
import { tmpdir } from "os"
import { Config, type ProjectConfig } from "../src/config"

let testDir: string

beforeEach(async () => {
  testDir = await mkdtemp(join(tmpdir(), "clawdstrike-config-test-"))
})

afterEach(async () => {
  await rm(testDir, { recursive: true, force: true })
})

describe("Config.exists", () => {
  test("returns false when no config file exists", async () => {
    expect(await Config.exists(testDir)).toBe(false)
  })

  test("returns true after config is saved", async () => {
    const config: ProjectConfig = {
      schema_version: "1.0.0",
      sandbox: "inplace",
      adapters: {},
      git_available: false,
      project_id: "default",
    }
    await Config.save(testDir, config)
    expect(await Config.exists(testDir)).toBe(true)
  })
})

describe("Config.save and Config.load", () => {
  test("round-trips a minimal config", async () => {
    const config: ProjectConfig = {
      schema_version: "1.0.0",
      sandbox: "inplace",
      adapters: {},
      git_available: false,
      project_id: "default",
    }
    await Config.save(testDir, config)
    const loaded = await Config.load(testDir)
    expect(loaded).not.toBeNull()
    expect(loaded!.schema_version).toBe("1.0.0")
    expect(loaded!.sandbox).toBe("inplace")
    expect(loaded!.git_available).toBe(false)
    expect(loaded!.project_id).toBe("default")
  })

  test("round-trips a full config", async () => {
    const config: ProjectConfig = {
      schema_version: "1.0.0",
      sandbox: "worktree",
      toolchain: "claude",
      adapters: {
        claude: { available: true, version: "1.0.0" },
        codex: { available: false },
      },
      git_available: true,
      project_id: "my-project",
    }
    await Config.save(testDir, config)
    const loaded = await Config.load(testDir)
    expect(loaded).not.toBeNull()
    expect(loaded!.sandbox).toBe("worktree")
    expect(loaded!.toolchain).toBe("claude")
    expect(loaded!.adapters.claude.available).toBe(true)
    expect(loaded!.adapters.codex.available).toBe(false)
    expect(loaded!.git_available).toBe(true)
    expect(loaded!.project_id).toBe("my-project")
  })

  test("saves valid JSON to disk", async () => {
    const config: ProjectConfig = {
      schema_version: "1.0.0",
      sandbox: "tmpdir",
      adapters: {},
      git_available: false,
      project_id: "default",
    }
    await Config.save(testDir, config)
    const raw = await readFile(
      join(testDir, ".clawdstrike", "config.json"),
      "utf-8"
    )
    const parsed = JSON.parse(raw)
    expect(parsed.schema_version).toBe("1.0.0")
    expect(parsed.sandbox).toBe("tmpdir")
  })

  test("creates .clawdstrike directory if missing", async () => {
    const config: ProjectConfig = {
      schema_version: "1.0.0",
      sandbox: "inplace",
      adapters: {},
      git_available: false,
      project_id: "default",
    }
    await Config.save(testDir, config)
    expect(await Config.exists(testDir)).toBe(true)
  })
})

describe("Config.load", () => {
  test("returns null for missing config", async () => {
    const loaded = await Config.load(testDir)
    expect(loaded).toBeNull()
  })

  test("returns null for invalid JSON", async () => {
    const { mkdir, writeFile } = await import("fs/promises")
    await mkdir(join(testDir, ".clawdstrike"), { recursive: true })
    await writeFile(
      join(testDir, ".clawdstrike", "config.json"),
      "not json"
    )
    const loaded = await Config.load(testDir)
    expect(loaded).toBeNull()
  })

  test("returns null for invalid schema", async () => {
    const { mkdir, writeFile } = await import("fs/promises")
    await mkdir(join(testDir, ".clawdstrike"), { recursive: true })
    await writeFile(
      join(testDir, ".clawdstrike", "config.json"),
      JSON.stringify({ schema_version: "2.0.0", sandbox: "unknown" })
    )
    const loaded = await Config.load(testDir)
    expect(loaded).toBeNull()
  })
})

describe("Config.detect", () => {
  test("returns detection result with adapter info", async () => {
    const result = await Config.detect(testDir)
    expect(result).toBeDefined()
    expect(typeof result.git_available).toBe("boolean")
    expect(result.adapters).toBeDefined()
    expect(typeof result.recommended_sandbox).toBe("string")
    expect(["inplace", "worktree", "tmpdir"]).toContain(
      result.recommended_sandbox
    )
  })

  test("recommends worktree when git is available", async () => {
    // This test depends on whether we're in a git repo
    const result = await Config.detect(process.cwd())
    if (result.git_available) {
      expect(result.recommended_sandbox).toBe("worktree")
    }
  })

  test("recommends inplace when git is not available", async () => {
    // tmpdir is guaranteed to not be a git repo
    const result = await Config.detect(testDir)
    if (!result.git_available) {
      expect(result.recommended_sandbox).toBe("inplace")
    }
  })
})

describe("Config.inspectProject", () => {
  test("recommends inplace outside git", async () => {
    const result = await Config.inspectProject(testDir)
    expect(result.git_available).toBe(false)
    expect(result.recommended_sandbox).toBe("inplace")
  })

  test("recommends worktree when .git marker exists", async () => {
    const { mkdir } = await import("fs/promises")
    await mkdir(join(testDir, ".git"))

    const result = await Config.inspectProject(testDir)
    expect(result.git_available).toBe(true)
    expect(result.recommended_sandbox).toBe("worktree")
  })
})
