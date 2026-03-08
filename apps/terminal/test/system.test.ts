import { afterEach, describe, expect, test } from "bun:test"
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { commandExists, resolveCommandPath } from "../src/system"

const originalPath = process.env.PATH
const tempDirs: string[] = []

afterEach(() => {
  process.env.PATH = originalPath
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()
    if (dir) {
      rmSync(dir, { recursive: true, force: true })
    }
  }
})

describe("system helpers", () => {
  test("resolveCommandPath ignores directories in PATH", () => {
    if (process.platform === "win32") {
      return
    }

    const tempDir = mkdtempSync(join(tmpdir(), "clawdstrike-system-test-"))
    tempDirs.push(tempDir)

    const fakeCommandDir = join(tempDir, "codex")
    mkdirSync(fakeCommandDir)
    chmodSync(fakeCommandDir, 0o755)

    process.env.PATH = tempDir

    expect(resolveCommandPath("codex")).toBeNull()
    expect(commandExists("codex")).toBe(false)
  })

  test("resolveCommandPath still returns executable files", () => {
    const tempDir = mkdtempSync(join(tmpdir(), "clawdstrike-system-test-"))
    tempDirs.push(tempDir)

    const fakeCommand = join(tempDir, "codex")
    writeFileSync(fakeCommand, "#!/bin/sh\nexit 0\n")
    chmodSync(fakeCommand, 0o755)

    process.env.PATH = tempDir

    expect(resolveCommandPath("codex")).toBe(fakeCommand)
    expect(commandExists("codex")).toBe(true)
  })
})
