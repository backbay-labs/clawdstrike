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
  test("resolveCommandPath ignores directories in PATH", async () => {
    if (process.platform === "win32") {
      return
    }

    const tempDir = mkdtempSync(join(tmpdir(), "clawdstrike-system-test-"))
    tempDirs.push(tempDir)

    const fakeCommandDir = join(tempDir, "codex")
    mkdirSync(fakeCommandDir)
    chmodSync(fakeCommandDir, 0o755)

    process.env.PATH = tempDir

    await expect(resolveCommandPath("codex")).resolves.toBeNull()
    await expect(commandExists("codex")).resolves.toBe(false)
  })

  test("resolveCommandPath still returns executable files", async () => {
    const tempDir = mkdtempSync(join(tmpdir(), "clawdstrike-system-test-"))
    tempDirs.push(tempDir)

    const fakeCommand = join(tempDir, "codex")
    writeFileSync(fakeCommand, "#!/bin/sh\nexit 0\n")
    chmodSync(fakeCommand, 0o755)

    process.env.PATH = tempDir

    await expect(resolveCommandPath("codex")).resolves.toBe(fakeCommand)
    await expect(commandExists("codex")).resolves.toBe(true)
  })
})
