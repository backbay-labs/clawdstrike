/**
 * CLI tests
 *
 * Tests for the clawdstrike command-line interface.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs/promises"
import * as path from "node:path"
import * as os from "node:os"
import { parseCliArgs } from "../src/cli"

// Create temp directory for tests
let tempDir: string

beforeEach(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-cli-test-"))
})

afterEach(async () => {
  await fs.rm(tempDir, { recursive: true, force: true })
})

describe("CLI Argument Parsing", () => {
  // Save original argv
  const originalArgv = process.argv

  afterEach(() => {
    process.argv = originalArgv
  })

  test("parses help command", () => {
    process.argv = ["bun", "clawdstrike", "help"]
    const { command, args } = parseCliArgs()
    expect(command).toBe("help")
    expect(args).toEqual([])
  })

  test("parses version flag", () => {
    process.argv = ["bun", "clawdstrike", "--version"]
    const result = parseCliArgs()
    expect(result.options.version).toBe(true)
  })

  test("parses dispatch command with prompt", () => {
    process.argv = ["bun", "clawdstrike", "dispatch", "Fix", "the", "bug"]
    const { command, args } = parseCliArgs()
    expect(command).toBe("dispatch")
    expect(args).toEqual(["Fix", "the", "bug"])
  })

  test("parses dispatch with toolchain option", () => {
    process.argv = ["bun", "clawdstrike", "dispatch", "-t", "claude", "Fix bug"]
    const { command, options, args } = parseCliArgs()
    expect(command).toBe("dispatch")
    expect(options.toolchain).toBe("claude")
    expect(args).toContain("Fix bug")
  })

  test("parses gate command with gates", () => {
    process.argv = ["bun", "clawdstrike", "gate", "pytest", "mypy", "ruff"]
    const { command, args } = parseCliArgs()
    expect(command).toBe("gate")
    expect(args).toEqual(["pytest", "mypy", "ruff"])
  })

  test("parses speculate with strategy", () => {
    process.argv = ["bun", "clawdstrike", "speculate", "-s", "best_score", "Refactor"]
    const { command, options, args } = parseCliArgs()
    expect(command).toBe("speculate")
    expect(options.strategy).toBe("best_score")
    expect(args).toContain("Refactor")
  })

  test("parses beads subcommand", () => {
    process.argv = ["bun", "clawdstrike", "beads", "list"]
    const { command, args } = parseCliArgs()
    expect(command).toBe("beads")
    expect(args).toEqual(["list"])
  })

  test("parses json flag", () => {
    process.argv = ["bun", "clawdstrike", "status", "--json"]
    const { command, options } = parseCliArgs()
    expect(command).toBe("status")
    expect(options.json).toBe(true)
  })

  test("parses short json flag", () => {
    process.argv = ["bun", "clawdstrike", "status", "-j"]
    const { options } = parseCliArgs()
    expect(options.json).toBe(true)
  })

  test("parses cwd option", () => {
    process.argv = ["bun", "clawdstrike", "gate", "--cwd", "/some/path"]
    const { options } = parseCliArgs()
    expect(options.cwd).toBe("/some/path")
  })

  test("parses project option", () => {
    process.argv = ["bun", "clawdstrike", "dispatch", "-p", "my-project", "task"]
    const { options } = parseCliArgs()
    expect(options.project).toBe("my-project")
  })

  test("parses timeout option", () => {
    process.argv = ["bun", "clawdstrike", "dispatch", "--timeout", "60000", "task"]
    const { options } = parseCliArgs()
    expect(options.timeout).toBe(60000)
  })

  test("defaults to empty command (TUI) when no args", () => {
    process.argv = ["bun", "clawdstrike"]
    const { command } = parseCliArgs()
    expect(command).toBe("")
  })
})

describe("CLI Integration", () => {
  test("help command runs without error", async () => {
    const proc = Bun.spawn(["bun", "run", "./src/cli/index.ts", "help"], {
      cwd: process.cwd(),
      stdout: "pipe",
      stderr: "pipe",
    })

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    expect(stdout).toContain("clawdstrike")
    expect(stdout).toContain("dispatch")
    expect(stdout).toContain("speculate")
  })

  test("version command outputs version", async () => {
    const proc = Bun.spawn(["bun", "run", "./src/cli/index.ts", "version"], {
      cwd: process.cwd(),
      stdout: "pipe",
      stderr: "pipe",
    })

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    expect(stdout).toContain("0.1.0")
  })

  test("--version flag outputs version", async () => {
    const proc = Bun.spawn(["bun", "run", "./src/cli/index.ts", "--version"], {
      cwd: process.cwd(),
      stdout: "pipe",
      stderr: "pipe",
    })

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    expect(stdout).toContain("0.1.0")
  })

  test("status command shows kernel status", async () => {
    const proc = Bun.spawn(
      ["bun", "run", "./src/cli/index.ts", "status", "--cwd", tempDir],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    expect(stdout).toContain("clawdstrike Status")
    expect(stdout).toContain("Version")
    expect(stdout).toContain("0.1.0")
  })

  test("init command initializes clawdstrike", async () => {
    const proc = Bun.spawn(
      ["bun", "run", "./src/cli/index.ts", "init", "--cwd", tempDir],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    expect(stdout).toContain("initialized")

    // Verify directories created
    const beadsExists = await Bun.file(`${tempDir}/.beads/issues.jsonl`).exists()
    expect(beadsExists).toBe(true)
  })

  test("beads list shows empty initially", async () => {
    const proc = Bun.spawn(
      ["bun", "run", "./src/cli/index.ts", "beads", "list", "--cwd", tempDir],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    expect(stdout).toContain("No issues found")
  })

  test("beads ready shows empty initially", async () => {
    const proc = Bun.spawn(
      ["bun", "run", "./src/cli/index.ts", "beads", "ready", "--cwd", tempDir],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    expect(stdout).toContain("No issues ready")
  })

  test("beads create creates issue", async () => {
    const proc = Bun.spawn(
      [
        "bun",
        "run",
        "./src/cli/index.ts",
        "beads",
        "create",
        "Test issue",
        "--cwd",
        tempDir,
      ],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    expect(stdout).toContain("Created issue")
    expect(stdout).toContain("Test issue")
  })

  test("unknown command shows error", async () => {
    const proc = Bun.spawn(
      ["bun", "run", "./src/cli/index.ts", "unknown-command"],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stderr = await new Response(proc.stderr).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(1)
    expect(stderr).toContain("Unknown command")
  })

  test("dispatch without prompt shows error", async () => {
    const proc = Bun.spawn(
      ["bun", "run", "./src/cli/index.ts", "dispatch", "--cwd", tempDir],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stderr = await new Response(proc.stderr).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(1)
    expect(stderr).toContain("Missing prompt")
  })

  test("speculate without prompt shows error", async () => {
    const proc = Bun.spawn(
      ["bun", "run", "./src/cli/index.ts", "speculate", "--cwd", tempDir],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stderr = await new Response(proc.stderr).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(1)
    expect(stderr).toContain("Missing prompt")
  })

  test("beads help shows subcommands", async () => {
    const proc = Bun.spawn(
      ["bun", "run", "./src/cli/index.ts", "beads", "--help"],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    expect(stdout).toContain("list")
    expect(stdout).toContain("get")
    expect(stdout).toContain("ready")
    expect(stdout).toContain("create")
  })

  test("json output works for status", async () => {
    const proc = Bun.spawn(
      ["bun", "run", "./src/cli/index.ts", "status", "--json", "--cwd", tempDir],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    const parsed = JSON.parse(stdout)
    expect(parsed).toHaveProperty("active")
    expect(Array.isArray(parsed.active)).toBe(true)
  })

  test("no-color flag disables colors", async () => {
    const proc = Bun.spawn(
      ["bun", "run", "./src/cli/index.ts", "help", "--no-color"],
      {
        cwd: process.cwd(),
        stdout: "pipe",
        stderr: "pipe",
      }
    )

    const stdout = await new Response(proc.stdout).text()
    const exitCode = await proc.exited

    expect(exitCode).toBe(0)
    // Should not contain ANSI escape codes
    expect(stdout).not.toContain("\x1b[")
  })
})
