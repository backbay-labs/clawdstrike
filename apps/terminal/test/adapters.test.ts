/**
 * Adapter integration tests
 *
 * Tests for CLI adapter implementations.
 */

import { afterEach, describe, test, expect } from "bun:test"
import * as fs from "node:fs/promises"
import * as os from "node:os"
import * as path from "node:path"
import { Dispatcher } from "../src/dispatcher"
import { CodexAdapter } from "../src/dispatcher/adapters/codex"
import { ClaudeAdapter } from "../src/dispatcher/adapters/claude"
import { OpenCodeAdapter } from "../src/dispatcher/adapters/opencode"
import { CrushAdapter } from "../src/dispatcher/adapters/crush"
import type { WorkcellInfo, TaskInput } from "../src/types"

const originalPath = process.env.PATH
const originalHome = process.env.HOME
const originalUserProfile = process.env.USERPROFILE

async function withFakeCli(
  name: string,
  script = "#!/bin/sh\nexit 0\n"
): Promise<string> {
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), `clawdstrike-adapter-${name}-`))
  const binDir = path.join(tempDir, "bin")
  await fs.mkdir(binDir, { recursive: true })
  const cliPath = path.join(binDir, name)
  await fs.writeFile(cliPath, script, { mode: 0o755 })
  process.env.PATH = [binDir, originalPath].filter(Boolean).join(":")
  process.env.HOME = tempDir
  process.env.USERPROFILE = tempDir
  return tempDir
}

afterEach(() => {
  process.env.PATH = originalPath
  if (originalHome === undefined) delete process.env.HOME
  else process.env.HOME = originalHome
  if (originalUserProfile === undefined) delete process.env.USERPROFILE
  else process.env.USERPROFILE = originalUserProfile
})

async function probeAdapterAvailability(
  modulePath: "./src/dispatcher/adapters/codex" | "./src/dispatcher/adapters/claude",
  exportName: "CodexAdapter" | "ClaudeAdapter",
  envOverrides: Record<string, string | undefined>,
): Promise<boolean> {
  const script =
    `import { ${exportName} } from ${JSON.stringify(modulePath)};\n` +
    `console.log(JSON.stringify(await ${exportName}.isAvailable()));\n`
  const env = {
    ...process.env,
    ...envOverrides,
  }
  if (envOverrides.HOME === undefined) {
    delete env.HOME
  }
  if (envOverrides.USERPROFILE === undefined) {
    delete env.USERPROFILE
  }

  const proc = Bun.spawn(["bun", "-e", script], {
    cwd: process.cwd(),
    env,
    stdout: "pipe",
    stderr: "pipe",
  })
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])
  expect(exitCode).toBe(0)
  expect(stderr.trim()).toBe("")
  return JSON.parse(stdout.trim()) as boolean
}

// Mock workcell for testing
const mockWorkcell: WorkcellInfo = {
  id: "123e4567-e89b-12d3-a456-426614174000",
  name: "wc-test",
  directory: "/tmp/test-workcell",
  branch: "wc-test",
  status: "warm",
  projectId: "test-project",
  createdAt: Date.now(),
  useCount: 0,
}

// Mock task for testing
const mockTask: TaskInput = {
  prompt: "Test prompt",
  context: {
    cwd: "/tmp/test-workcell",
    projectId: "test-project",
    branch: "main",
  },
}

describe("Adapter info", () => {
  test("CodexAdapter has correct info", () => {
    expect(CodexAdapter.info.id).toBe("codex")
    expect(CodexAdapter.info.authType).toBe("oauth")
    expect(CodexAdapter.info.requiresInstall).toBe(true)
  })

  test("ClaudeAdapter has correct info", () => {
    expect(ClaudeAdapter.info.id).toBe("claude")
    expect(ClaudeAdapter.info.authType).toBe("oauth")
    expect(ClaudeAdapter.info.requiresInstall).toBe(true)
  })

  test("OpenCodeAdapter has correct info", () => {
    expect(OpenCodeAdapter.info.id).toBe("opencode")
    expect(OpenCodeAdapter.info.authType).toBe("api_key")
    expect(OpenCodeAdapter.info.requiresInstall).toBe(false)
  })

  test("CrushAdapter has correct info", () => {
    expect(CrushAdapter.info.id).toBe("crush")
    expect(CrushAdapter.info.authType).toBe("api_key")
    expect(CrushAdapter.info.requiresInstall).toBe(true)
  })
})

describe("Dispatcher adapter registry", () => {
  test("getAdapter returns correct adapter for each toolchain", () => {
    expect(Dispatcher.getAdapter("codex")?.info.id).toBe("codex")
    expect(Dispatcher.getAdapter("claude")?.info.id).toBe("claude")
    expect(Dispatcher.getAdapter("opencode")?.info.id).toBe("opencode")
    expect(Dispatcher.getAdapter("crush")?.info.id).toBe("crush")
  })

  test("getAllAdapters returns all adapters", () => {
    const adapters = Dispatcher.getAllAdapters()
    expect(adapters.length).toBe(4)
    expect(adapters.map((a) => a.info.id)).toEqual(
      expect.arrayContaining(["codex", "claude", "opencode", "crush"])
    )
  })
})

describe("Adapter availability", () => {
  // These tests verify the availability check logic works
  // Some may be slow if CLI tools exist but need to check auth status

  test("CodexAdapter.isAvailable returns boolean", async () => {
    const result = await Promise.race([
      CodexAdapter.isAvailable(),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 2000)),
    ])
    expect(typeof result).toBe("boolean")
  })

  test("ClaudeAdapter.isAvailable returns boolean", async () => {
    // Skip slow auth check by just testing the type
    const result = await Promise.race([
      ClaudeAdapter.isAvailable(),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 2000)),
    ])
    expect(typeof result).toBe("boolean")
  })

  test("CodexAdapter.isAvailable returns false when auth state is missing", async () => {
    const tempDir = await withFakeCli(
      "codex",
      "#!/bin/sh\nif [ \"$1\" = \"login\" ] && [ \"$2\" = \"status\" ]; then\n  exit 1\nfi\nexit 0\n"
    )
    await fs.mkdir(path.join(tempDir, ".codex"), { recursive: true })
    await expect(
      probeAdapterAvailability("./src/dispatcher/adapters/codex", "CodexAdapter", {
        PATH: [path.join(tempDir, "bin"), originalPath].filter(Boolean).join(":"),
        HOME: tempDir,
        USERPROFILE: tempDir,
      }),
    ).resolves.toBe(false)
  })

  test("CodexAdapter.isAvailable falls back to codex auth status", async () => {
    const tempDir = await withFakeCli(
      "codex",
      "#!/bin/sh\nif [ \"$1\" = \"login\" ] && [ \"$2\" = \"status\" ]; then\n  exit 0\nfi\nexit 1\n"
    )
    await fs.mkdir(path.join(tempDir, ".codex"), { recursive: true })
    await expect(
      probeAdapterAvailability("./src/dispatcher/adapters/codex", "CodexAdapter", {
        PATH: [path.join(tempDir, "bin"), originalPath].filter(Boolean).join(":"),
        HOME: tempDir,
        USERPROFILE: tempDir,
      }),
    ).resolves.toBe(true)
  })

  test("CodexAdapter.isAvailable checks auth status when HOME is unset", async () => {
    const tempDir = await withFakeCli(
      "codex",
      "#!/bin/sh\nif [ \"$1\" = \"login\" ] && [ \"$2\" = \"status\" ]; then\n  exit 0\nfi\nexit 1\n"
    )
    await expect(
      probeAdapterAvailability("./src/dispatcher/adapters/codex", "CodexAdapter", {
        PATH: [path.join(tempDir, "bin"), originalPath].filter(Boolean).join(":"),
        HOME: undefined,
        USERPROFILE: undefined,
      }),
    ).resolves.toBe(true)
  })

  test("ClaudeAdapter.isAvailable returns false when auth state is missing", async () => {
    const tempDir = await withFakeCli(
      "claude",
      "#!/bin/sh\nif [ \"$1\" = \"auth\" ] && [ \"$2\" = \"status\" ]; then\n  exit 1\nfi\nexit 0\n"
    )
    await fs.mkdir(path.join(tempDir, ".claude"), { recursive: true })
    await expect(
      probeAdapterAvailability("./src/dispatcher/adapters/claude", "ClaudeAdapter", {
        PATH: [path.join(tempDir, "bin"), originalPath].filter(Boolean).join(":"),
        HOME: tempDir,
        USERPROFILE: tempDir,
      }),
    ).resolves.toBe(false)
  })

  test("ClaudeAdapter.isAvailable falls back to claude auth status", async () => {
    const tempDir = await withFakeCli(
      "claude",
      "#!/bin/sh\nif [ \"$1\" = \"auth\" ] && [ \"$2\" = \"status\" ]; then\n  exit 0\nfi\nexit 1\n"
    )
    await fs.mkdir(path.join(tempDir, ".claude"), { recursive: true })
    await expect(
      probeAdapterAvailability("./src/dispatcher/adapters/claude", "ClaudeAdapter", {
        PATH: [path.join(tempDir, "bin"), originalPath].filter(Boolean).join(":"),
        HOME: tempDir,
        USERPROFILE: tempDir,
      }),
    ).resolves.toBe(true)
  })

  test("ClaudeAdapter.isAvailable returns false when auth status times out", async () => {
    const tempDir = await withFakeCli(
      "claude",
      "#!/bin/sh\nif [ \"$1\" = \"auth\" ] && [ \"$2\" = \"status\" ]; then\n  sleep 4\n  exit 0\nfi\nexit 1\n"
    )
    await fs.mkdir(path.join(tempDir, ".claude"), { recursive: true })
    await expect(
      probeAdapterAvailability("./src/dispatcher/adapters/claude", "ClaudeAdapter", {
        PATH: [path.join(tempDir, "bin"), originalPath].filter(Boolean).join(":"),
        HOME: tempDir,
        USERPROFILE: tempDir,
      }),
    ).resolves.toBe(false)
  })

  test("ClaudeAdapter.isAvailable checks auth status when HOME is unset", async () => {
    const tempDir = await withFakeCli(
      "claude",
      "#!/bin/sh\nif [ \"$1\" = \"auth\" ] && [ \"$2\" = \"status\" ]; then\n  exit 0\nfi\nexit 1\n"
    )
    await expect(
      probeAdapterAvailability("./src/dispatcher/adapters/claude", "ClaudeAdapter", {
        PATH: [path.join(tempDir, "bin"), originalPath].filter(Boolean).join(":"),
        HOME: undefined,
        USERPROFILE: undefined,
      }),
    ).resolves.toBe(true)
  })

  test("OpenCodeAdapter.isAvailable returns boolean", async () => {
    const result = await OpenCodeAdapter.isAvailable()
    expect(typeof result).toBe("boolean")
  })

  test("OpenCodeAdapter.isAvailable returns false without API key or CLI", async () => {
    const { configure } = await import("../src/dispatcher/adapters/opencode")
    configure({ provider: "anthropic", apiKeyEnvVar: undefined })
    delete process.env.ANTHROPIC_API_KEY
    delete process.env.OPENAI_API_KEY
    delete process.env.GOOGLE_API_KEY
    process.env.PATH = ""

    await expect(OpenCodeAdapter.isAvailable()).resolves.toBe(false)
  })

  test("CrushAdapter.isAvailable returns boolean", async () => {
    const result = await CrushAdapter.isAvailable()
    expect(typeof result).toBe("boolean")
  })
})

describe("Adapter telemetry parsing", () => {
  test("CodexAdapter parses telemetry from JSON output", () => {
    const output = JSON.stringify({
      model: "gpt-4o",
      usage: {
        prompt_tokens: 100,
        completion_tokens: 50,
      },
      cost: 0.01,
    })

    const telemetry = CodexAdapter.parseTelemetry(output)
    expect(telemetry!.model).toBe("gpt-4o")
    expect(telemetry!.tokens?.input).toBe(100)
    expect(telemetry!.tokens?.output).toBe(50)
    expect(telemetry!.cost).toBe(0.01)
  })

  test("CodexAdapter parses telemetry from current exec JSONL output", () => {
    const output = [
      JSON.stringify({ type: "thread.started", thread_id: "thread_123" }),
      JSON.stringify({
        type: "turn.completed",
        usage: {
          input_tokens: 12339,
          output_tokens: 35,
        },
      }),
    ].join("\n")

    const telemetry = CodexAdapter.parseTelemetry(output)
    expect(telemetry!.tokens?.input).toBe(12339)
    expect(telemetry!.tokens?.output).toBe(35)
  })

  test("ClaudeAdapter parses telemetry from JSON output", () => {
    const output = JSON.stringify({
      model: "claude-3-opus-20240229",
      usage: {
        input_tokens: 200,
        output_tokens: 100,
      },
      cost: 0.02,
    })

    const telemetry = ClaudeAdapter.parseTelemetry(output)
    expect(telemetry!.model).toBe("claude-3-opus-20240229")
    expect(telemetry!.tokens?.input).toBe(200)
    expect(telemetry!.tokens?.output).toBe(100)
    expect(telemetry!.cost).toBe(0.02)
  })

  test("ClaudeAdapter parses telemetry from current result output", () => {
    const output = JSON.stringify({
      type: "result",
      result: "OK",
      total_cost_usd: 0.0353275,
      usage: {
        input_tokens: 3,
        output_tokens: 4,
      },
      modelUsage: {
        "claude-opus-4-6": {
          inputTokens: 3,
          outputTokens: 4,
        },
      },
    })

    const telemetry = ClaudeAdapter.parseTelemetry(output)
    expect(telemetry!.model).toBe("claude-opus-4-6")
    expect(telemetry!.tokens?.input).toBe(3)
    expect(telemetry!.tokens?.output).toBe(4)
    expect(telemetry!.cost).toBe(0.0353275)
  })

  test("OpenCodeAdapter parses telemetry from JSON output", () => {
    const output = JSON.stringify({
      model: "claude-sonnet-4-20250514",
      usage: {
        input_tokens: 150,
        output_tokens: 75,
      },
    })

    const telemetry = OpenCodeAdapter.parseTelemetry(output)
    expect(telemetry!.model).toBe("claude-sonnet-4-20250514")
    expect(telemetry!.tokens?.input).toBe(150)
    expect(telemetry!.tokens?.output).toBe(75)
  })

  test("CrushAdapter parses telemetry from JSON output", () => {
    const output = JSON.stringify({
      model: "gemini-1.5-pro",
      usage: {
        input_tokens: 300,
        output_tokens: 150,
      },
      cost: 0.03,
    })

    const telemetry = CrushAdapter.parseTelemetry(output)
    expect(telemetry!.model).toBe("gemini-1.5-pro")
    expect(telemetry!.tokens?.input).toBe(300)
    expect(telemetry!.tokens?.output).toBe(150)
    expect(telemetry!.cost).toBe(0.03)
  })

  test("parseTelemetry handles multiline JSON output", () => {
    const output = `Some text before
{"model": "gpt-4o", "usage": {"prompt_tokens": 100, "completion_tokens": 50}}
Some text after`

    const telemetry = CodexAdapter.parseTelemetry(output)
    expect(telemetry!.model).toBe("gpt-4o")
  })

  test("parseTelemetry returns empty object for invalid input", () => {
    const telemetry = CodexAdapter.parseTelemetry("not json")
    expect(telemetry).toEqual({})
  })
})

describe("Dispatcher execution", () => {
  test("CodexAdapter.execute uses current exec flags and stdin prompts", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-codex-exec-"))
    const captureArgsPath = path.join(tempDir, "codex-args.txt")
    const capturePromptPath = path.join(tempDir, "codex-prompt.txt")
    const binDir = path.join(tempDir, "bin")
    const cliPath = path.join(binDir, "codex")
    await fs.mkdir(binDir, { recursive: true })
    await fs.writeFile(
      cliPath,
      `#!/bin/sh
printf '%s\\n' "$@" > ${JSON.stringify(captureArgsPath)}
cat > ${JSON.stringify(capturePromptPath)}
printf '%s\\n' '{"type":"item.completed","item":{"type":"agent_message","text":"OK"}}'
printf '%s\\n' '{"type":"turn.completed","usage":{"input_tokens":12,"output_tokens":2}}'
`,
      { mode: 0o755 },
    )
    await fs.chmod(cliPath, 0o755)

    process.env.PATH = [binDir, originalPath].filter(Boolean).join(":")

    const workcellDir = path.join(tempDir, "workcell")
    await fs.mkdir(workcellDir, { recursive: true })

    const result = await CodexAdapter.execute(
      { ...mockWorkcell, directory: workcellDir },
      mockTask,
      new AbortController().signal,
    )

    expect(result.success).toBe(true)
    expect(result.output).toBe("OK")
    expect(result.telemetry?.tokens?.input).toBe(12)
    expect(result.telemetry?.tokens?.output).toBe(2)

    const args = (await fs.readFile(captureArgsPath, "utf8")).trim().split("\n")
    expect(args).toEqual(["-a", "never", "-s", "workspace-write", "exec", "--json", "-C", workcellDir, "-"])
    expect(await fs.readFile(capturePromptPath, "utf8")).toBe(mockTask.prompt)
  })

  test("ClaudeAdapter.execute returns the parsed result text", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-claude-exec-"))
    const binDir = path.join(tempDir, "bin")
    const cliPath = path.join(binDir, "claude")
    await fs.mkdir(binDir, { recursive: true })
    await fs.writeFile(
      cliPath,
      `#!/bin/sh
printf '%s\\n' '{"type":"result","result":"OK","total_cost_usd":0.02,"usage":{"input_tokens":8,"output_tokens":3},"modelUsage":{"claude-opus-4-6":{"inputTokens":8,"outputTokens":3}}}'
`,
      { mode: 0o755 },
    )
    await fs.chmod(cliPath, 0o755)

    process.env.PATH = [binDir, originalPath].filter(Boolean).join(":")

    const workcellDir = path.join(tempDir, "workcell")
    await fs.mkdir(workcellDir, { recursive: true })

    const result = await ClaudeAdapter.execute(
      { ...mockWorkcell, directory: workcellDir },
      mockTask,
      new AbortController().signal,
    )

    expect(result.success).toBe(true)
    expect(result.output).toBe("OK")
    expect(result.telemetry?.model).toBe("claude-opus-4-6")
    expect(result.telemetry?.tokens?.input).toBe(8)
    expect(result.telemetry?.tokens?.output).toBe(3)
    expect(result.telemetry?.cost).toBe(0.02)
  })

  test("ClaudeAdapter.execute omits bypassPermissions for inplace workcells", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-claude-inplace-"))
    const binDir = path.join(tempDir, "bin")
    const cliPath = path.join(binDir, "claude")
    const captureArgsPath = path.join(tempDir, "claude-args.txt")
    const workcellDir = path.join(tempDir, "workcell")
    await fs.mkdir(binDir, { recursive: true })
    await fs.mkdir(workcellDir, { recursive: true })
    await fs.writeFile(
      cliPath,
      `#!/bin/sh
printf '%s\\n' "$@" > "${captureArgsPath}"
printf '%s\\n' '{"type":"result","result":"OK"}'
exit 0
`,
      { mode: 0o755 },
    )
    await fs.chmod(cliPath, 0o755)

    process.env.PATH = [binDir, originalPath].filter(Boolean).join(":")

    const result = await ClaudeAdapter.execute(
      { ...mockWorkcell, name: "inplace", directory: workcellDir },
      mockTask,
      new AbortController().signal,
    )

    expect(result.success).toBe(true)
    const args = (await fs.readFile(captureArgsPath, "utf8")).trim().split("\n")
    expect(args).not.toContain("--permission-mode")
    expect(args).toEqual([
      "--print",
      "--output-format",
      "json",
      "--allowedTools",
      "Read,Glob,Grep,Edit,Write,Bash",
      "--max-turns",
      "50",
      mockTask.prompt,
    ])
  })

  test("ClaudeAdapter.execute keeps bypassPermissions for isolated workcells", async () => {
    const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-claude-isolated-"))
    const binDir = path.join(tempDir, "bin")
    const cliPath = path.join(binDir, "claude")
    const captureArgsPath = path.join(tempDir, "claude-args.txt")
    const workcellDir = path.join(tempDir, "workcell")
    await fs.mkdir(binDir, { recursive: true })
    await fs.mkdir(workcellDir, { recursive: true })
    await fs.writeFile(
      cliPath,
      `#!/bin/sh
printf '%s\\n' "$@" > "${captureArgsPath}"
printf '%s\\n' '{"type":"result","result":"OK"}'
exit 0
`,
      { mode: 0o755 },
    )
    await fs.chmod(cliPath, 0o755)

    process.env.PATH = [binDir, originalPath].filter(Boolean).join(":")

    const result = await ClaudeAdapter.execute(
      { ...mockWorkcell, name: "wc-isolated", directory: workcellDir },
      mockTask,
      new AbortController().signal,
    )

    expect(result.success).toBe(true)
    const args = (await fs.readFile(captureArgsPath, "utf8")).trim().split("\n")
    expect(args).toContain("--permission-mode")
    expect(args).toEqual([
      "--print",
      "--output-format",
      "json",
      "--permission-mode",
      "bypassPermissions",
      "--allowedTools",
      "Read,Glob,Grep,Edit,Write,Bash",
      "--max-turns",
      "50",
      mockTask.prompt,
    ])
  })

  test("execute returns error when adapter unavailable", async () => {
    const result = await Dispatcher.execute({
      task: mockTask,
      workcell: mockWorkcell,
      toolchain: "codex",
    })

    // Without proper CLI/auth, should return error
    expect(result.taskId).toBeDefined()
    expect(result.workcellId).toBe(mockWorkcell.id)
    expect(result.toolchain).toBe("codex")
    expect(result.telemetry).toBeDefined()
    expect(result.telemetry.startedAt).toBeDefined()
    expect(result.telemetry.completedAt).toBeDefined()

    // When adapter is not available
    if (!result.success) {
      expect(result.error).toBeDefined()
    }
  })

  test("execute handles opencode toolchain", async () => {
    // Test a single toolchain to avoid timeout
    const result = await Dispatcher.execute({
      task: mockTask,
      workcell: mockWorkcell,
      toolchain: "opencode",
    })

    expect(result.toolchain).toBe("opencode")
    expect(result.telemetry).toBeDefined()
  })

  test("execute generates taskId when not provided", async () => {
    const result = await Dispatcher.execute({
      task: { ...mockTask, id: undefined },
      workcell: mockWorkcell,
      toolchain: "codex",
    })

    // Should generate a UUID
    expect(result.taskId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    )
  })

  test("execute preserves taskId when provided", async () => {
    const taskId = "550e8400-e29b-41d4-a716-446655440000"
    const result = await Dispatcher.execute({
      task: { ...mockTask, id: taskId },
      workcell: mockWorkcell,
      toolchain: "codex",
    })

    expect(result.taskId).toBe(taskId)
  })
})

describe("Adapter configuration", () => {
  test("CodexAdapter supports approval mode configuration", async () => {
    const { configure } = await import("../src/dispatcher/adapters/codex")
    // Just verify it doesn't throw
    expect(() => configure({ approvalMode: "full-auto" })).not.toThrow()
  })

  test("ClaudeAdapter supports model configuration", async () => {
    const { configure } = await import("../src/dispatcher/adapters/claude")
    expect(() => configure({ model: "claude-3-opus-20240229" })).not.toThrow()
  })

  test("OpenCodeAdapter supports provider configuration", async () => {
    const { configure } = await import("../src/dispatcher/adapters/opencode")
    expect(() => configure({ provider: "openai" })).not.toThrow()
  })

  test("CrushAdapter supports providers configuration", async () => {
    const { configure } = await import("../src/dispatcher/adapters/crush")
    expect(() => configure({ providers: ["anthropic", "openai"] })).not.toThrow()
  })
})
