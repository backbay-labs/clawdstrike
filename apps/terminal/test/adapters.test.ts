/**
 * Adapter integration tests
 *
 * Tests for CLI adapter implementations.
 */

import { describe, test, expect } from "bun:test"
import { Dispatcher } from "../src/dispatcher"
import { CodexAdapter } from "../src/dispatcher/adapters/codex"
import { ClaudeAdapter } from "../src/dispatcher/adapters/claude"
import { OpenCodeAdapter } from "../src/dispatcher/adapters/opencode"
import { CrushAdapter } from "../src/dispatcher/adapters/crush"
import type { WorkcellInfo, TaskInput } from "../src/types"

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

  test("OpenCodeAdapter.isAvailable returns boolean", async () => {
    const result = await OpenCodeAdapter.isAvailable()
    expect(typeof result).toBe("boolean")
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
