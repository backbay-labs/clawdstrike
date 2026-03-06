import { describe, expect, test } from "bun:test"
import { canRunExternal, createManagedRun, getRunExternalDisabledReason } from "../src/tui/runs"
import {
  getAvailableExternalAdapters,
  getExternalAdapter,
  toExternalAdapterOptions,
} from "../src/tui/external/registry"
import {
  createRecoverableExternalFailureRun,
  ExternalRunHeartbeatTimeoutError,
  ExternalLaunchStartupTimeoutError,
  isRecoverableExternalLaunchError,
} from "../src/tui/external/state"
import { makeTerminalWindowRef, parseTerminalWindowRef } from "../src/tui/external/terminal-app"
import { resolveWezTermShell } from "../src/tui/external/wezterm"
import type { ExternalRunSessionPlan, ExternalTerminalAdapter } from "../src/tui/external/types"

function createPlan(): ExternalRunSessionPlan {
  return {
    ptySessionId: "pty_test",
    workcell: {
      id: "550e8400-e29b-41d4-a716-446655440000",
      name: "wc-1",
      directory: "/tmp/wc-1",
      branch: "HEAD",
      status: "in_use",
      projectId: "default",
      createdAt: 1,
      useCount: 1,
    },
    routing: { toolchain: "codex", strategy: "external terminal", gates: [] },
    scriptPath: "/tmp/wc-1/.clawdstrike/external-launch.zsh",
    statusPath: "/tmp/wc-1/.clawdstrike/external-status.json",
    startupTimeoutMs: 10_000,
    livenessTimeoutMs: 15_000,
    cleanup: async () => {},
  }
}

describe("external adapter registry", () => {
  test("filters adapters by availability and preserves display metadata", async () => {
    const adapters: ExternalTerminalAdapter[] = [
      {
        id: "wezterm",
        label: "WezTerm",
        description: "Launch WezTerm.",
        isAvailable: async () => true,
        launch: async () => ({ ref: "wezterm:123" }),
      },
      {
        id: "kitty",
        label: "Kitty",
        description: "Launch Kitty.",
        isAvailable: async () => false,
        launch: async () => ({ ref: "kitty:123" }),
      },
    ]

    const available = await getAvailableExternalAdapters(adapters)

    expect(available.map((adapter) => adapter.id)).toEqual(["wezterm"])
    expect(toExternalAdapterOptions(available)).toEqual([
      {
        id: "wezterm",
        label: "WezTerm",
        description: "Launch WezTerm.",
      },
    ])
  })

  test("returns null for unknown adapters and surfaces launch refs", async () => {
    const adapter: ExternalTerminalAdapter = {
      id: "terminal-app",
      label: "Terminal.app",
      description: "Launch Terminal.app.",
      isAvailable: async () => true,
      launch: async (_plan) => ({ ref: "terminal-app" }),
    }

    expect(getExternalAdapter("missing", [adapter])).toBeNull()
    expect(getExternalAdapter("terminal-app", [adapter])?.label).toBe("Terminal.app")
    await expect(adapter.launch(createPlan())).resolves.toEqual({ ref: "terminal-app" })
  })

  test("marks startup timeout failures as recoverable", () => {
    const error = new ExternalLaunchStartupTimeoutError()
    expect(isRecoverableExternalLaunchError(error)).toBe(true)
    expect(isRecoverableExternalLaunchError(new ExternalRunHeartbeatTimeoutError())).toBe(true)
    expect(isRecoverableExternalLaunchError(new Error("boom"))).toBe(false)
  })

  test("preserves a retryable run after external launch failure", () => {
    const run = createManagedRun({
      prompt: "Investigate terminal launch",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
      mode: "external",
    })

    run.phase = "executing"
    run.routing = { toolchain: "codex", strategy: "external terminal", gates: [] }
    run.workcellId = "wc_123"
    run.worktreePath = "/tmp/workcell"
    run.ptySessionId = "pty_123"

    const failed = createRecoverableExternalFailureRun(
      run,
      "terminal-app",
      "launch script never started",
    )

    expect(failed.phase).toBe("failed")
    expect(failed.completedAt).not.toBeNull()
    expect(failed.routing).toBeNull()
    expect(failed.workcellId).toBeNull()
    expect(failed.worktreePath).toBeNull()
    expect(failed.ptySessionId).toBeNull()
    expect(failed.result).toBeNull()
    expect(failed.external.adapterId).toBe("terminal-app")
    expect(failed.external.status).toBe("failed")
    expect(failed.external.error).toBe("launch script never started")
    expect(canRunExternal(failed)).toBe(true)
    expect(getRunExternalDisabledReason(failed)).toBeNull()
  })

  test("round-trips Terminal.app window refs", () => {
    expect(makeTerminalWindowRef(5126)).toBe("terminal-window:5126")
    expect(parseTerminalWindowRef("terminal-window:5126")).toBe(5126)
    expect(parseTerminalWindowRef("terminal-app")).toBeNull()
  })

  test("uses the current shell for WezTerm launches", () => {
    const previousShell = process.env.SHELL
    process.env.SHELL = "/usr/local/bin/fish"
    expect(resolveWezTermShell()).toBe("/usr/local/bin/fish")
    delete process.env.SHELL
    expect(resolveWezTermShell()).toBe("sh")
    if (previousShell === undefined) delete process.env.SHELL
    else process.env.SHELL = previousShell
  })
})
