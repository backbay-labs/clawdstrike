import { describe, expect, test } from "bun:test"
import {
  getAvailableExternalAdapters,
  getExternalAdapter,
  toExternalAdapterOptions,
} from "../src/tui/external/registry"
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
})
