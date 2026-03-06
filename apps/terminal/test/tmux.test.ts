import { describe, expect, test } from "bun:test"
import {
  buildTmuxLaunchCommand,
  detectTmuxAvailability,
  focusTmuxSurface,
  hasTmuxAdapter,
  isTmuxSurfaceAlive,
  launchInTmux,
} from "../src/tui/external/tmux"
import type { ExternalRunSessionPlan } from "../src/tui/external/types"

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

describe("tmux adapter", () => {
  test("detects adapter availability from tmux env and binary presence", () => {
    expect(hasTmuxAdapter({ TMUX: "/tmp/tmux.sock,123,0" }, () => "/usr/bin/tmux")).toBe(true)
    expect(hasTmuxAdapter({}, () => "/usr/bin/tmux")).toBe(false)
    expect(hasTmuxAdapter({ TMUX: "/tmp/tmux.sock,123,0" }, () => null)).toBe(false)
  })

  test("loads active session metadata when tmux is available", async () => {
    const availability = await detectTmuxAvailability(
      { TMUX: "/tmp/tmux.sock,123,0" },
      () => "/usr/bin/tmux",
      async (args) => {
        expect(args).toEqual(["display-message", "-p", "#{session_id}"])
        return { exitCode: 0, stdout: "$1\n", stderr: "" }
      },
    )

    expect(availability).toEqual({
      available: true,
      sessionId: "$1",
      reason: null,
    })
  })

  test("builds tmux split and window commands around the external launch script", () => {
    const plan = createPlan()

    expect(buildTmuxLaunchCommand("tmux-split", { sessionId: "$1" }, plan)).toEqual([
      "split-window",
      "-P",
      "-F",
      "#{pane_id}",
      "-t",
      "$1",
      "-c",
      "/tmp/wc-1",
      "'/bin/zsh' '/tmp/wc-1/.clawdstrike/external-launch.zsh'",
    ])

    expect(buildTmuxLaunchCommand("tmux-window", { sessionId: "$1" }, plan)).toEqual([
      "new-window",
      "-P",
      "-F",
      "#{window_id}",
      "-t",
      "$1",
      "-n",
      "clawdstrike-550e8400",
      "-c",
      "/tmp/wc-1",
      "'/bin/zsh' '/tmp/wc-1/.clawdstrike/external-launch.zsh'",
    ])
  })

  test("returns external refs and can focus them later", async () => {
    const originalTmux = process.env.TMUX
    try {
      process.env.TMUX = "/tmp/tmux.sock,123,0"

      const external = await launchInTmux(
        "tmux-split",
        createPlan(),
        async (args) => {
          if (args[0] === "display-message") {
            return { exitCode: 0, stdout: "$1\n", stderr: "" }
          }
          return { exitCode: 0, stdout: "%11\n", stderr: "" }
        },
      )

      expect(external).toEqual({ ref: "%11" })

      let focusArgs: string[] | null = null
      await focusTmuxSurface("tmux-split", "%11", async (args) => {
        focusArgs = args
        return { exitCode: 0, stdout: "", stderr: "" }
      })
      expect(focusArgs ?? ([] as string[])).toEqual(["select-pane", "-t", "%11"])
    } finally {
      if (originalTmux === undefined) {
        delete process.env.TMUX
      } else {
        process.env.TMUX = originalTmux
      }
    }
  })

  test("detects whether a tmux surface still exists", async () => {
    await expect(
      isTmuxSurfaceAlive("tmux-split", "%11", async (args) => {
        expect(args).toEqual(["display-message", "-p", "-t", "%11", "#{pane_id}"])
        return { exitCode: 0, stdout: "%11\n", stderr: "" }
      }),
    ).resolves.toBe(true)

    await expect(
      isTmuxSurfaceAlive("tmux-window", "@9", async (args) => {
        expect(args).toEqual(["display-message", "-p", "-t", "@9", "#{window_id}"])
        return { exitCode: 1, stdout: "", stderr: "can't find window" }
      }),
    ).resolves.toBe(false)
  })
})
