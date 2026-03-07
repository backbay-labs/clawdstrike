import { mkdtemp } from "node:fs/promises"
import { join } from "node:path"
import { tmpdir } from "node:os"
import { afterEach, describe, expect, test } from "bun:test"
import { TUIApp } from "../src/tui/app"
import { Hushd } from "../src/hushd"
import { createManagedRun } from "../src/tui/runs"

const originalGetClient = Hushd.getClient
const originalIsInitialized = Hushd.isInitialized
const originalInit = Hushd.init
const originalReset = Hushd.reset

afterEach(() => {
  ;(Hushd as unknown as {
    getClient: typeof Hushd.getClient
    isInitialized: typeof Hushd.isInitialized
    init: typeof Hushd.init
    reset: typeof Hushd.reset
  }).getClient = originalGetClient
  ;(Hushd as unknown as {
    getClient: typeof Hushd.getClient
    isInitialized: typeof Hushd.isInitialized
    init: typeof Hushd.init
    reset: typeof Hushd.reset
  }).isInitialized = originalIsInitialized
  ;(Hushd as unknown as {
    getClient: typeof Hushd.getClient
    isInitialized: typeof Hushd.isInitialized
    init: typeof Hushd.init
    reset: typeof Hushd.reset
  }).init = originalInit
  ;(Hushd as unknown as {
    getClient: typeof Hushd.getClient
    isInitialized: typeof Hushd.isInitialized
    init: typeof Hushd.init
    reset: typeof Hushd.reset
  }).reset = originalReset
})

describe("TUIApp security refresh", () => {
  test("refreshes the recent audit preview outside the initial hushd connect", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        hushdStatus: string
        inputMode: string
        recentAuditPreview: unknown[]
      }
      render: () => void
      refreshRecentAuditPreview: (force?: boolean) => Promise<void>
    }

    let calls = 0
    app.state.hushdStatus = "connected"
    app.state.inputMode = "security"
    app.render = () => {}

    ;(Hushd as unknown as {
      getClient: typeof Hushd.getClient
      isInitialized: typeof Hushd.isInitialized
    }).isInitialized = () => true
    ;(Hushd as unknown as {
      getClient: typeof Hushd.getClient
      isInitialized: typeof Hushd.isInitialized
    }).getClient = () => ({
      getAuditDetailed: async () => {
        calls += 1
        return {
          ok: true,
          status: 200,
          data: {
            events: [{
              id: "preview-1",
              timestamp: "2026-03-06T06:00:00Z",
              event_type: "report_export",
              action_type: "report_export",
              decision: "allowed",
              target: "/tmp/report.md",
              guard: null,
              severity: "info",
              message: "preview refreshed",
              session_id: null,
              agent_id: null,
              metadata: {},
            }],
            total: 1,
            offset: 0,
            limit: 6,
            has_more: false,
          },
        }
      },
    } as never)

    await app.refreshRecentAuditPreview(true)

    expect(calls).toBe(1)
    expect(app.state.recentAuditPreview).toHaveLength(1)
  })

  test("schedules reconnect when the initial hushd probe fails", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        hushdStatus: string
        hushdReconnectAttempts: number
        hushdLastError: string | null
      }
      render: () => void
      connectHushd: () => void
      hushdReconnectTimer: ReturnType<typeof setTimeout> | null
    }

    app.render = () => {}

    ;(Hushd as unknown as {
      getClient: typeof Hushd.getClient
      isInitialized: typeof Hushd.isInitialized
      init: typeof Hushd.init
      reset: typeof Hushd.reset
    }).isInitialized = () => false
    ;(Hushd as unknown as {
      getClient: typeof Hushd.getClient
      isInitialized: typeof Hushd.isInitialized
      init: typeof Hushd.init
      reset: typeof Hushd.reset
    }).init = () => {}
    ;(Hushd as unknown as {
      getClient: typeof Hushd.getClient
      isInitialized: typeof Hushd.isInitialized
      init: typeof Hushd.init
      reset: typeof Hushd.reset
    }).reset = () => {}
    ;(Hushd as unknown as {
      getClient: typeof Hushd.getClient
      isInitialized: typeof Hushd.isInitialized
      init: typeof Hushd.init
      reset: typeof Hushd.reset
    }).getClient = () => ({
      probe: async () => false,
    } as never)

    app.connectHushd()
    await Bun.sleep(0)

    expect(app.state.hushdStatus).toBe("disconnected")
    expect(app.state.hushdLastError).toBe("health probe failed")
    expect(app.state.hushdReconnectAttempts).toBe(1)
    expect(app.hushdReconnectTimer).not.toBeNull()

    if (app.hushdReconnectTimer) {
      clearTimeout(app.hushdReconnectTimer)
      app.hushdReconnectTimer = null
    }
  })

  test("ignores stale hushd probe failures after lifecycle cleanup", async () => {
    let resolveProbe!: (value: boolean) => void
    const probePromise = new Promise<boolean>((resolve) => {
      resolveProbe = resolve
    })

    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        hushdStatus: string
        hushdReconnectAttempts: number
      }
      render: () => void
      connectHushd: () => void
      hushdReconnectTimer: ReturnType<typeof setTimeout> | null
      hushdLifecycleToken: number
    }

    app.render = () => {}

    ;(Hushd as unknown as {
      getClient: typeof Hushd.getClient
      isInitialized: typeof Hushd.isInitialized
      init: typeof Hushd.init
      reset: typeof Hushd.reset
    }).isInitialized = () => false
    ;(Hushd as unknown as {
      getClient: typeof Hushd.getClient
      isInitialized: typeof Hushd.isInitialized
      init: typeof Hushd.init
      reset: typeof Hushd.reset
    }).init = () => {}
    ;(Hushd as unknown as {
      getClient: typeof Hushd.getClient
      isInitialized: typeof Hushd.isInitialized
      init: typeof Hushd.init
      reset: typeof Hushd.reset
    }).reset = () => {}
    ;(Hushd as unknown as {
      getClient: typeof Hushd.getClient
      isInitialized: typeof Hushd.isInitialized
      init: typeof Hushd.init
      reset: typeof Hushd.reset
    }).getClient = () => ({
      probe: async () => probePromise,
    } as never)

    app.connectHushd()
    app.hushdLifecycleToken += 1
    resolveProbe(false)
    await Bun.sleep(0)

    expect(app.state.hushdStatus).toBe("connecting")
    expect(app.state.hushdReconnectAttempts).toBe(0)
    expect(app.hushdReconnectTimer).toBeNull()
  })

  test("cleanup terminates an attached session and clears handoff state", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        attachedRunId: string | null
        pendingAttachRunId: string | null
        ptyHandoffActive: boolean
      }
      attachedSession: { terminate: () => void } | null
      cleanup: () => Promise<void>
    }

    let terminated = false
    app.state.attachedRunId = "run_attach"
    app.state.pendingAttachRunId = "run_attach"
    app.state.ptyHandoffActive = true
    app.attachedSession = {
      terminate: () => {
        terminated = true
      },
    }

    await app.cleanup()

    expect(terminated).toBe(true)
    expect(app.state.attachedRunId).toBeNull()
    expect(app.state.pendingAttachRunId).toBeNull()
    expect(app.state.ptyHandoffActive).toBe(false)
  })

  test("run stays active until quit performs final cleanup", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      start: () => Promise<void>
      cleanup: () => Promise<void>
      run: () => Promise<void>
      quit: () => Promise<void>
    }

    let started = false
    let cleaned = false
    let settled = false

    app.start = async () => {
      started = true
    }
    app.cleanup = async () => {
      cleaned = true
    }

    const runPromise = app.run().then(() => {
      settled = true
    })

    await Bun.sleep(0)
    expect(started).toBe(true)
    expect(settled).toBe(false)

    await app.quit()
    await runPromise

    expect(cleaned).toBe(true)
    expect(settled).toBe(true)
  })

  test("rejects unsupported attach runs before creating backlog entries", () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        dispatchSheet: {
          open: boolean
          prompt: string
          action: "dispatch" | "speculate"
          mode: "managed" | "attach" | "external"
          agentIndex: number
          focusedField: 0 | 1 | 2 | 3
          error: string | null
        }
        runs: {
          entries: unknown[]
        }
        inputMode: string
      }
      render: () => void
      launchDispatchSheet: () => void
    }

    app.render = () => {}
    app.state.dispatchSheet = {
      open: true,
      prompt: "open an attach session on an unsupported agent",
      action: "dispatch",
      mode: "attach",
      agentIndex: 2,
      focusedField: 0,
      error: null,
    }

    app.launchDispatchSheet()

    expect(app.state.runs.entries).toHaveLength(0)
    expect(app.state.dispatchSheet.error).toContain("does not expose an interactive attach session yet")
    expect(app.state.inputMode).toBe("main")
  })

  test("uses the embedded interactive surface for codex attach by default", () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        pendingAttachRunId: string | null
        runs: {
          entries: Array<ReturnType<typeof createManagedRun>>
        }
      }
      launchEmbeddedInteractiveRun: (runId: string) => Promise<void>
      launchAttachRun: (runId: string) => Promise<void>
      confirmAttachRun: () => void
    }

    let embeddedRunId: string | null = null
    let rawRunId: string | null = null
    app.launchEmbeddedInteractiveRun = async (runId) => {
      embeddedRunId = runId
    }
    app.launchAttachRun = async (runId) => {
      rawRunId = runId
    }

    const run = createManagedRun({
      prompt: "open codex interactively",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
      mode: "attach",
    })

    app.state.runs.entries = [run]
    app.state.pendingAttachRunId = run.id
    app.confirmAttachRun()

    expect(embeddedRunId === run.id).toBe(true)
    expect(rawRunId).toBeNull()
    expect(app.state.pendingAttachRunId).toBeNull()
  })

  test("falls back from staged external mode into managed execution", () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        runs: {
          entries: Array<ReturnType<typeof createManagedRun>>
        }
        externalSheet: {
          runId: string | null
          adapters: unknown[]
          selectedIndex: number
          loading: boolean
          error: string | null
        }
        statusMessage: string
      }
      render: () => void
      launchManagedRun: (run: ReturnType<typeof createManagedRun>) => Promise<void>
      launchRunInMode: (runId: string, mode: "managed" | "attach" | "external") => void
    }

    let launchedMode: "managed" | "attach" | "external" | null = null
    app.render = () => {}
    app.launchManagedRun = async (run) => {
      launchedMode = run.mode
    }

    const run = createManagedRun({
      prompt: "Retry this in managed mode",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
      mode: "external",
    })
    run.phase = "failed"
    run.completedAt = new Date().toISOString()
    run.external = {
      kind: "wezterm",
      adapterId: "wezterm",
      ref: null,
      status: "failed",
      error: "wezterm not found",
    }

    app.state.runs.entries = [run]
    app.state.externalSheet = {
      runId: run.id,
      adapters: [],
      selectedIndex: 0,
      loading: false,
      error: "wezterm not found",
    }

    app.launchRunInMode(run.id, "managed")

    expect(app.state.runs.entries[0]?.mode).toBe("managed")
    expect(app.state.runs.entries[0]?.phase).toBe("launching")
    expect(app.state.runs.entries[0]?.external.status).toBe("idle")
    expect(app.state.externalSheet.runId).toBeNull()
    expect(launchedMode as string | null).toBe("managed")
  })

  test("relaunches a completed managed run into external mode without mutating the original run", () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        runs: {
          entries: Array<ReturnType<typeof createManagedRun>>
        }
        statusMessage: string
        activeRunId: string | null
      }
      render: () => void
      beginExternalRunFlow: (runId: string) => Promise<void>
      relaunchRunInMode: (runId: string, mode: "attach" | "external") => void
    }

    let openedExternalRunId: string | null = null
    app.render = () => {}
    app.beginExternalRunFlow = async (runId) => {
      openedExternalRunId = runId
    }

    const run = createManagedRun({
      prompt: "Relaunch me externally",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    run.phase = "review_ready"
    run.completedAt = new Date().toISOString()
    run.result = {
      success: true,
      taskId: "task-review",
      agent: "Codex",
      action: "dispatch",
      duration: 1000,
    }

    app.state.runs.entries = [run]
    app.state.activeRunId = run.id

    app.relaunchRunInMode(run.id, "external")

    expect(app.state.runs.entries).toHaveLength(2)
    expect(app.state.runs.entries.some((entry) => entry.id === run.id && entry.phase === "review_ready")).toBe(true)
    const relaunched = app.state.runs.entries.find((entry) => entry.id !== run.id)
    const relaunchedId = relaunched?.id as string
    expect(relaunched?.mode).toBe("external")
    expect(relaunched?.phase).toBe("launching")
    expect(openedExternalRunId).not.toBeNull()
    if (openedExternalRunId === null) {
      throw new Error("expected external relaunch to open a new run")
    }
    expect(openedExternalRunId === relaunchedId).toBe(true)
  })

  test("showRuns picks a filter that includes the active completed run", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        runs: {
          entries: Array<ReturnType<typeof createManagedRun>>
          selectedRunId: string | null
          filter: "active" | "review_ready" | "all"
        }
        activeRunId: string | null
      }
      setScreen: (mode: "runs") => void
      showRuns: () => Promise<void>
    }

    let openedScreen: string | null = null
    app.setScreen = (mode) => {
      openedScreen = mode
    }

    const run = createManagedRun({
      prompt: "Reopen me from backlog",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    run.phase = "review_ready"
    run.completedAt = new Date().toISOString()
    run.result = {
      success: true,
      taskId: "task-review",
      agent: "Codex",
      action: "dispatch",
      duration: 1000,
    }

    app.state.runs.entries = [run]
    app.state.runs.filter = "active"
    app.state.runs.selectedRunId = null
    app.state.activeRunId = run.id

    await app.showRuns()

    expect(openedScreen === "runs").toBe(true)
    expect((app.state.runs.filter as unknown as string) === "review_ready").toBe(true)
    expect(app.state.runs.selectedRunId === run.id).toBe(true)
  })

  test("times out external sessions that never start", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      waitForExternalExit: (
        statusPath: string,
        startupTimeoutMs: number,
        livenessTimeoutMs: number,
        surfaceAlive?: () => Promise<boolean>,
        surfaceClosedMessage?: string,
      ) => Promise<number>
    }
    const dir = await mkdtemp(join(tmpdir(), "clawdstrike-external-timeout-"))
    const statusPath = join(dir, "external-status.json")

    await expect(app.waitForExternalExit(statusPath, 10, 50)).rejects.toThrow(
      "launch script never started",
    )
  })

  test("times out external sessions that stop reporting heartbeat after startup", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      waitForExternalExit: (
        statusPath: string,
        startupTimeoutMs: number,
        livenessTimeoutMs: number,
        surfaceAlive?: () => Promise<boolean>,
        surfaceClosedMessage?: string,
      ) => Promise<number>
    }
    const dir = await mkdtemp(join(tmpdir(), "clawdstrike-external-stale-"))
    const statusPath = join(dir, "external-status.json")

    await Bun.write(
      statusPath,
      JSON.stringify({
        state: "running",
        startedAt: new Date(Date.now() - 1_000).toISOString(),
        heartbeatAt: new Date(Date.now() - 1_000).toISOString(),
      }),
    )

    await expect(app.waitForExternalExit(statusPath, 100, 20)).rejects.toThrow(
      "stopped reporting liveness",
    )
  })

  test("reports closed external surfaces before heartbeat timeout", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      waitForExternalExit: (
        statusPath: string,
        startupTimeoutMs: number,
        livenessTimeoutMs: number,
        surfaceAlive?: () => Promise<boolean>,
        surfaceClosedMessage?: string,
      ) => Promise<number>
    }
    const dir = await mkdtemp(join(tmpdir(), "clawdstrike-external-closed-"))
    const statusPath = join(dir, "external-status.json")

    await Bun.write(
      statusPath,
      JSON.stringify({
        state: "running",
        startedAt: new Date().toISOString(),
        heartbeatAt: new Date().toISOString(),
      }),
    )

    await expect(
      app.waitForExternalExit(statusPath, 100, 5_000, async () => false, "External terminal window closed"),
    ).rejects.toThrow("External terminal window closed")
  })
})
