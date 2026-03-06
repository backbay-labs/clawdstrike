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
      launchRunInMode: (runId: string, mode: "managed" | "attach") => void
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
    expect(app.state.runs.entries[0]?.external.status).toBe("idle")
    expect(app.state.externalSheet.runId).toBeNull()
    expect(launchedMode as string | null).toBe("managed")
  })

  test("times out external sessions that never start", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      waitForExternalExit: (statusPath: string, startupTimeoutMs: number) => Promise<number>
    }
    const dir = await mkdtemp(join(tmpdir(), "clawdstrike-external-timeout-"))
    const statusPath = join(dir, "external-status.json")

    await expect(app.waitForExternalExit(statusPath, 10)).rejects.toThrow(
      "launch script never started",
    )
  })
})
