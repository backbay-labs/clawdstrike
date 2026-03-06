import { afterEach, describe, expect, test } from "bun:test"
import { TUIApp } from "../src/tui/app"
import { Hushd } from "../src/hushd"

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
})
