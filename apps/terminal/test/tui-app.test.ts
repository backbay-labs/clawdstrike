import { afterEach, describe, expect, test } from "bun:test"
import { TUIApp } from "../src/tui/app"
import { Hushd } from "../src/hushd"

const originalGetClient = Hushd.getClient
const originalIsInitialized = Hushd.isInitialized

afterEach(() => {
  ;(Hushd as unknown as {
    getClient: typeof Hushd.getClient
    isInitialized: typeof Hushd.isInitialized
  }).getClient = originalGetClient
  ;(Hushd as unknown as {
    getClient: typeof Hushd.getClient
    isInitialized: typeof Hushd.isInitialized
  }).isInitialized = originalIsInitialized
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
})
