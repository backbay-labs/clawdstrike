import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import * as fs from "node:fs/promises"
import * as os from "node:os"
import * as path from "node:path"
import type { AppController, AppState, InputMode, ScreenContext } from "../src/tui/types"
import {
  createInitialAuditLogState,
  createInitialDispatchSheetState,
  createInitialExternalExecutionSheetState,
  createInitialHuntState,
  createInitialInteractiveSessionState,
  createInitialRunListState,
} from "../src/tui/types"
import { THEME } from "../src/tui/theme"
import { createMainScreen } from "../src/tui/screens/main"
import { integrationsScreen } from "../src/tui/screens/integrations"
import { auditScreen } from "../src/tui/screens/audit"
import { huntReportScreen } from "../src/tui/screens/hunt-report"
import { huntReportHistoryScreen } from "../src/tui/screens/hunt-report-history"
import { huntQueryScreen } from "../src/tui/screens/hunt-query"
import { huntScanScreen } from "../src/tui/screens/hunt-scan"
import { huntTimelineScreen } from "../src/tui/screens/hunt-timeline"
import { huntWatchScreen } from "../src/tui/screens/hunt-watch"
import { runsScreen } from "../src/tui/screens/runs"
import { securityScreen } from "../src/tui/screens/security"
import { policyScreen } from "../src/tui/screens/policy"
import { getRecommendedSandboxIndex } from "../src/tui/screens/setup"
import { loadDesktopAgentSnapshotSync } from "../src/desktop-agent"
import { stripAnsi } from "../src/tui/components/types"
import { updateInvestigation, buildInvestigationReport } from "../src/tui/investigation"
import { exportReportBundle } from "../src/tui/report-export"
import { Hushd } from "../src/hushd"
import type { CheckEventData } from "../src/hushd"
import { createManagedRun } from "../src/tui/runs"

class TestApp implements AppController {
  public screen: InputMode | null = null
  public renderCount = 0
  public quitCalled = false
  public submitted: "dispatch" | "speculate" | null = null
  public launchedDispatchSheet = false
  public closedDispatchSheet = false
  public openedRunId: string | null = null
  public beganAttachRunId: string | null = null
  public confirmedAttach = false
  public canceledAttach = false
  public beganExternalRunId: string | null = null
  public confirmedExternal = false
  public canceledExternal = false
  public launchedFallback: { runId: string; mode: "managed" | "attach" | "external" } | null = null
  public relaunchedRun: { runId: string; mode: "attach" | "external" } | null = null
  public canceledRunId: string | null = null

  constructor(private cwd: string) {}

  setScreen(mode: InputMode): void {
    this.screen = mode
  }

  launchDispatchSheet(): void {
    this.launchedDispatchSheet = true
  }

  closeDispatchSheet(): void {
    this.closedDispatchSheet = true
  }

  openRun(runId: string): void {
    this.openedRunId = runId
  }

  beginAttachRun(runId: string): void {
    this.beganAttachRunId = runId
  }

  confirmAttachRun(): void {
    this.confirmedAttach = true
  }

  cancelAttachRun(): void {
    this.canceledAttach = true
  }

  beginExternalRun(runId: string): void {
    this.beganExternalRunId = runId
  }

  confirmExternalRun(): void {
    this.confirmedExternal = true
  }

  cancelExternalRun(): void {
    this.canceledExternal = true
  }

  launchRunInMode(runId: string, mode: "managed" | "attach" | "external"): void {
    this.launchedFallback = { runId, mode }
  }

  relaunchRunInMode(runId: string, mode: "attach" | "external"): void {
    this.relaunchedRun = { runId, mode }
  }

  cancelRun(runId: string): void {
    this.canceledRunId = runId
  }

  render(): void {
    this.renderCount += 1
  }

  runHealthcheck(): void {}
  connectHushd(): void {}
  submitPrompt(action: "dispatch" | "speculate"): void {
    this.submitted = action
  }
  runGates(): void {}
  showBeads(): void {}
  showRuns(): void {
    this.screen = "runs"
  }
  showHelp(): void {}
  quit(): void {
    this.quitCalled = true
  }
  getCwd(): string {
    return this.cwd
  }
  refreshDesktopAgent(): void {}
}

function createState(): AppState {
  return {
    promptBuffer: "",
    agentIndex: 0,
    homeActionIndex: 0,
    homeFocus: "prompt",
    homePromptTraceStartFrame: 0,
    homeActionsTraceStartFrame: 0,
    inputMode: "main",
    commandIndex: 0,
    statusMessage: "",
    isRunning: false,
    activeRuns: 0,
    openBeads: 0,
    lastRefresh: new Date(),
    health: null,
    healthChecking: false,
    animationFrame: 0,
    runtimeInfo: null,
    desktopAgent: null,
    hushdStatus: "disconnected",
    hushdConnected: false,
    hushdLastEventAt: null,
    hushdLastError: null,
    hushdReconnectAttempts: 0,
    hushdDroppedEvents: 0,
    recentEvents: [],
    recentAuditPreview: [],
    auditLog: createInitialAuditLogState(),
    auditStats: null,
    activePolicy: null,
    securityError: null,
    dispatchSheet: createInitialDispatchSheetState(),
    externalSheet: createInitialExternalExecutionSheetState(),
    runs: createInitialRunListState(),
    interactiveSession: createInitialInteractiveSessionState(),
    activeRunId: null,
    pendingAttachRunId: null,
    attachedRunId: null,
    ptyHandoffActive: false,
    runDetailEvents: { offset: 0, selected: 0 },
    lastResult: null,
    setupDetection: null,
    setupStep: "detecting",
    setupSandboxIndex: 0,
    hunt: createInitialHuntState(),
  }
}

function createContext(
  state: AppState,
  app: AppController,
  width = 100,
  height = 32,
): ScreenContext {
  return {
    state,
    width,
    height,
    theme: THEME,
    app,
  }
}

async function waitForWatchError(state: AppState, timeoutMs = 2500): Promise<void> {
  const started = Date.now()
  while (state.hunt.watch.error == null && Date.now() - started < timeoutMs) {
    await Bun.sleep(25)
  }
}

let tempDir: string

beforeEach(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-tui-screen-"))
})

afterEach(async () => {
  await fs.rm(tempDir, { recursive: true, force: true })
})

describe("main screen", () => {
  test("opens home shortcuts from an empty prompt by default", () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const ctx = createContext(state, app)

    expect(screen.handleInput("W", ctx)).toBe(true)
    expect(app.screen).toBe("hunt-watch")
    expect(state.promptBuffer).toBe("")
    expect(state.homeFocus).toBe("prompt")
  })

  test("uses home hotkeys only in nav focus", () => {
    const state = createState()
    state.homeFocus = "nav"
    const screen = createMainScreen([])
    const securityApp = new TestApp(tempDir)
    const securityCtx = createContext(state, securityApp)

    expect(screen.handleInput("S", securityCtx)).toBe(true)
    expect(securityApp.screen).toBe("security")

    const auditApp = new TestApp(tempDir)
    const auditCtx = createContext(state, auditApp)
    expect(screen.handleInput("A", auditCtx)).toBe(true)
    expect(auditApp.screen).toBe("audit")

    const policyApp = new TestApp(tempDir)
    const policyCtx = createContext(state, policyApp)
    expect(screen.handleInput("P", policyCtx)).toBe(true)
    expect(policyApp.screen).toBe("policy")

    const integrationsApp = new TestApp(tempDir)
    const integrationsCtx = createContext(state, integrationsApp)
    expect(screen.handleInput("I", integrationsCtx)).toBe(true)
    expect(integrationsApp.screen).toBe("integrations")

    const runsApp = new TestApp(tempDir)
    const runsCtx = createContext(state, runsApp)
    expect(screen.handleInput("R", runsCtx)).toBe(true)
    expect(runsApp.screen).toBe("runs")
  })

  test("supports tab into actions, arrow-key selection, and enter to open", () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const ctx = createContext(state, app)

    expect(screen.handleInput("\t", ctx)).toBe(true)
    expect(state.homeFocus).toBe("actions")

    expect(screen.handleInput("\x1b[B", ctx)).toBe(true)
    expect(state.homeActionIndex).toBe(2)

    expect(screen.handleInput("\x1b[C", ctx)).toBe(true)
    expect(state.homeActionIndex).toBe(3)

    expect(screen.handleInput("\r", ctx)).toBe(true)
    expect(app.screen).toBe("integrations")
  })

  test("uses esc to toggle prompt and nav focus without clearing prompt text", () => {
    const state = createState()
    state.promptBuffer = "triage "
    state.animationFrame = 12
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const ctx = createContext(state, app)

    expect(screen.handleInput("\x1b", ctx)).toBe(true)
    expect(state.homeFocus).toBe("nav")
    expect(state.promptBuffer).toBe("triage ")
    expect(state.homeActionsTraceStartFrame).toBe(12)

    expect(screen.handleInput("\x1b", ctx)).toBe(true)
    expect(state.homeFocus).toBe("prompt")
    expect(state.promptBuffer).toBe("triage ")
    expect(state.homePromptTraceStartFrame).toBe(12)
  })

  test("keeps printable keys as prompt input when text already exists", () => {
    const state = createState()
    state.promptBuffer = "triage "
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const ctx = createContext(state, app)

    expect(screen.handleInput("W", ctx)).toBe(true)
    expect(app.screen).toBeNull()
    expect(state.promptBuffer).toBe("triage W")
  })

  test("keeps home hotkeys in the prompt once typing has started", () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const ctx = createContext(state, app)

    expect(screen.handleInput("f", ctx)).toBe(true)
    expect(app.screen).toBeNull()
    expect(state.promptBuffer).toBe("f")

    expect(screen.handleInput("W", ctx)).toBe(true)
    expect(app.screen).toBeNull()
    expect(state.promptBuffer).toBe("fW")
  })

  test("does not open the selected home action when enter is pressed in prompt focus", () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const ctx = createContext(state, app)

    state.homeActionIndex = 3

    expect(screen.handleInput("\r", ctx)).toBe(true)
    expect(app.screen).toBeNull()
    expect(app.submitted).toBeNull()
  })

  test("cycles between prompt and actions with tab", () => {
    const state = createState()
    state.animationFrame = 9
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const ctx = createContext(state, app)

    expect(screen.handleInput("\t", ctx)).toBe(true)
    expect(state.homeFocus).toBe("actions")
    expect(state.homeActionsTraceStartFrame).toBe(9)

    expect(screen.handleInput("\t", ctx)).toBe(true)
    expect(state.homeFocus).toBe("prompt")
    expect(state.homePromptTraceStartFrame).toBe(9)
  })

  test("renders focus-aware home hints", () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])

    const promptOutput = stripAnsi(screen.render(createContext(state, app, 120, 36)))
    expect(promptOutput).toContain("Dispatch [prompt]")
    expect(promptOutput).toContain("Prompt focus:")
    expect(promptOutput).toContain("Enter dispatch sheet")
    expect(promptOutput).toContain("empty prompt keeps")
    expect(promptOutput).toContain("W/X/T/Q/E/H live")

    state.homeFocus = "actions"
    const actionsOutput = stripAnsi(screen.render(createContext(state, app, 120, 36)))
    expect(actionsOutput).toContain("Dispatch [actions]")
    expect(actionsOutput).toContain("Actions focus:")
    expect(actionsOutput).toContain("Ops Snapshot • actions")
    expect(actionsOutput).toContain("Selected [S] Security overview")

    state.homeFocus = "nav"
    const navOutput = stripAnsi(screen.render(createContext(state, app, 120, 36)))
    expect(navOutput).toContain("Dispatch [nav]")
    expect(navOutput).toContain("Nav mode:")
    expect(navOutput).toContain("Ops Snapshot • nav")
  })

  test("renders degraded health, stale stream state, and last deny summary", () => {
    const state = createState()
    state.hushdConnected = true
    state.hushdStatus = "connected"
    state.health = {
      security: [{ id: "hushd", name: "hushd", category: "security", available: true, checkedAt: Date.now() }],
      ai: [{ id: "codex", name: "Codex", category: "ai", available: false, checkedAt: Date.now(), error: "not found" }],
      infra: [{ id: "git", name: "Git", category: "infra", available: true, checkedAt: Date.now() }],
      mcp: [],
      checkedAt: Date.now(),
    }
    state.recentEvents = [
      {
        type: "check",
        timestamp: new Date(Date.now() - 8 * 60_000).toISOString(),
        data: {
          action_type: "shell",
          target: "/very/long/path/that/should/still/appear/in/the/deny/summary.txt",
          decision: "deny",
          guard: "shell.policy",
          severity: "error",
        } satisfies CheckEventData,
      },
    ]

    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const output = stripAnsi(screen.render(createContext(state, app, 120, 36)))

    expect(output).toContain("Health: degraded")
    expect(output).toContain("Stream: stale")
    expect(output).toContain("Last deny:")
    expect(output).toContain("shell.policy")
  })

  test("renders full home navigation copy without truncating the shortcut hint", () => {
    const state = createState()
    state.hushdConnected = true
    state.hushdStatus = "connected"
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const output = stripAnsi(screen.render(createContext(state, app, 120, 36)))

    expect(output).toContain("Prompt focus:")
    expect(output).toContain("Integrations runtime status")
    expect(output).toContain("Timeline event replay")
  })
})

describe("runs screen", () => {
  test("cycles filters and opens the selected run detail", () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const activeRun = createManagedRun({
      prompt: "Keep running",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    activeRun.phase = "executing"
    const reviewRun = createManagedRun({
      prompt: "Ready for review",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    reviewRun.phase = "review_ready"
    reviewRun.completedAt = "2026-03-06T09:00:00Z"
    reviewRun.result = {
      success: true,
      taskId: "task-runs-screen",
      agent: "Codex",
      action: "dispatch",
      duration: 500,
    }
    state.runs.entries = [activeRun, reviewRun]

    const ctx = createContext(state, app, 128, 34)
    expect(stripAnsi(runsScreen.render(ctx))).toContain("Managed Runs")

    expect(runsScreen.handleInput("f", ctx)).toBe(true)
    expect(state.runs.filter).toBe("review_ready")
    expect(state.runs.selectedRunId).toBe(reviewRun.id)

    expect(runsScreen.handleInput("\r", ctx)).toBe(true)
    expect(app.openedRunId).toBe(reviewRun.id)
  })
})

describe("setup sandbox mapping", () => {
  test("maps recommended sandbox through the available option list", () => {
    expect(getRecommendedSandboxIndex("inplace", false)).toBe(0)
    expect(getRecommendedSandboxIndex("worktree", true)).toBe(1)
    expect(getRecommendedSandboxIndex("tmpdir", false)).toBe(2)
  })

  test("falls back to inplace when the recommended sandbox is unavailable", () => {
    expect(getRecommendedSandboxIndex("worktree", false)).toBe(0)
  })
})

describe("supported surface polish", () => {
  test("shortens long integration runtime values into labeled blocks", () => {
    const state = createState()
    state.runtimeInfo = {
      source: "repo-source",
      scriptPath: "/Users/connor/Medica/backbay/standalone/clawdstrike-sdks/apps/terminal/src/cli/index.ts",
      bunVersion: "1.3.3",
    }
    state.desktopAgent = {
      found: true,
      enabled: true,
      enrolled: true,
      enrollmentInProgress: false,
      settingsPath: "/Users/connor/Library/Application Support/clawdstrike/agent.json",
      localAgentId: "endpoint-e5a1cf6a-3311-4882-a596-4151d240d241",
      daemonPort: 9876,
      mcpPort: 9877,
      agentApiPort: 9878,
      dashboardUrl: "http://127.0.0.1:9878/ui",
      tenantId: "tenant-dogfood-1",
      natsEnabled: true,
      natsUrl: "nats://k8s-clawdstr-clawdstr-c56cf8ccc8-ae1abaa88d768410.elb.us-east-1.amazonaws.com:4222",
      natsCredsFile: null,
      natsToken: "token",
      nkeySeed: null,
      natsTokenConfigured: true,
      nkeySeedConfigured: false,
      subjectPrefix: "tenant.desktop",
      error: null,
    }
    state.hushdStatus = "connected"

    const output = stripAnsi(integrationsScreen.render(createContext(state, new TestApp(tempDir), 90, 28)))

    expect(output).toContain("entry:")
    expect(output).toContain("cluster stream:")
    expect(output).toContain("dashboard:")
    expect(output).toContain("…")
  })

  test("keeps audit rows clear of the split divider", () => {
    const state = createState()
    state.auditLog.events = [
      {
        id: "audit-1",
        timestamp: new Date().toISOString(),
        event_type: "local_service_session_created",
        action_type: "session",
        decision: "allowed",
        target: "local_service_session_created_for_really_long_target_name",
        session_id: "session-1",
        agent_id: null,
        guard: null,
        message: null,
        metadata: {},
      },
    ]

    const output = stripAnsi(auditScreen.render(createContext(state, new TestApp(tempDir), 100, 24)))

    expect(output).toContain("Audit Events")
    expect(output).toContain(" │ ╭")
    expect(output).toContain("allowed local_…created")
  })

  test("renders an audit scope summary inside the list pane", () => {
    const state = createState()
    state.auditLog.filters.decision = "blocked"
    state.auditLog.filters.eventType = "report_export"
    state.auditLog.filters.sessionId = "session-prod-9"
    state.auditLog.offset = 20
    state.auditLog.limit = 20
    state.auditLog.hasMore = true
    state.auditLog.events = [
      {
        id: "audit-1",
        timestamp: new Date().toISOString(),
        event_type: "report_export",
        action_type: "report",
        decision: "blocked",
        target: "/reports/20260306-policy.md",
        session_id: "session-prod-9",
        agent_id: null,
        guard: null,
        message: "export blocked",
        metadata: {},
      },
    ]

    const output = stripAnsi(auditScreen.render(createContext(state, new TestApp(tempDir), 110, 24)))

    expect(output).toContain("scope: blocked / report_export")
    expect(output).toContain("session: session-prod-9")
    expect(output).toContain("showing: 21-21")
    expect(output).toContain("next page ready")
  })

  test("uses daemon cursors for audit pagination", async () => {
    const state = createState()
    state.auditLog.nextCursor = "off_20"
    state.auditLog.hasMore = true
    const app = new TestApp(tempDir)
    const queries: Array<Record<string, unknown>> = []
    const originalGetClient = Hushd.getClient

    try {
      ;(Hushd as unknown as { getClient: typeof Hushd.getClient }).getClient = () => ({
        getAuditDetailed: async (query?: Record<string, unknown>) => {
          queries.push(query ?? {})
          return {
            ok: true,
            status: 200,
            data: {
              events: [],
              total: 0,
              offset: 20,
              limit: 20,
              next_cursor: "off_40",
              has_more: true,
            },
          }
        },
      } as never)

      expect(auditScreen.handleInput("n", createContext(state, app, 110, 24))).toBe(true)
      await Bun.sleep(0)

      expect(queries).toHaveLength(1)
      expect(queries[0]?.cursor).toBe("off_20")
      expect(queries[0]?.offset).toBeUndefined()
      expect(state.auditLog.cursor).toBe("off_20")
      expect(state.auditLog.previousCursors).toEqual([null])
    } finally {
      ;(Hushd as unknown as { getClient: typeof Hushd.getClient }).getClient = originalGetClient
    }
  })

  test("keeps the report help bar readable at 80 columns", () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const output = stripAnsi(huntReportScreen.render(createContext(state, app, 80, 24)))

    expect(output).toContain("c copy")
    expect(output).toContain("ESC back")
    expect(output).not.toContain("c copy J")
  })
})

describe("hunt state cards", () => {
  test("keeps the scan header visible during loading", () => {
    const state = createState()
    state.hunt.scan.loading = true
    const app = new TestApp(tempDir)

    const output = stripAnsi(huntScanScreen.render(createContext(state, app, 100, 24)))

    expect(output).toContain("HUNT // MCP Scan Explorer [beta]")
    expect(output).toContain("Scan In Progress")
  })

  test("keeps the query header visible in empty state", () => {
    const state = createState()
    const app = new TestApp(tempDir)

    const output = stripAnsi(huntQueryScreen.render(createContext(state, app, 100, 24)))

    expect(output).toContain("HUNT // Hunt Query [beta]")
    expect(output).toContain("No Matches")
  })

  test("keeps the timeline header visible in error state", () => {
    const state = createState()
    state.hunt.timeline.error = "timeline failed"
    const app = new TestApp(tempDir)

    const output = stripAnsi(huntTimelineScreen.render(createContext(state, app, 100, 24)))

    expect(output).toContain("HUNT // Timeline Replay [beta]")
    expect(output).toContain("Timeline Failed")
  })

  test("compresses scan rows while keeping full detail context", () => {
    const state = createState()
    state.hunt.scan.results = [
      {
        client: "cursor",
        path: "/Users/connor/Library/Application Support/Cursor/User/globalStorage/mcp.json",
        issues: [{ severity: "warning", code: "path-warning", message: "Path issue" }],
        servers: [
          {
            name: "filesystem",
            command: "/usr/local/bin/fs-mcp",
            args: ["--stdio"],
            issues: [{ severity: "warning", code: "unused", message: "Unused server entry" }],
            violations: [],
          },
        ],
        errors: [],
      },
    ]
    state.hunt.scan.tree.expandedKeys = new Set([state.hunt.scan.results[0].path])
    const app = new TestApp(tempDir)

    const output = stripAnsi(huntScanScreen.render(createContext(state, app, 100, 28)))

    expect(output).toContain("cursor · mcp.json 1s 2i")
    expect(output).toContain("Path: /Users/connor/Library/Applicati")
    expect(output).toContain("Support/Cursor/User/globalStora")
    expect(output).not.toContain("cursor — /Users/connor/Library")
  })
})

describe("audit metadata rendering", () => {
  test("pretty-prints nested metadata instead of clipping JSON blobs", () => {
    const state = createState()
    state.auditLog.events = [
      {
        id: "evt-1",
        timestamp: "2026-03-06T06:20:12Z",
        decision: "allowed",
        event_type: "report_export",
        action_type: "report_export",
        message: "Report exported",
        metadata: {
          principal: {
            source_ip: "127.0.0.1",
            issuer: "Local Service",
            roles: ["local-service"],
          },
        },
      },
    ]
    const app = new TestApp(tempDir)

    const output = stripAnsi(auditScreen.render(createContext(state, app, 84, 26)))

    expect(output).toContain("principal: {")
    expect(output).toContain("\"source_ip\": \"127.0.0.1\"")
    expect(output).toContain("\"issuer\": \"Local Service\"")
  })
})

describe("hunt report screen", () => {
  test("supports expand and manual scroll for evidence details", () => {
    const state = createState()
    updateInvestigation(state, {
      origin: "query",
      title: "Expanded Evidence",
      summary: "A report with details that require scrolling.",
      query: "deny events",
      events: [
        {
          timestamp: new Date().toISOString(),
          source: "receipt",
          kind: "policy_violation",
          verdict: "deny",
          summary: "Denied write to policy file",
          details: {
            path: "/tmp/policy.yaml",
            actor: "codex",
            policy: "strict",
            reason: "blocked by policy",
            extra1: "one",
            extra2: "two",
            extra3: "three",
            extra4: "four",
            extra5: "five",
          },
        },
      ],
      findings: ["deny: Denied write to policy file"],
    })
    state.hunt.report.report = buildInvestigationReport(state)

    const app = new TestApp(tempDir)
    const ctx = createContext(state, app, 96, 16)

    expect(huntReportScreen.handleInput("\r", ctx)).toBe(true)
    expect(state.hunt.report.expandedEvidence).toBe(0)

    const rendered = stripAnsi(huntReportScreen.render(ctx))
    expect(rendered).toContain("Source:")
    expect(rendered).toContain("more evidence below")

    expect(huntReportScreen.handleInput("J", ctx)).toBe(true)
    expect(state.hunt.report.list.offset).toBeGreaterThan(0)

    expect(huntReportScreen.handleInput("K", ctx)).toBe(true)
    expect(state.hunt.report.list.offset).toBeGreaterThanOrEqual(0)
  })

  test("exports a markdown and json bundle from the screen", async () => {
    const state = createState()
    updateInvestigation(state, {
      origin: "timeline",
      title: "Export Investigation",
      summary: "Ready for evidence handoff.",
      query: "source=receipt",
      events: [
        {
          timestamp: new Date().toISOString(),
          source: "receipt",
          kind: "policy_violation",
          verdict: "deny",
          summary: "Denied write to secrets file",
          details: { path: "/tmp/secrets.env", tool: "claude" },
        },
      ],
      findings: ["deny: Denied write to secrets file"],
    })
    state.hunt.report.report = buildInvestigationReport(state)

    const app = new TestApp(tempDir)
    const ctx = createContext(state, app, 100, 24)

    expect(huntReportScreen.handleInput("x", ctx)).toBe(true)
    await Bun.sleep(25)

    const reportDir = path.join(tempDir, ".clawdstrike", "reports")
    const entries = await fs.readdir(reportDir)

    expect(entries.some((entry) => entry.endsWith(".json"))).toBe(true)
    expect(entries.some((entry) => entry.endsWith(".md"))).toBe(true)
    expect(stripAnsi(state.hunt.report.statusMessage ?? "")).toContain("Exported report bundle:")
  })

  test("exports a zero-evidence scan report from the screen", async () => {
    const state = createState()
    updateInvestigation(state, {
      origin: "scan",
      title: "MCP Scan Explorer",
      summary: "8 path(s) scanned for MCP exposure and policy drift.",
      query: null,
      events: [],
      findings: ["warning: Unused MCP server configuration detected"],
    })
    state.hunt.report.report = buildInvestigationReport(state)

    const app = new TestApp(tempDir)
    const ctx = createContext(state, app, 100, 24)

    expect(huntReportScreen.handleInput("x", ctx)).toBe(true)
    await Bun.sleep(25)

    const reportDir = path.join(tempDir, ".clawdstrike", "reports")
    const entries = await fs.readdir(reportDir)

    expect(entries.some((entry) => entry.endsWith(".json"))).toBe(true)
    expect(entries.some((entry) => entry.endsWith(".md"))).toBe(true)
    expect(stripAnsi(state.hunt.report.statusMessage ?? "")).toContain("Exported report bundle:")
  })

  test("preserves not-configured audit traceability during export", async () => {
    const state = createState()
    state.hushdStatus = "not_configured"
    updateInvestigation(state, {
      origin: "scan",
      title: "MCP Scan Explorer",
      summary: "8 path(s) scanned for MCP exposure and policy drift.",
      query: null,
      events: [],
      findings: ["warning: Unused MCP server configuration detected"],
    })
    state.hunt.report.report = buildInvestigationReport(state)

    const app = new TestApp(tempDir)
    const ctx = createContext(state, app, 100, 24)

    expect(huntReportScreen.handleInput("x", ctx)).toBe(true)
    await Bun.sleep(25)

    expect(stripAnsi(state.hunt.report.statusMessage ?? "")).toContain("[audit:not_configured]")
    expect(state.hunt.reportHistory.entries[0]?.traceability.auditStatus).toBe("not_configured")
  })

  test("opens exported reports from history", async () => {
    const state = createState()
    updateInvestigation(state, {
      origin: "timeline",
      title: "History Entry",
      summary: "Previously exported report.",
      query: "source=receipt",
      events: [
        {
          timestamp: new Date().toISOString(),
          source: "receipt",
          kind: "policy_violation",
          verdict: "deny",
          summary: "Denied write to lockfile",
          details: { receipt_id: "rcpt-1", audit_id: "audit-1" },
        },
      ],
      findings: ["deny: Denied write to lockfile"],
    })
    const report = buildInvestigationReport(state)
    await exportReportBundle(report!, tempDir)

    const app = new TestApp(tempDir)
    const ctx = createContext(state, app, 110, 24)

    huntReportHistoryScreen.onEnter?.(ctx)
    await Bun.sleep(25)

    const rendered = stripAnsi(huntReportHistoryScreen.render(ctx))
    expect(rendered).toContain("History Entry")
    expect(rendered).toContain("Export Bundles")
    expect(rendered).toContain("Traceability")
    expect(rendered).toContain("rcpt-1")

    expect(huntReportHistoryScreen.handleInput("\r", ctx)).toBe(true)
    await Bun.sleep(25)

    expect(app.screen).toBe("hunt-report")
    expect(state.hunt.report.report?.title).toBe("History Entry")
    expect(stripAnsi(state.hunt.report.statusMessage ?? "")).toContain("Loaded exported report:")
  })

  test("supports ANSI arrow keys in report history", async () => {
    const state = createState()
    updateInvestigation(state, {
      origin: "timeline",
      title: "First Entry",
      summary: "First exported report.",
      query: "source=receipt",
      events: [],
      findings: ["first"],
    })
    await exportReportBundle(buildInvestigationReport(state)!, tempDir)

    updateInvestigation(state, {
      origin: "timeline",
      title: "Second Entry",
      summary: "Second exported report.",
      query: "source=receipt",
      events: [],
      findings: ["second"],
    })
    await exportReportBundle(buildInvestigationReport(state)!, tempDir)

    const app = new TestApp(tempDir)
    const ctx = createContext(state, app, 110, 24)

    huntReportHistoryScreen.onEnter?.(ctx)
    await Bun.sleep(25)

    expect(state.hunt.reportHistory.list.selected).toBe(0)
    expect(huntReportHistoryScreen.handleInput("\x1b[B", ctx)).toBe(true)
    expect(state.hunt.reportHistory.list.selected).toBe(1)
    expect(huntReportHistoryScreen.handleInput("\x1b[A", ctx)).toBe(true)
    expect(state.hunt.reportHistory.list.selected).toBe(0)
  })

  test("returns to the originating hunt screen when exiting report", () => {
    const state = createState()
    updateInvestigation(state, {
      origin: "watch",
      title: "Watch Investigation",
      summary: "Return to watch after reviewing evidence.",
      query: "deny events",
      events: [
        {
          timestamp: new Date().toISOString(),
          source: "receipt",
          kind: "policy_violation",
          verdict: "deny",
          summary: "Denied change to policy file",
          details: { path: "/tmp/policy.yaml" },
        },
      ],
      findings: ["deny: Denied change to policy file"],
    })
    state.hunt.report.report = buildInvestigationReport(state)
    state.hunt.report.returnScreen = "hunt-watch"

    const app = new TestApp(tempDir)
    const ctx = createContext(state, app, 100, 24)

    expect(huntReportScreen.handleInput("q", ctx)).toBe(true)
    expect(app.screen).toBe("hunt-watch")
  })
})

describe("hunt watch screen", () => {
  test("explains when the workstation is local-only", async () => {
    const state = createState()
    state.hushdConnected = true
    state.hushdStatus = "connected"

    const settingsPath = path.join(tempDir, "agent.json")
    await fs.writeFile(settingsPath, JSON.stringify({
      enabled: true,
      daemon_port: 9876,
      mcp_port: 9877,
      agent_api_port: 9878,
      dashboard_url: "http://127.0.0.1:9878/ui",
      local_agent_id: "endpoint-local",
      nats: { enabled: false, nats_url: null, creds_file: null, token: null, nkey_seed: null },
      enrollment: { enrolled: false, enrollment_in_progress: false },
    }))

    const original = process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH
    process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH = settingsPath
    state.desktopAgent = loadDesktopAgentSnapshotSync()

    try {
      const app = new TestApp(tempDir)
      const ctx = createContext(state, app, 108, 20)

      huntWatchScreen.onEnter?.(ctx)

      expect(state.hunt.watch.running).toBe(false)
      expect(state.hunt.watch.error).toContain("cluster streaming is not configured")

      const rendered = stripAnsi(huntWatchScreen.render(ctx))
      expect(rendered).toContain("Cluster watch unavailable")
      expect(rendered).toContain("Use Security or Audit for local")
      expect(rendered).toContain("events, or enroll the desktop agent")
    } finally {
      if (original == null) delete process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH
      else process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH = original
    }
  })

  test("surfaces launch failures inside the screen", async () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const ctx = createContext(state, app, 96, 18)
    const fakeBinary = path.join(tempDir, "clawdstrike-watch-stub")

    await fs.writeFile(fakeBinary, "#!/bin/sh\necho 'stub watch failed' >&2\nexit 5\n")
    await fs.chmod(fakeBinary, 0o755)

    const original = process.env.CLAWDSTRIKE_TUI_HUNT_BINARY
    process.env.CLAWDSTRIKE_TUI_HUNT_BINARY = fakeBinary

    try {
      huntWatchScreen.onEnter?.(ctx)
      await waitForWatchError(state)

      expect(state.hunt.watch.running).toBe(false)
      expect(state.hunt.watch.error).toContain("stub watch failed")

      const rendered = stripAnsi(huntWatchScreen.render(ctx))
      expect(rendered).toContain("Cluster watch unavailable")
      expect(rendered).toContain("stub watch failed")
    } finally {
      if (original == null) delete process.env.CLAWDSTRIKE_TUI_HUNT_BINARY
      else process.env.CLAWDSTRIKE_TUI_HUNT_BINARY = original
    }
  })

  test("collapses structured json watch failures into a readable message", async () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const ctx = createContext(state, app, 96, 18)
    const fakeBinary = path.join(tempDir, "clawdstrike-watch-json-stub")

    await fs.writeFile(
      fakeBinary,
      "#!/bin/sh\ncat <<'EOF'\n{\n  \"version\": 1,\n  \"command\": \"hunt watch\",\n  \"exit_code\": 4,\n  \"error\": {\n    \"kind\": \"runtime_error\",\n    \"message\": \"Watch failed: NATS error: connection refused\"\n  },\n  \"data\": null\n}\nEOF\nexit 4\n",
    )
    await fs.chmod(fakeBinary, 0o755)

    const original = process.env.CLAWDSTRIKE_TUI_HUNT_BINARY
    process.env.CLAWDSTRIKE_TUI_HUNT_BINARY = fakeBinary

    try {
      huntWatchScreen.onEnter?.(ctx)
      await waitForWatchError(state)

      expect(state.hunt.watch.running).toBe(false)
      expect(state.hunt.watch.error).toContain("Watch failed: NATS error: connection refused")

      const rendered = stripAnsi(huntWatchScreen.render(ctx))
      expect(rendered).toContain("Cluster watch unavailable")
      expect(rendered).toContain("Watch failed: NATS error: connection refused")
      expect(rendered).not.toContain("Failed to parse stream line")
    } finally {
      if (original == null) delete process.env.CLAWDSTRIKE_TUI_HUNT_BINARY
      else process.env.CLAWDSTRIKE_TUI_HUNT_BINARY = original
    }
  })

  test("passes token-backed desktop-agent auth through the environment", async () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const ctx = createContext(state, app, 96, 18)
    const fakeBinary = path.join(tempDir, "clawdstrike-watch-token-stub")
    const settingsPath = path.join(tempDir, "agent.json")

    await fs.writeFile(settingsPath, JSON.stringify({
      enabled: true,
      daemon_port: 9876,
      mcp_port: 9877,
      agent_api_port: 9878,
      dashboard_url: "http://127.0.0.1:9878/ui",
      local_agent_id: "endpoint-cluster",
      nats: {
        enabled: true,
        nats_url: "nats://cluster.example:4222",
        creds_file: null,
        token: "secret-token",
        nkey_seed: null,
      },
      enrollment: { enrolled: true, enrollment_in_progress: false },
    }))

    await fs.writeFile(
      fakeBinary,
      [
        "#!/bin/sh",
        "case \" $* \" in",
        "  *\" --nats-token \"*) echo 'token leaked on argv' >&2; exit 7 ;;",
        "esac",
        "if [ \"$CLAWDSTRIKE_HUNT_NATS_TOKEN\" != \"secret-token\" ]; then echo 'missing token env' >&2; exit 6; fi",
        "echo 'cluster connect failed' >&2",
        "exit 5",
      ].join("\n"),
    )
    await fs.chmod(fakeBinary, 0o755)

    const originalBinary = process.env.CLAWDSTRIKE_TUI_HUNT_BINARY
    const originalSettings = process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH
    process.env.CLAWDSTRIKE_TUI_HUNT_BINARY = fakeBinary
    process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH = settingsPath
    state.desktopAgent = loadDesktopAgentSnapshotSync()

    try {
      huntWatchScreen.onEnter?.(ctx)
      await waitForWatchError(state)

      expect(state.hunt.watch.running).toBe(false)
      expect(state.hunt.watch.error).toContain("cluster connect failed")
      expect(state.hunt.watch.error).not.toContain("missing token env")
      expect(state.hunt.watch.error).not.toContain("token leaked on argv")
    } finally {
      if (originalBinary == null) delete process.env.CLAWDSTRIKE_TUI_HUNT_BINARY
      else process.env.CLAWDSTRIKE_TUI_HUNT_BINARY = originalBinary
      if (originalSettings == null) delete process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH
      else process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH = originalSettings
    }
  })
})

describe("integrations screen", () => {
  test("shows desktop-agent enrollment and cluster-watch status", async () => {
    const state = createState()
    state.hushdConnected = true
    state.hushdStatus = "connected"

    const settingsPath = path.join(tempDir, "agent.json")
    await fs.writeFile(settingsPath, JSON.stringify({
      enabled: true,
      daemon_port: 9876,
      mcp_port: 9877,
      agent_api_port: 9878,
      dashboard_url: "http://127.0.0.1:9878/ui",
      local_agent_id: "endpoint-local",
      nats: { enabled: false, nats_url: null, creds_file: null, token: null, nkey_seed: null },
      enrollment: { enrolled: false, enrollment_in_progress: false },
    }))

    const original = process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH
    process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH = settingsPath
    state.desktopAgent = loadDesktopAgentSnapshotSync()

    try {
      const app = new TestApp(tempDir)
      const rendered = stripAnsi(integrationsScreen.render(createContext(state, app, 120, 34)))

      expect(rendered).toContain("Desktop Agent")
      expect(rendered).toContain("not enrolled")
      expect(rendered).toContain("cluster stream: disabled")
      expect(rendered).toContain("Use Security or Audit for local events")
    } finally {
      if (original == null) delete process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH
      else process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH = original
    }
  })

  test("shows token-backed cluster watch as configured", async () => {
    const state = createState()
    state.hushdConnected = true
    state.hushdStatus = "connected"

    const settingsPath = path.join(tempDir, "agent.json")
    await fs.writeFile(settingsPath, JSON.stringify({
      enabled: true,
      daemon_port: 9876,
      mcp_port: 9877,
      agent_api_port: 9878,
      dashboard_url: "http://127.0.0.1:9878/ui",
      local_agent_id: "endpoint-cluster",
      nats: {
        enabled: true,
        nats_url: "nats://cluster.example:4222",
        creds_file: null,
        token: "secret-token",
        nkey_seed: null,
      },
      enrollment: { enrolled: true, enrollment_in_progress: false },
    }))

    const original = process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH
    process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH = settingsPath
    state.desktopAgent = loadDesktopAgentSnapshotSync()

    try {
      const app = new TestApp(tempDir)
      const rendered = stripAnsi(integrationsScreen.render(createContext(state, app, 120, 34)))

      expect(rendered).toContain("enrolled")
      expect(rendered).toContain("cluster stream: enabled nats://cluster.example:4222")
      expect(rendered).toContain("watch auth: token")
      expect(rendered).not.toContain("Use Security or Audit for local events")
    } finally {
      if (original == null) delete process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH
      else process.env.CLAWDSTRIKE_AGENT_SETTINGS_PATH = original
    }
  })
})

describe("security screen", () => {
  test("explains when recent events are unavailable because hushd is offline", () => {
    const state = createState()
    state.hushdStatus = "disconnected"

    const app = new TestApp(tempDir)
    const rendered = stripAnsi(securityScreen.render(createContext(state, app, 110, 28)))

    expect(rendered).toContain("Recent events")
    expect(rendered).toContain("unavailable because hushd is")
    expect(rendered).toContain("offline.")
    expect(rendered).not.toContain("No events yet")
  })

  test("explains when recent events require hushd authorization", () => {
    const state = createState()
    state.hushdStatus = "unauthorized"

    const app = new TestApp(tempDir)
    const rendered = stripAnsi(securityScreen.render(createContext(state, app, 110, 28)))

    expect(rendered).toContain("Recent events")
    expect(rendered).toContain("authorization")
    expect(rendered).toContain("required.")
    expect(rendered).not.toContain("No events yet")
  })

  test("renders a daemon-normalized policy guard summary without crashing", () => {
    const state = createState()
    state.hushdStatus = "connected"
    state.activePolicy = {
      name: "Default",
      version: "1.1.0",
      hash: "abc123",
      schema_version: "1.2.0",
      guards: [
        { id: "forbidden_path", enabled: true },
        { id: "path_allowlist", enabled: false },
      ],
      loaded_at: null,
      description: "Default security rules",
      yaml: "guards:\\n  forbidden_path:\\n    enabled: true",
      source: { kind: "ruleset:default" },
      schema: { current: "1.2.0", supported: ["1.1.0", "1.2.0"] },
    }

    const app = new TestApp(tempDir)
    const rendered = stripAnsi(securityScreen.render(createContext(state, app, 110, 28)))

    expect(rendered).toContain("Policy")
    expect(rendered).toContain("guards: 1 active")
  })

  test("falls back to recent audit history when the live stream is quiet", () => {
    const state = createState()
    state.hushdStatus = "connected"
    state.recentAuditPreview = [
      {
        id: "audit-preview-1",
        timestamp: new Date("2026-03-06T06:00:00Z").toISOString(),
        event_type: "report_export",
        action_type: "report_export",
        decision: "blocked",
        target: "/Users/connor/very/long/path/to/generated/report-export-validation.md",
        guard: null,
        severity: "warning",
        message: "report export preview",
        session_id: "session-preview-1",
        agent_id: "agent-preview-1",
        metadata: {},
      },
    ]

    const app = new TestApp(tempDir)
    const rendered = stripAnsi(securityScreen.render(createContext(state, app, 120, 30)))

    expect(rendered).toContain("source: recent audit log")
    expect(rendered).toContain("report")
    expect(rendered).toContain("validation.md")
  })
})

describe("policy screen", () => {
  test("renders guard information from normalized live policy data", () => {
    const state = createState()
    state.hushdStatus = "connected"
    state.activePolicy = {
      name: "Default",
      version: "1.1.0",
      hash: "abc123",
      schema_version: "1.2.0",
      guards: [
        { id: "forbidden_path", enabled: true },
        { id: "secret_leak", enabled: false },
      ],
      loaded_at: null,
      description: "Default security rules",
      yaml: "guards:\\n  forbidden_path:\\n    enabled: true",
      source: { kind: "ruleset:default" },
      schema: { current: "1.2.0", supported: ["1.1.0", "1.2.0"] },
    }

    const rendered = stripAnsi(policyScreen.render(createContext(state, new TestApp(tempDir), 110, 28)))

    expect(rendered).toContain("Policy Summary")
    expect(rendered).toContain("Summary")
    expect(rendered).toContain("unknown")
    expect(rendered).toContain("forbidden_path")
    expect(rendered).toContain("ruleset:default")
    expect(rendered).toContain("secret_leak")
  })
})
