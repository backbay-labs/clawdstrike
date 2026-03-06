import { afterEach, beforeEach, describe, expect, test } from "bun:test"
import * as fs from "node:fs/promises"
import * as os from "node:os"
import * as path from "node:path"
import type { AppController, AppState, InputMode, ScreenContext } from "../src/tui/types"
import { createInitialAuditLogState, createInitialHuntState } from "../src/tui/types"
import { THEME } from "../src/tui/theme"
import { createMainScreen } from "../src/tui/screens/main"
import { integrationsScreen } from "../src/tui/screens/integrations"
import { huntReportScreen } from "../src/tui/screens/hunt-report"
import { huntReportHistoryScreen } from "../src/tui/screens/hunt-report-history"
import { huntQueryScreen } from "../src/tui/screens/hunt-query"
import { huntScanScreen } from "../src/tui/screens/hunt-scan"
import { huntTimelineScreen } from "../src/tui/screens/hunt-timeline"
import { huntWatchScreen } from "../src/tui/screens/hunt-watch"
import { securityScreen } from "../src/tui/screens/security"
import { loadDesktopAgentSnapshotSync } from "../src/desktop-agent"
import { stripAnsi } from "../src/tui/components/types"
import { updateInvestigation, buildInvestigationReport } from "../src/tui/investigation"
import { exportReportBundle } from "../src/tui/report-export"
import type { CheckEventData } from "../src/hushd"

class TestApp implements AppController {
  public screen: InputMode | null = null
  public renderCount = 0
  public quitCalled = false
  public submitted: "dispatch" | "speculate" | null = null

  constructor(private cwd: string) {}

  setScreen(mode: InputMode): void {
    this.screen = mode
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
  showRuns(): void {}
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
    auditLog: createInitialAuditLogState(),
    auditStats: null,
    activePolicy: null,
    securityError: null,
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
  test("uses hunt shortcuts when prompt is empty", () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const ctx = createContext(state, app)

    expect(screen.handleInput("W", ctx)).toBe(true)
    expect(app.screen).toBe("hunt-watch")
  })

  test("uses supported surface shortcuts when prompt is empty", () => {
    const state = createState()
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
  })

  test("supports arrow-key home action selection with enter", () => {
    const state = createState()
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const ctx = createContext(state, app)

    expect(screen.handleInput("\x1b[B", ctx)).toBe(true)
    expect(state.homeActionIndex).toBe(2)

    expect(screen.handleInput("\x1b[C", ctx)).toBe(true)
    expect(state.homeActionIndex).toBe(3)

    expect(screen.handleInput("\r", ctx)).toBe(true)
    expect(app.screen).toBe("integrations")
  })

  test("keeps shortcut keys as prompt input when text already exists", () => {
    const state = createState()
    state.promptBuffer = "triage "
    const app = new TestApp(tempDir)
    const screen = createMainScreen([])
    const ctx = createContext(state, app)

    expect(screen.handleInput("W", ctx)).toBe(true)
    expect(app.screen).toBeNull()
    expect(state.promptBuffer).toBe("triage W")
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

    expect(output).toContain("or use shortcut keys")
    expect(output).toContain("Integrations runtime status")
    expect(output).toContain("Timeline event replay")
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
    expect(rendered).toContain("rcpt-1")

    expect(huntReportHistoryScreen.handleInput("\r", ctx)).toBe(true)
    await Bun.sleep(25)

    expect(app.screen).toBe("hunt-report")
    expect(state.hunt.report.report?.title).toBe("History Entry")
    expect(stripAnsi(state.hunt.report.statusMessage ?? "")).toContain("Loaded exported report:")
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
})
