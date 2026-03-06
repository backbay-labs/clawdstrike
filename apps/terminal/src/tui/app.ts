/**
 * TUI App - Interactive Terminal User Interface for ClawdStrike
 *
 * Thin coordinator: lifecycle, input routing, screen registry.
 * All screen rendering/input is delegated to screen modules.
 */

import { VERSION, init, shutdown, isInitialized } from "../index"
import { Beads } from "../beads"
import { Telemetry } from "../telemetry"
import { Health } from "../health"
import { MCP } from "../mcp"
import { Hushd, eventDecision } from "../hushd"
import { Config } from "../config"
import { loadDesktopAgentSnapshotSync } from "../desktop-agent"
import { THEME, ESC, AGENTS } from "./theme"
import { renderStatusBar } from "./components/status-bar"
import { getInvestigationCounts, isInvestigationStale } from "./investigation"
import { getSurfaceMeta } from "./surfaces"
import type { Screen, ScreenContext, AppState, InputMode, Command, AppController, DispatchResultInfo, RunRecord } from "./types"
import {
  createInitialAuditLogState,
  createInitialDispatchSheetState,
  createInitialHuntState,
  createInitialRunListState,
  type RuntimeInfo,
} from "./types"
import {
  canRunAttach,
  createManagedRun,
  executeManagedRun,
  getRunAttachDisabledReason,
  isRunTerminal,
  supportsAttachToolchain,
  updateRunRecord,
} from "./runs"
import { createAttachRunSession } from "./pty"

// Screen imports
import { createMainScreen } from "./screens/main"
import { getRecommendedSandboxIndex, setupScreen } from "./screens/setup"
import { integrationsScreen } from "./screens/integrations"
import { securityScreen } from "./screens/security"
import { auditScreen } from "./screens/audit"
import { policyScreen } from "./screens/policy"
import { runsScreen } from "./screens/runs"
import { runDetailScreen } from "./screens/run-detail"
import { resultScreen } from "./screens/result"

// Hunt screen imports
import { huntWatchScreen } from "./screens/hunt-watch"
import { huntScanScreen } from "./screens/hunt-scan"
import { huntTimelineScreen } from "./screens/hunt-timeline"
import { huntRuleBuilderScreen } from "./screens/hunt-rule-builder"
import { huntQueryScreen } from "./screens/hunt-query"
import { huntDiffScreen } from "./screens/hunt-diff"
import { huntReportScreen } from "./screens/hunt-report"
import { huntReportHistoryScreen } from "./screens/hunt-report-history"
import { huntMitreScreen } from "./screens/hunt-mitre"
import { huntPlaybookScreen } from "./screens/hunt-playbook"

const AUDIT_PREVIEW_REFRESH_INTERVAL_MS = 15_000

// =============================================================================
// TUI APP
// =============================================================================

function resolveRuntimeInfo(): RuntimeInfo {
  const scriptPath = process.env.CLAWDSTRIKE_TUI_RUNTIME_SCRIPT ?? Bun.main ?? process.argv[1] ?? null
  const envSource = process.env.CLAWDSTRIKE_TUI_RUNTIME_SOURCE

  if (
    envSource === "override" ||
    envSource === "installed-bundle" ||
    envSource === "embedded-bundle" ||
    envSource === "repo-source" ||
    envSource === "direct"
  ) {
    return {
      source: envSource,
      scriptPath,
      bunVersion: Bun.version ?? null,
    }
  }

  if (scriptPath?.includes("/apps/terminal/src/cli/index.ts")) {
    return { source: "repo-source", scriptPath, bunVersion: Bun.version ?? null }
  }

  return { source: "direct", scriptPath, bunVersion: Bun.version ?? null }
}

export class TUIApp implements AppController {
  private state: AppState
  private refreshTimer: ReturnType<typeof setInterval> | null = null
  private animationTimer: ReturnType<typeof setInterval> | null = null
  private hushdReconnectTimer: ReturnType<typeof setTimeout> | null = null
  private hushdLifecycleToken = 0
  private auditPreviewRefreshing = false
  private lastAuditPreviewRefreshAt = 0
  private width: number = 80
  private height: number = 24
  private cwd: string
  private canceledRunIds = new Set<string>()
  private attachedSession: { exited: Promise<number>; terminate: () => void } | null = null
  private readonly inputListener = (key: string) => this.handleInput(key)
  private readonly resizeListener = () => {
    this.updateTerminalSize()
    if (!this.state.ptyHandoffActive) {
      this.render()
    }
  }

  private commands: Command[]
  private screens: Map<string, Screen>

  constructor(cwd: string = process.cwd()) {
    this.cwd = cwd
    this.state = {
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
      runtimeInfo: resolveRuntimeInfo(),
      desktopAgent: loadDesktopAgentSnapshotSync(),
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
      runs: createInitialRunListState(),
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

    // Build commands list (including hunt commands)
    this.commands = [
      { key: "d", label: "dispatch", description: "send task to agent", stage: "supported", action: () => this.submitPrompt("dispatch") },
      { key: "s", label: "speculate", description: "parallel multi-agent", stage: "supported", action: () => this.submitPrompt("speculate") },
      { key: "g", label: "gates", description: "run quality gates", stage: "supported", action: () => this.runGates() },
      { key: "S", label: "security", description: "security overview", stage: "supported", action: () => this.setScreen("security") },
      { key: "a", label: "audit", description: "audit log", stage: "supported", action: () => this.setScreen("audit") },
      { key: "p", label: "policy", description: "active policy", stage: "supported", action: () => this.setScreen("policy") },
      { key: "W", label: "watch", description: "live hunt stream", stage: "supported", action: () => this.setScreen("hunt-watch") },
      { key: "X", label: "scan", description: "MCP scan explorer", stage: "supported", action: () => this.setScreen("hunt-scan") },
      { key: "T", label: "timeline", description: "timeline replay", stage: "supported", action: () => this.setScreen("hunt-timeline") },
      { key: "R", label: "rules", description: "correlation rule builder", stage: "experimental", action: () => this.setScreen("hunt-rule-builder") },
      { key: "Q", label: "query", description: "hunt query REPL", stage: "supported", action: () => this.setScreen("hunt-query") },
      { key: "D", label: "diff", description: "scan change detection", stage: "experimental", action: () => this.setScreen("hunt-diff") },
      { key: "E", label: "evidence", description: "evidence report", stage: "supported", action: () => this.setScreen("hunt-report") },
      { key: "H", label: "history", description: "exported report index", stage: "supported", action: () => this.setScreen("hunt-report-history") },
      { key: "M", label: "mitre", description: "MITRE ATT&CK heatmap", stage: "experimental", action: () => this.setScreen("hunt-mitre") },
      { key: "P", label: "playbook", description: "playbook runner", stage: "experimental", action: () => this.setScreen("hunt-playbook") },
      { key: "b", label: "beads", description: "view work graph", stage: "supported", action: () => this.showBeads() },
      { key: "r", label: "runs", description: "managed backlog", stage: "supported", action: () => this.showRuns() },
      { key: "i", label: "integrations", description: "system status", stage: "supported", action: () => this.setScreen("integrations") },
      { key: "?", label: "help", description: "keyboard shortcuts", stage: "supported", action: () => this.showHelp() },
      { key: "q", label: "quit", description: "exit clawdstrike", stage: "supported", action: () => this.quit() },
    ]

    // Build screen registry
    const mainScreen = createMainScreen(this.commands)
    this.screens = new Map<string, Screen>([
      ["main", mainScreen],
      ["commands", mainScreen], // commands overlay shares the main screen
      ["dispatch-sheet", mainScreen], // dispatch overlay shares the main screen
      ["setup", setupScreen],
      ["integrations", integrationsScreen],
      ["security", securityScreen],
      ["audit", auditScreen],
      ["policy", policyScreen],
      ["runs", runsScreen],
      ["run-detail", runDetailScreen],
      ["result", resultScreen],
      ["hunt-watch", huntWatchScreen],
      ["hunt-scan", huntScanScreen],
      ["hunt-timeline", huntTimelineScreen],
      ["hunt-rule-builder", huntRuleBuilderScreen],
      ["hunt-query", huntQueryScreen],
      ["hunt-diff", huntDiffScreen],
      ["hunt-report", huntReportScreen],
      ["hunt-report-history", huntReportHistoryScreen],
      ["hunt-mitre", huntMitreScreen],
      ["hunt-playbook", huntPlaybookScreen],
    ])
  }

  // ===========================================================================
  // LIFECYCLE
  // ===========================================================================

  async start(): Promise<void> {
    if (!isInitialized()) {
      await init({
        beadsPath: `${this.cwd}/.beads`,
        telemetryDir: `${this.cwd}/.clawdstrike/runs`,
      })
    }

    this.updateTerminalSize()
    this.setupInput()

    process.stdout.write(ESC.altScreen + ESC.hideCursor)

    await this.checkFirstRun()

    this.animationTimer = setInterval(() => {
      this.state.animationFrame++
      if (this.state.inputMode === "main" || this.state.inputMode === "setup") {
        this.render()
      }
    }, 80)

    if (this.state.inputMode === "setup") {
      this.render()
      return
    }

    this.startBackgroundServices()
    await this.refresh()
    this.render()
  }

  private startBackgroundServices(): void {
    this.state.desktopAgent = loadDesktopAgentSnapshotSync()
    this.startMcpServer()
    this.connectHushd()
    this.runHealthcheck()
    this.refreshTimer = setInterval(() => this.refresh(), 2000)
  }

  private async startMcpServer(): Promise<void> {
    try {
      await MCP.start({ cwd: this.cwd, projectId: "default" })
      this.render()
    } catch {
      // MCP server failed to start - not critical
    }
  }

  runHealthcheck(): void {
    this.state.desktopAgent = loadDesktopAgentSnapshotSync()
    this.state.healthChecking = true
    this.render()

    Health.checkAll({ timeout: 2000 })
      .then((health) => {
        this.state.health = health
      })
      .catch(() => {
        // Healthcheck failed
      })
      .finally(() => {
        this.state.healthChecking = false
        this.render()
      })
  }

  connectHushd(): void {
    const lifecycleToken = ++this.hushdLifecycleToken

    if (this.hushdReconnectTimer) {
      clearTimeout(this.hushdReconnectTimer)
      this.hushdReconnectTimer = null
    }

    if (Hushd.isInitialized()) {
      Hushd.reset()
    }
    Hushd.init()
    const client = Hushd.getClient()
    this.state.hushdStatus = "connecting"
    this.state.hushdLastError = null
    this.state.securityError = null
    this.state.recentAuditPreview = []
    this.render()

    client.probe()
      .then(async (connected) => {
        if (lifecycleToken !== this.hushdLifecycleToken) {
          return
        }
        this.state.hushdConnected = connected

        if (!connected) {
          this.state.hushdStatus = "disconnected"
          this.state.hushdLastError = "health probe failed"
          this.state.securityError = "hushd is unreachable."
          this.state.recentAuditPreview = []
          this.scheduleHushdReconnect(lifecycleToken)
          return
        }

        const [policyResult, statsResult, previewResult] = await Promise.all([
          client.getPolicyDetailed(),
          client.getAuditStatsDetailed(),
          client.getAuditDetailed({ limit: 6 }),
        ])
        if (lifecycleToken !== this.hushdLifecycleToken) {
          return
        }
        const unauthorized = [policyResult.status, statsResult.status, previewResult.status].some(
          (status) => status === 401 || status === 403,
        )
        const errors = [policyResult.error, statsResult.error].filter(Boolean)

        this.state.activePolicy = policyResult.data ?? null
        this.state.auditStats = statsResult.data ?? null
        this.state.recentAuditPreview = previewResult.data?.events ?? []
        this.lastAuditPreviewRefreshAt = previewResult.ok ? Date.now() : 0
        this.state.hushdConnected = !unauthorized
        this.state.hushdStatus = unauthorized
          ? "unauthorized"
          : policyResult.ok && statsResult.ok
            ? "connected"
            : "degraded"
        this.state.hushdLastError = errors[0] ?? null
        this.state.securityError = errors[0] ?? null

        if (unauthorized) {
          return
        }

        client.connectSSE(
          (event) => {
            if (lifecycleToken !== this.hushdLifecycleToken) {
              return
            }
            this.state.recentEvents.unshift(event)
            if (this.state.recentEvents.length > 50) {
              this.state.recentEvents.length = 50
            }
            this.state.hushdConnected = true
            this.state.hushdStatus = "connected"
            this.state.hushdLastEventAt = event.timestamp
            this.state.hushdLastError = null
            this.state.hushdReconnectAttempts = 0
            this.render()
          },
          (error) => {
            if (lifecycleToken !== this.hushdLifecycleToken) {
              return
            }
            const message = error.message || "stream error"
            this.state.hushdLastError = message
            this.state.securityError = message

            if (message.startsWith("Failed to parse")) {
              this.state.hushdDroppedEvents += 1
              this.state.hushdStatus = "degraded"
              this.render()
              return
            }

            if (message.includes("401") || message.includes("403")) {
              this.state.hushdConnected = false
              this.state.hushdStatus = "unauthorized"
              this.render()
              return
            }

            this.state.hushdConnected = false
            this.state.hushdStatus = this.state.hushdLastEventAt ? "stale" : "disconnected"
            this.scheduleHushdReconnect(lifecycleToken)
            this.render()
          },
        )
      })
      .catch((err) => {
        if (lifecycleToken !== this.hushdLifecycleToken) {
          return
        }
        this.state.hushdConnected = false
        this.state.hushdStatus = "error"
        this.state.hushdLastError = err instanceof Error ? err.message : String(err)
        this.state.securityError = this.state.hushdLastError
        this.state.recentAuditPreview = []
        this.scheduleHushdReconnect(lifecycleToken)
      })
      .finally(() => {
        if (lifecycleToken === this.hushdLifecycleToken) {
          this.render()
        }
      })
  }

  private scheduleHushdReconnect(lifecycleToken: number = this.hushdLifecycleToken): void {
    if (lifecycleToken !== this.hushdLifecycleToken) {
      return
    }
    if (this.hushdReconnectTimer || this.state.hushdStatus === "unauthorized") {
      return
    }

    const attempt = this.state.hushdReconnectAttempts + 1
    const delay = Math.min(15_000, 1_000 * (2 ** Math.min(attempt - 1, 4)))
    this.state.hushdReconnectAttempts = attempt
    this.hushdReconnectTimer = setTimeout(() => {
      if (lifecycleToken !== this.hushdLifecycleToken) {
        this.hushdReconnectTimer = null
        return
      }
      this.hushdReconnectTimer = null
      this.connectHushd()
    }, delay)
  }

  private async refreshRecentAuditPreview(force = false): Promise<void> {
    if (this.auditPreviewRefreshing || !Hushd.isInitialized()) {
      return
    }

    if (
      !force &&
      Date.now() - this.lastAuditPreviewRefreshAt < AUDIT_PREVIEW_REFRESH_INTERVAL_MS
    ) {
      return
    }

    if (
      this.state.hushdStatus === "connecting" ||
      this.state.hushdStatus === "disconnected" ||
      this.state.hushdStatus === "error" ||
      this.state.hushdStatus === "not_configured" ||
      this.state.hushdStatus === "unauthorized"
    ) {
      return
    }

    this.auditPreviewRefreshing = true
    try {
      const result = await Hushd.getClient().getAuditDetailed({ limit: 6 })
      if (result.ok && result.data) {
        this.state.recentAuditPreview = result.data.events
        this.lastAuditPreviewRefreshAt = Date.now()
        if (this.state.inputMode === "main" || this.state.inputMode === "security") {
          this.render()
        }
        return
      }

      if (result.status === 401 || result.status === 403) {
        this.state.hushdConnected = false
        this.state.hushdStatus = "unauthorized"
        this.state.hushdLastError = result.error ?? "audit access denied"
        this.state.securityError = this.state.hushdLastError
        this.state.recentAuditPreview = []
        this.render()
      }
    } finally {
      this.auditPreviewRefreshing = false
    }
  }

  private async checkFirstRun(): Promise<void> {
    if (await Config.exists(this.cwd)) return

    this.state.inputMode = "setup"
    this.state.setupStep = "detecting"
    this.render()

    const detection = await Config.detect(this.cwd)
    this.state.setupDetection = detection
    this.state.setupStep = "review"
    this.state.setupSandboxIndex = getRecommendedSandboxIndex(
      detection.recommended_sandbox,
      detection.git_available,
    )
    this.render()
  }

  private async cleanup(): Promise<void> {
    this.hushdLifecycleToken += 1

    if (this.refreshTimer) {
      clearInterval(this.refreshTimer)
      this.refreshTimer = null
    }

    if (this.animationTimer) {
      clearInterval(this.animationTimer)
      this.animationTimer = null
    }

    if (this.hushdReconnectTimer) {
      clearTimeout(this.hushdReconnectTimer)
      this.hushdReconnectTimer = null
    }

    try {
      await MCP.stop()
    } catch {
      // Ignore MCP shutdown errors
    }

    Hushd.reset()
    this.detachTerminalListeners()
    this.attachedSession?.terminate()
    this.attachedSession = null
    this.state.attachedRunId = null
    this.state.pendingAttachRunId = null
    this.state.ptyHandoffActive = false

    process.stdout.write(ESC.showCursor + ESC.mainScreen)

    if (isInitialized()) {
      await shutdown()
    }
  }

  private updateTerminalSize(): void {
    this.width = process.stdout.columns || 80
    this.height = process.stdout.rows || 24
  }

  private setupInput(): void {
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true)
    }
    process.stdin.resume()
    process.stdin.setEncoding("utf8")
    this.attachTerminalListeners()
  }

  private attachTerminalListeners(): void {
    process.stdin.off("data", this.inputListener)
    process.stdout.off("resize", this.resizeListener)
    process.stdin.on("data", this.inputListener)
    process.stdout.on("resize", this.resizeListener)
  }

  private detachTerminalListeners(): void {
    process.stdin.off("data", this.inputListener)
    process.stdout.off("resize", this.resizeListener)
  }

  // ===========================================================================
  // INPUT HANDLING
  // ===========================================================================

  private handleInput(key: string): void {
    if (this.state.ptyHandoffActive) {
      return
    }

    // Ctrl+C always quits
    if (key === "\x03") {
      this.quit()
      return
    }

    const screen = this.screens.get(this.state.inputMode)
    if (screen) {
      const ctx = this.createContext()
      screen.handleInput(key, ctx)
    }
  }

  // ===========================================================================
  // RENDERING
  // ===========================================================================

  render(): void {
    let output = ESC.moveTo(1, 1)

    const ctx = this.createContext()
    const screen = this.screens.get(this.state.inputMode)
    let screenContent = screen ? screen.render(ctx) : ""

    // Apply background + status bar
    const clearToEol = "\x1b[K"
    const lines = screenContent.split("\n")

    // Inject status bar at the end if the screen doesn't have one
    // (Hunt screens manage their own, existing screens had it in renderStatusBar)
    const statusBar = this.buildStatusBar()

    const paddedLines = lines.map((line) => {
      return THEME.bg + line + clearToEol
    })

    // Add status bar as the last line
    if (paddedLines.length < this.height) {
      // Pad to fill screen minus the single status bar row
      while (paddedLines.length < this.height - 1) {
        paddedLines.push(THEME.bg + clearToEol)
      }
      paddedLines.push(THEME.bg + statusBar + clearToEol)
    }

    output += paddedLines.join("\n")
    output += THEME.bg + ESC.clearToEndOfScreen
    process.stdout.write(output)
  }

  private buildStatusBar(): string {
    const surface = getSurfaceMeta(this.state.inputMode)
    const investigation = this.state.hunt.investigation
    const investigationCounts = getInvestigationCounts(investigation)

    return renderStatusBar(
      {
        version: VERSION,
        cwd: this.cwd,
        currentScreenLabel: surface.label,
        currentScreenStage: surface.stage,
        healthChecking: this.state.healthChecking,
        health: this.state.health,
        hushdStatus: this.state.hushdStatus,
        deniedCount: this.state.recentEvents.filter((event) => eventDecision(event) === "deny").length,
        activeRuns: this.state.activeRuns,
        openBeads: this.state.openBeads,
        agentId: AGENTS[this.state.agentIndex].id,
        investigation:
          investigation.origin || investigationCounts.events > 0 || investigationCounts.findings > 0
            ? {
                origin: investigation.origin ?? "manual",
                events: investigationCounts.events,
                findings: investigationCounts.findings,
                stale: isInvestigationStale(investigation),
              }
            : null,
        huntWatch: this.state.hunt.watch.running ? {
          events: this.state.hunt.watch.stats?.events_processed ?? 0,
          alerts: this.state.hunt.watch.stats?.alerts_fired ?? 0,
        } : null,
        huntScan: this.state.hunt.scan.loading ? { status: "scanning" } : null,
        lastExportedReport: this.state.hunt.reportHistory.entries[0]
          ? {
              title: this.state.hunt.reportHistory.entries[0].title,
              severity: this.state.hunt.reportHistory.entries[0].severity,
            }
          : null,
      },
      this.width,
      THEME,
    )
  }

  private createContext(): ScreenContext {
    return {
      state: this.state,
      width: this.width,
      height: this.height - 1, // Reserve 1 line for the shared status bar
      theme: THEME,
      app: this,
    }
  }

  // ===========================================================================
  // APP CONTROLLER INTERFACE
  // ===========================================================================

  setScreen(mode: InputMode): void {
    const oldScreen = this.screens.get(this.state.inputMode)
    const ctx = this.createContext()

    if (oldScreen?.onExit) {
      oldScreen.onExit(ctx)
    }

    this.state.inputMode = mode
    if (mode === "main") {
      this.state.homeFocus = "prompt"
      this.state.homePromptTraceStartFrame = this.state.animationFrame
    }

    const newScreen = this.screens.get(mode)
    if (newScreen?.onEnter) {
      newScreen.onEnter(ctx)
    }

    this.render()
  }

  launchDispatchSheet(): void {
    if (!this.state.dispatchSheet.open) {
      return
    }

    if (this.state.dispatchSheet.mode === "external") {
      this.state.dispatchSheet = {
        ...this.state.dispatchSheet,
        error: `${this.state.dispatchSheet.mode} mode is reserved for later phases.`,
      }
      this.render()
      return
    }

    const { prompt, action, agentIndex, mode } = this.state.dispatchSheet
    if (mode === "attach" && action !== "dispatch") {
      this.state.dispatchSheet = {
        ...this.state.dispatchSheet,
        error: "attach mode is only available for dispatch runs.",
      }
      this.render()
      return
    }

    const agent = AGENTS[agentIndex]
    if (mode === "attach" && !supportsAttachToolchain(agent.id)) {
      this.state.dispatchSheet = {
        ...this.state.dispatchSheet,
        error: `${agent.name} does not expose an interactive attach session yet.`,
      }
      this.render()
      return
    }

    const run = createManagedRun({
      prompt,
      action,
      agentId: agent.id,
      agentLabel: agent.name,
      mode,
    })

    this.state.agentIndex = agentIndex
    this.state.dispatchSheet = createInitialDispatchSheetState()
    this.state.promptBuffer = ""
    this.replaceRun(run)
    this.state.statusMessage =
      mode === "attach"
        ? `${THEME.accent}⠋${THEME.reset} Attach run staged via ${agent.name}`
        : `${THEME.accent}⠋${THEME.reset} ${action === "dispatch" ? "Managed run launched" : "Managed speculation launched"} via ${agent.name}`
    this.syncManagedRunState()
    this.openRun(run.id)

    if (mode === "attach") {
      this.beginAttachRun(run.id)
      return
    }

    void this.launchManagedRun(run)
  }

  closeDispatchSheet(): void {
    this.state.dispatchSheet = createInitialDispatchSheetState()
    this.state.inputMode = "main"
    this.state.homeFocus = "prompt"
    this.state.homePromptTraceStartFrame = this.state.animationFrame
    this.render()
  }

  openRun(runId: string): void {
    const run = this.state.runs.entries.find((entry) => entry.id === runId)
    if (!run) {
      return
    }

    this.state.activeRunId = runId
    this.state.runs.selectedRunId = runId
    const lastEventIndex = Math.max(0, run.events.length - 1)
    this.state.runDetailEvents = { offset: Math.max(0, lastEventIndex - 5), selected: lastEventIndex }
    this.setScreen("run-detail")
  }

  beginAttachRun(runId: string): void {
    const run = this.state.runs.entries.find((entry) => entry.id === runId)
    if (!run) {
      return
    }

    const reason = getRunAttachDisabledReason(run)
    if (reason) {
      this.state.statusMessage = `${THEME.warning}!${THEME.reset} ${reason}`
      this.render()
      return
    }

    this.state.pendingAttachRunId = runId
    this.render()
  }

  confirmAttachRun(): void {
    const runId = this.state.pendingAttachRunId
    if (!runId) {
      return
    }

    const run = this.state.runs.entries.find((entry) => entry.id === runId)
    if (!run || !canRunAttach(run)) {
      this.cancelAttachRun()
      return
    }

    this.state.pendingAttachRunId = null
    void this.launchAttachRun(run.id)
  }

  cancelAttachRun(): void {
    this.state.pendingAttachRunId = null
    this.render()
  }

  cancelRun(runId: string): void {
    const run = this.state.runs.entries.find((entry) => entry.id === runId)
    if (!run || isRunTerminal(run.phase)) {
      return
    }

    this.canceledRunIds.add(runId)
    this.replaceRun({
      ...run,
      phase: "canceled",
      updatedAt: new Date().toISOString(),
      completedAt: new Date().toISOString(),
      events: [
        ...run.events,
        {
          timestamp: new Date().toISOString(),
          kind: "warning",
          message: "Run canceled from the TUI",
        },
      ],
    })
    this.state.statusMessage = `${THEME.warning}!${THEME.reset} Run ${run.title} canceled from the TUI`
    this.syncManagedRunState()
    this.render()
  }

  getCwd(): string {
    return this.cwd
  }

  refreshDesktopAgent(): void {
    this.state.desktopAgent = loadDesktopAgentSnapshotSync()
    this.render()
  }

  // ===========================================================================
  // DATA REFRESH
  // ===========================================================================

  private async refresh(): Promise<void> {
    try {
      const active = Telemetry.getActive()
      this.state.activeRuns = Math.max(active.length, this.getManagedActiveRunCount())

      const beads = await Beads.query({ status: "open", limit: 100 })
      this.state.openBeads = beads.length

      this.state.lastRefresh = new Date()
      await this.refreshRecentAuditPreview()

      if (this.state.inputMode === "main" && !this.state.isRunning) {
        this.render()
      }
    } catch {
      // Ignore refresh errors
    }
  }

  // ===========================================================================
  // ACTIONS
  // ===========================================================================

  private getManagedActiveRunCount(): number {
    return this.state.runs.entries.filter((entry) => !isRunTerminal(entry.phase)).length
  }

  private syncManagedRunState(): void {
    const activeRunCount = this.getManagedActiveRunCount()
    this.state.isRunning = activeRunCount > 0
    this.state.activeRuns = activeRunCount
  }

  private replaceRun(nextRun: RunRecord): void {
    const entries = [...this.state.runs.entries]
    const index = entries.findIndex((entry) => entry.id === nextRun.id)

    if (index >= 0) {
      entries[index] = nextRun
    } else {
      entries.unshift(nextRun)
    }

    entries.sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))
    this.state.runs.entries = entries

    if (!this.state.activeRunId) {
      this.state.activeRunId = nextRun.id
    }
    if (!this.state.runs.selectedRunId) {
      this.state.runs.selectedRunId = nextRun.id
    }

    if (this.state.activeRunId === nextRun.id) {
      const lastEventIndex = Math.max(0, nextRun.events.length - 1)
      this.state.runDetailEvents = { offset: Math.max(0, lastEventIndex - 5), selected: lastEventIndex }
    }
  }

  private prepareTerminalForPtyHandoff(): void {
    this.state.ptyHandoffActive = true
    this.detachTerminalListeners()
    process.stdout.write(ESC.showCursor + ESC.mainScreen)
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(false)
    }
  }

  private restoreTerminalAfterPtyHandoff(): void {
    if (process.stdin.isTTY) {
      process.stdin.setRawMode(true)
    }
    this.attachTerminalListeners()
    this.state.ptyHandoffActive = false
    process.stdout.write(ESC.altScreen + ESC.hideCursor)
    this.updateTerminalSize()
  }

  private openDispatchSheet(action: "dispatch" | "speculate"): void {
    const prompt = this.state.promptBuffer.trim()
    if (!prompt) {
      return
    }

    this.state.dispatchSheet = {
      open: true,
      prompt,
      action,
      mode: "managed",
      agentIndex: this.state.agentIndex,
      focusedField: 0,
      error: null,
    }
    this.state.inputMode = "dispatch-sheet"
    this.render()
  }

  private finishRun(run: RunRecord, result: DispatchResultInfo): void {
    const nextPhase = result.success
      ? result.verification
        ? "review_ready"
        : "completed"
      : "failed"
    const nextRun: RunRecord = {
      ...run,
      phase: nextPhase,
      updatedAt: new Date().toISOString(),
      routing: result.routing ?? null,
      execution: result.execution ?? null,
      verification: result.verification ?? null,
      result,
      error: result.error ?? result.execution?.error ?? null,
      completedAt:
        nextPhase === "review_ready" || nextPhase === "completed" || nextPhase === "failed"
          ? new Date().toISOString()
          : null,
      workcellId: result.taskId || null,
      events: [
        ...run.events,
        {
          timestamp: new Date().toISOString(),
          kind: result.success ? "status" : "error",
          message: result.success
            ? nextPhase === "review_ready"
              ? "Run ready for review"
              : "Run completed"
            : `Run failed: ${result.error ?? result.execution?.error ?? "unknown error"}`,
        },
      ],
    }

    this.replaceRun(nextRun)
    this.state.lastResult = result
    this.state.statusMessage = result.success
      ? `${THEME.success}✓${THEME.reset} ${run.agentLabel} ${nextPhase === "review_ready" ? "ready for review" : "completed"}`
      : `${THEME.error}✗${THEME.reset} ${run.agentLabel} failed`
    this.syncManagedRunState()
    this.render()
  }

  private async launchAttachRun(runId: string): Promise<void> {
    const originalRun = this.state.runs.entries.find((entry) => entry.id === runId)
    if (!originalRun) {
      return
    }

    let sessionPlan: Awaited<ReturnType<typeof createAttachRunSession>> | null = null
    let terminalPrepared = false
    const startedAt = Date.now()

    try {
      const preparingRun = updateRunRecord(
        originalRun,
        {
          attachState: "attaching",
          attached: false,
          error: null,
        },
        { kind: "status", message: "Preparing attach session" },
      )
      this.replaceRun(preparingRun)
      this.state.statusMessage = `${THEME.accent}⠋${THEME.reset} Preparing attach session`
      this.syncManagedRunState()
      this.render()

      sessionPlan = await createAttachRunSession(preparingRun, {
        cwd: this.cwd,
        projectId: "default",
      })

      const attachedRun = updateRunRecord(
        this.state.runs.entries.find((entry) => entry.id === runId) ?? preparingRun,
        {
          phase: "executing",
          routing: sessionPlan.routing,
          workcellId: sessionPlan.workcell.id,
          worktreePath: sessionPlan.workcell.directory,
          ptySessionId: sessionPlan.ptySessionId,
          attached: true,
          attachState: "attached",
        },
        { kind: "status", message: "Terminal attached to interactive session" },
      )
      this.replaceRun(attachedRun)
      this.state.attachedRunId = runId
      this.prepareTerminalForPtyHandoff()
      terminalPrepared = true
      this.attachedSession = sessionPlan.start()

      const exitCode = await this.attachedSession.exited
      const returningRun = updateRunRecord(
        this.state.runs.entries.find((entry) => entry.id === runId) ?? attachedRun,
        {
          attached: false,
          attachState: "returning",
        },
        { kind: "status", message: "Returning control to ClawdStrike" },
      )
      this.replaceRun(returningRun)
      this.state.attachedRunId = null
      this.attachedSession = null
      this.restoreTerminalAfterPtyHandoff()
      terminalPrepared = false

      const success = exitCode === 0
      const finishedRun = updateRunRecord(
        this.state.runs.entries.find((entry) => entry.id === runId) ?? returningRun,
        {
          phase: success ? "completed" : "failed",
          result: {
            success,
            taskId: sessionPlan.workcell.id,
            agent: returningRun.agentLabel,
            action: returningRun.action,
            routing: sessionPlan.routing,
            execution: success ? { success: true } : { success: false, error: `Interactive session exited with code ${exitCode}` },
            error: success ? undefined : `Interactive session exited with code ${exitCode}`,
            duration: Date.now() - startedAt,
          },
          execution: success ? { success: true } : { success: false, error: `Interactive session exited with code ${exitCode}` },
          error: success ? null : `Interactive session exited with code ${exitCode}`,
          completedAt: new Date().toISOString(),
          attached: false,
          attachState: "detached",
        },
        {
          kind: success ? "status" : "error",
          message: success ? "Interactive session completed" : `Run failed: Interactive session exited with code ${exitCode}`,
        },
      )
      this.replaceRun(finishedRun)
      this.state.lastResult = finishedRun.result
      this.state.statusMessage = success
        ? `${THEME.success}✓${THEME.reset} ${finishedRun.agentLabel} returned from attach`
        : `${THEME.error}✗${THEME.reset} ${finishedRun.agentLabel} attach session failed`
      this.syncManagedRunState()
      this.openRun(runId)
    } catch (error) {
      if (terminalPrepared) {
        this.restoreTerminalAfterPtyHandoff()
      }
      this.attachedSession?.terminate()
      this.attachedSession = null
      this.state.attachedRunId = null

      const message = error instanceof Error ? error.message : String(error)
      const failedRun = updateRunRecord(
        this.state.runs.entries.find((entry) => entry.id === runId) ?? originalRun,
        {
          phase: "failed",
          attached: false,
          attachState: "detached",
          error: message,
          completedAt: new Date().toISOString(),
          result: {
            success: false,
            taskId: sessionPlan?.workcell.id ?? "",
            agent: originalRun.agentLabel,
            action: originalRun.action,
            routing: sessionPlan?.routing,
            execution: { success: false, error: message },
            error: message,
            duration: Date.now() - startedAt,
          },
          execution: { success: false, error: message },
        },
        { kind: "error", message: `Run failed: ${message}` },
      )
      this.replaceRun(failedRun)
      this.state.lastResult = failedRun.result
      this.state.statusMessage = `${THEME.error}✗${THEME.reset} Attach failed`
      this.syncManagedRunState()
      this.render()
    } finally {
      await sessionPlan?.cleanup().catch(() => {})
    }
  }

  private async launchManagedRun(run: RunRecord): Promise<void> {
    try {
      const { executeTool } = await import("../tools")
      await executeManagedRun(run, {
        cwd: this.cwd,
        projectId: "default",
        executeTool,
        shouldAbort: () => this.canceledRunIds.has(run.id),
        onUpdate: (nextRun) => {
          this.replaceRun(nextRun)
          if (nextRun.result) {
            this.state.lastResult = nextRun.result
          }
          if (isRunTerminal(nextRun.phase)) {
            this.canceledRunIds.delete(nextRun.id)
            this.state.statusMessage =
              nextRun.phase === "canceled"
                ? `${THEME.warning}!${THEME.reset} ${nextRun.title} canceled`
                : nextRun.result?.success
                  ? `${THEME.success}✓${THEME.reset} ${nextRun.agentLabel} ${nextRun.phase === "review_ready" ? "ready for review" : "completed"}`
                  : `${THEME.error}✗${THEME.reset} ${nextRun.agentLabel} failed`
          }
          this.syncManagedRunState()
          this.render()
        },
      })
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error)
      this.finishRun(run, {
        success: false,
        taskId: "",
        agent: run.agentLabel,
        action: run.action,
        error: message,
        duration: 0,
      })
    }
  }

  async submitPrompt(action: "dispatch" | "speculate"): Promise<void> {
    const prompt = this.state.promptBuffer.trim()
    if (!prompt) return
    this.openDispatchSheet(action)
  }

  async runGates(): Promise<void> {
    this.state.statusMessage = `${THEME.accent}⠋${THEME.reset} Running quality gates...`
    this.render()

    try {
      const { executeTool } = await import("../tools")
      const context = { cwd: this.cwd, projectId: "default" }
      const result = (await executeTool("gate", { directory: this.cwd }, context)) as {
        success: boolean
        score: number
      }

      if (result.success) {
        this.state.statusMessage = `${THEME.success}✓${THEME.reset} All gates passed (${result.score}/100)`
      } else {
        this.state.statusMessage = `${THEME.error}✗${THEME.reset} Gates failed (${result.score}/100)`
      }
    } catch (err) {
      this.state.statusMessage = `${THEME.error}✗${THEME.reset} Error: ${err}`
    }

    this.render()

    setTimeout(() => {
      this.state.statusMessage = ""
      this.render()
    }, 5000)
  }

  async showBeads(): Promise<void> {
    await this.cleanup()

    console.log("")
    console.log(THEME.secondary + THEME.bold + "  ⟨ Beads ◇ Work Graph ⟩" + THEME.reset)
    console.log(THEME.dim + "  " + "═".repeat(40) + THEME.reset)
    console.log("")

    try {
      const beads = await Beads.query({ limit: 20 })

      if (beads.length === 0) {
        console.log(THEME.muted + "  No tasks inscribed" + THEME.reset)
      } else {
        for (const bead of beads) {
          const statusColor =
            bead.status === "open" ? THEME.secondary :
            bead.status === "in_progress" ? THEME.accent :
            bead.status === "completed" ? THEME.success :
            THEME.muted
          const statusIcon =
            bead.status === "open" ? "◇" :
            bead.status === "in_progress" ? "◈" :
            bead.status === "completed" ? "◆" :
            "◇"
          console.log(`  ${statusColor}${statusIcon}${THEME.reset} ${THEME.dim}${bead.id}${THEME.reset}  ${bead.title}`)
        }
      }
    } catch (err) {
      console.log(THEME.error + `  Error: ${err}` + THEME.reset)
    }

    console.log("")
    console.log(THEME.dim + "  Press any key to return..." + THEME.reset)

    await this.waitForKey()
    await this.start()
  }

  async showRuns(): Promise<void> {
    this.setScreen("runs")
  }

  async showHelp(): Promise<void> {
    await this.cleanup()

    console.log("")
    console.log(THEME.secondary + THEME.bold + "  ⟨ ClawdStrike Grimoire ⟩" + THEME.reset)
    console.log(THEME.dim + "  " + "═".repeat(40) + THEME.reset)
    console.log("")
    console.log(THEME.white + THEME.bold + "  Invocations" + THEME.reset)
    console.log("")
    console.log(`  ${THEME.secondary}↑/↓${THEME.reset}  ${THEME.muted}or${THEME.reset}  ${THEME.secondary}j/k${THEME.reset}     Navigate`)
    console.log(`  ${THEME.secondary}Enter${THEME.reset}  ${THEME.muted}or${THEME.reset}  ${THEME.secondary}Space${THEME.reset}   Select`)
    console.log(`  ${THEME.secondary}Enter${THEME.reset}               Open dispatch sheet from the home prompt`)
    console.log(`  ${THEME.secondary}Tab${THEME.reset}                 Switch between prompt and actions`)
    console.log(`  ${THEME.secondary}Esc${THEME.reset}                 Toggle prompt and nav focus`)
    console.log(`  ${THEME.secondary}g${THEME.reset}                   Gates`)
    console.log(`  ${THEME.secondary}b${THEME.reset}                   Beads`)
    console.log(`  ${THEME.secondary}r${THEME.reset}                   Runs`)
    console.log(`  ${THEME.secondary}i${THEME.reset}                   Integrations`)
    console.log(`  ${THEME.secondary}Ctrl+N${THEME.reset}              Cycle agents`)
    console.log(`  ${THEME.secondary}Ctrl+S${THEME.reset}              Security overview`)
    console.log(`  ${THEME.secondary}Ctrl+P${THEME.reset}              Command palette`)
    console.log("")
    console.log(THEME.white + THEME.bold + "  Dispatch Sheet" + THEME.reset)
    console.log("")
    console.log(`  ${THEME.secondary}↑/↓${THEME.reset}                 Focus action / mode / agent`)
    console.log(`  ${THEME.secondary}←/→${THEME.reset}                 Change selected field`)
    console.log(`  ${THEME.secondary}d / s${THEME.reset}               Set action to dispatch or speculate`)
    console.log(`  ${THEME.secondary}Enter${THEME.reset}               Launch managed run`)
    console.log("")
    console.log(THEME.white + THEME.bold + "  Hunt Commands" + THEME.reset)
    console.log("")
    console.log(`  ${THEME.secondary}W${THEME.reset}                   Watch (live stream) ${THEME.success}[beta]${THEME.reset}`)
    console.log(`  ${THEME.secondary}X${THEME.reset}                   Scan (MCP explorer) ${THEME.success}[beta]${THEME.reset}`)
    console.log(`  ${THEME.secondary}T${THEME.reset}                   Timeline replay ${THEME.success}[beta]${THEME.reset}`)
    console.log(`  ${THEME.secondary}R${THEME.reset}                   Rule builder ${THEME.warning}[exp]${THEME.reset}`)
    console.log(`  ${THEME.secondary}Q${THEME.reset}                   Query REPL ${THEME.success}[beta]${THEME.reset}`)
    console.log(`  ${THEME.secondary}D${THEME.reset}                   Diff (scan changes) ${THEME.warning}[exp]${THEME.reset}`)
    console.log(`  ${THEME.secondary}E${THEME.reset}                   Evidence report ${THEME.success}[beta]${THEME.reset}`)
    console.log(`  ${THEME.secondary}H${THEME.reset}                   Export history ${THEME.success}[beta]${THEME.reset}`)
    console.log(`  ${THEME.secondary}M${THEME.reset}                   MITRE ATT&CK map ${THEME.warning}[exp]${THEME.reset}`)
    console.log(`  ${THEME.secondary}P${THEME.reset}                   Playbook runner ${THEME.warning}[exp]${THEME.reset}`)
    console.log("")
    console.log(THEME.dim + "  Press any key to return..." + THEME.reset)

    await this.waitForKey()
    await this.start()
  }

  async quit(): Promise<void> {
    // Call onExit on current screen
    const screen = this.screens.get(this.state.inputMode)
    if (screen?.onExit) {
      screen.onExit(this.createContext())
    }

    await this.cleanup()
    process.exit(0)
  }

  private waitForKey(): Promise<void> {
    return new Promise((resolve) => {
      if (process.stdin.isTTY) {
        process.stdin.setRawMode(true)
      }
      process.stdin.resume()
      process.stdin.once("data", () => {
        if (process.stdin.isTTY) {
          process.stdin.setRawMode(false)
        }
        resolve()
      })
    })
  }
}

/**
 * Launch the TUI app
 */
export async function launchTUI(cwd?: string): Promise<void> {
  const app = new TUIApp(cwd)
  await app.start()
}
