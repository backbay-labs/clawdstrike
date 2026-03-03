/**
 * TUI App - Interactive Terminal User Interface for ClawdStrike
 *
 * Thin coordinator: lifecycle, input routing, screen registry.
 * All screen rendering/input is delegated to screen modules.
 */

import { TUI } from "./index"
import { VERSION, init, shutdown, isInitialized } from "../index"
import { Beads } from "../beads"
import { Telemetry } from "../telemetry"
import { Health } from "../health"
import { MCP } from "../mcp"
import { Hushd } from "../hushd"
import { Config } from "../config"
import { THEME, ESC, AGENTS } from "./theme"
import { renderStatusBar } from "./components/status-bar"
import type { Screen, ScreenContext, AppState, InputMode, Command, AppController } from "./types"
import { createInitialHuntState } from "./types"

// Screen imports
import { createMainScreen } from "./screens/main"
import { setupScreen } from "./screens/setup"
import { integrationsScreen } from "./screens/integrations"
import { securityScreen } from "./screens/security"
import { auditScreen } from "./screens/audit"
import { policyScreen } from "./screens/policy"
import { resultScreen } from "./screens/result"

// Hunt screen imports
import { huntWatchScreen } from "./screens/hunt-watch"
import { huntScanScreen } from "./screens/hunt-scan"
import { huntTimelineScreen } from "./screens/hunt-timeline"
import { huntRuleBuilderScreen } from "./screens/hunt-rule-builder"
import { huntQueryScreen } from "./screens/hunt-query"
import { huntDiffScreen } from "./screens/hunt-diff"
import { huntReportScreen } from "./screens/hunt-report"
import { huntMitreScreen } from "./screens/hunt-mitre"
import { huntPlaybookScreen } from "./screens/hunt-playbook"

// =============================================================================
// TUI APP
// =============================================================================

export class TUIApp implements AppController {
  private state: AppState
  private refreshTimer: ReturnType<typeof setInterval> | null = null
  private animationTimer: ReturnType<typeof setInterval> | null = null
  private width: number = 80
  private height: number = 24
  private cwd: string

  private commands: Command[]
  private screens: Map<string, Screen>

  constructor(cwd: string = process.cwd()) {
    this.cwd = cwd
    this.state = {
      promptBuffer: "",
      agentIndex: 0,
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
      hushdConnected: false,
      recentEvents: [],
      auditStats: null,
      activePolicy: null,
      securityError: null,
      lastResult: null,
      setupDetection: null,
      setupStep: "detecting",
      setupSandboxIndex: 0,
      hunt: createInitialHuntState(),
    }

    // Build commands list (including hunt commands)
    this.commands = [
      { key: "d", label: "dispatch", description: "send task to agent", action: () => this.submitPrompt("dispatch") },
      { key: "s", label: "speculate", description: "parallel multi-agent", action: () => this.submitPrompt("speculate") },
      { key: "g", label: "gates", description: "run quality gates", action: () => this.runGates() },
      { key: "S", label: "security", description: "security overview", action: () => this.setScreen("security") },
      { key: "a", label: "audit", description: "audit log", action: () => this.setScreen("audit") },
      { key: "p", label: "policy", description: "active policy", action: () => this.setScreen("policy") },
      { key: "W", label: "watch", description: "live hunt stream", action: () => this.setScreen("hunt-watch") },
      { key: "X", label: "scan", description: "MCP scan explorer", action: () => this.setScreen("hunt-scan") },
      { key: "T", label: "timeline", description: "timeline replay", action: () => this.setScreen("hunt-timeline") },
      { key: "R", label: "rules", description: "correlation rule builder", action: () => this.setScreen("hunt-rule-builder") },
      { key: "Q", label: "query", description: "hunt query REPL", action: () => this.setScreen("hunt-query") },
      { key: "D", label: "diff", description: "scan change detection", action: () => this.setScreen("hunt-diff") },
      { key: "E", label: "evidence", description: "evidence report", action: () => this.setScreen("hunt-report") },
      { key: "M", label: "mitre", description: "MITRE ATT&CK heatmap", action: () => this.setScreen("hunt-mitre") },
      { key: "P", label: "playbook", description: "playbook runner", action: () => this.setScreen("hunt-playbook") },
      { key: "b", label: "beads", description: "view work graph", action: () => this.showBeads() },
      { key: "r", label: "runs", description: "active rollouts", action: () => this.showRuns() },
      { key: "i", label: "integrations", description: "system status", action: () => this.setScreen("integrations") },
      { key: "?", label: "help", description: "keyboard shortcuts", action: () => this.showHelp() },
      { key: "q", label: "quit", description: "exit clawdstrike", action: () => this.quit() },
    ]

    // Build screen registry
    const mainScreen = createMainScreen(this.commands)
    this.screens = new Map<string, Screen>([
      ["main", mainScreen],
      ["commands", mainScreen], // commands overlay shares the main screen
      ["setup", setupScreen],
      ["integrations", integrationsScreen],
      ["security", securityScreen],
      ["audit", auditScreen],
      ["policy", policyScreen],
      ["result", resultScreen],
      ["hunt-watch", huntWatchScreen],
      ["hunt-scan", huntScanScreen],
      ["hunt-timeline", huntTimelineScreen],
      ["hunt-rule-builder", huntRuleBuilderScreen],
      ["hunt-query", huntQueryScreen],
      ["hunt-diff", huntDiffScreen],
      ["hunt-report", huntReportScreen],
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
    Hushd.init()
    const client = Hushd.getClient()

    client.probe()
      .then(async (connected) => {
        this.state.hushdConnected = connected

        if (connected) {
          const [policy, stats] = await Promise.all([
            client.getPolicy(),
            client.getAuditStats(),
          ])
          this.state.activePolicy = policy
          this.state.auditStats = stats

          client.connectSSE(
            (event) => {
              this.state.recentEvents.unshift(event)
              if (this.state.recentEvents.length > 50) {
                this.state.recentEvents.length = 50
              }
              this.render()
            },
            () => {
              this.state.hushdConnected = false
              this.render()
            }
          )
        }
      })
      .catch(() => {
        this.state.hushdConnected = false
      })
      .finally(() => {
        this.render()
      })
  }

  private async checkFirstRun(): Promise<void> {
    if (await Config.exists(this.cwd)) return

    this.state.inputMode = "setup"
    this.state.setupStep = "detecting"
    this.render()

    const detection = await Config.detect(this.cwd)
    this.state.setupDetection = detection
    this.state.setupStep = "review"
    this.state.setupSandboxIndex = 0
    this.render()
  }

  private async cleanup(): Promise<void> {
    if (this.refreshTimer) {
      clearInterval(this.refreshTimer)
      this.refreshTimer = null
    }

    if (this.animationTimer) {
      clearInterval(this.animationTimer)
      this.animationTimer = null
    }

    try {
      await MCP.stop()
    } catch {
      // Ignore MCP shutdown errors
    }

    Hushd.reset()

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

    process.stdin.on("data", (key: string) => {
      this.handleInput(key)
    })

    process.stdout.on("resize", () => {
      this.updateTerminalSize()
      this.render()
    })
  }

  // ===========================================================================
  // INPUT HANDLING
  // ===========================================================================

  private handleInput(key: string): void {
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

    // Add status bar as last 2 lines
    if (paddedLines.length < this.height) {
      // Pad to fill screen minus status bar
      while (paddedLines.length < this.height - 2) {
        paddedLines.push(THEME.bg + clearToEol)
      }
      paddedLines.push(THEME.bg + statusBar + clearToEol)
    }

    output += paddedLines.join("\n")
    output += THEME.bg + ESC.clearToEndOfScreen
    process.stdout.write(output)
  }

  private buildStatusBar(): string {
    return renderStatusBar(
      {
        version: VERSION,
        cwd: this.cwd,
        healthChecking: this.state.healthChecking,
        health: this.state.health,
        hushdConnected: this.state.hushdConnected,
        deniedCount: this.state.recentEvents.filter(e =>
          e.type === "check" && (e.data as { decision?: string }).decision === "deny"
        ).length,
        activeRuns: this.state.activeRuns,
        openBeads: this.state.openBeads,
        agentId: AGENTS[this.state.agentIndex].id,
        huntWatch: this.state.hunt.watch.running ? {
          events: this.state.hunt.watch.stats?.events_processed ?? 0,
          alerts: this.state.hunt.watch.stats?.alerts_fired ?? 0,
        } : null,
        huntScan: this.state.hunt.scan.loading ? { status: "scanning" } : null,
      },
      this.width,
      THEME,
    )
  }

  private createContext(): ScreenContext {
    return {
      state: this.state,
      width: this.width,
      height: this.height - 2, // Reserve 2 lines for status bar
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

    const newScreen = this.screens.get(mode)
    if (newScreen?.onEnter) {
      newScreen.onEnter(ctx)
    }

    this.render()
  }

  getCwd(): string {
    return this.cwd
  }

  // ===========================================================================
  // DATA REFRESH
  // ===========================================================================

  private async refresh(): Promise<void> {
    try {
      const active = Telemetry.getActive()
      this.state.activeRuns = active.length

      const beads = await Beads.query({ status: "open", limit: 100 })
      this.state.openBeads = beads.length

      this.state.lastRefresh = new Date()

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

  async submitPrompt(action: "dispatch" | "speculate"): Promise<void> {
    const prompt = this.state.promptBuffer.trim()
    if (!prompt) return

    const agent = AGENTS[this.state.agentIndex]
    this.state.statusMessage = `${THEME.accent}⠋${THEME.reset} ${action === "dispatch" ? "Dispatching" : "Speculating"} via ${agent.name}...`
    this.state.isRunning = true
    this.render()

    const startTime = Date.now()

    try {
      const { executeTool } = await import("../tools")
      const context = { cwd: this.cwd, projectId: "default" }

      if (action === "dispatch") {
        const raw = await executeTool("dispatch", { prompt, toolchain: agent.id }, context) as Record<string, unknown>
        const duration = Date.now() - startTime
        const routing = raw.routing as Record<string, unknown> | undefined
        const result = raw.result as Record<string, unknown> | undefined
        const verification = raw.verification as Record<string, unknown> | undefined
        const telemetry = result?.telemetry as Record<string, unknown> | undefined
        this.state.lastResult = {
          success: raw.success as boolean,
          taskId: (raw.taskId as string) ?? "",
          agent: agent.name,
          action,
          routing: routing ? {
            toolchain: routing.toolchain as string,
            strategy: routing.strategy as string,
            gates: (routing.gates as string[]) ?? [],
          } : undefined,
          execution: result ? {
            success: result.success as boolean,
            error: result.error as string | undefined,
            model: telemetry?.model as string | undefined,
            tokens: telemetry?.tokens as { input: number; output: number } | undefined,
            cost: telemetry?.cost as number | undefined,
          } : undefined,
          verification: verification ? {
            allPassed: verification.allPassed as boolean,
            score: verification.score as number,
            summary: verification.summary as string,
            results: ((verification.results as Array<Record<string, unknown>>) ?? []).map(r => ({
              gate: r.gate as string,
              passed: r.passed as boolean,
            })),
          } : undefined,
          error: raw.error as string | undefined,
          duration,
        }
      } else {
        const raw = await executeTool("speculate", { prompt }, context) as Record<string, unknown>
        const duration = Date.now() - startTime
        this.state.lastResult = {
          success: raw.success as boolean,
          taskId: "",
          agent: "multi",
          action,
          error: raw.success ? undefined : "No passing result from speculation",
          duration,
        }
      }
    } catch (err) {
      this.state.lastResult = {
        success: false,
        taskId: "",
        agent: agent.name,
        action,
        error: err instanceof Error ? err.message : String(err),
        duration: Date.now() - startTime,
      }
    }

    this.state.isRunning = false
    this.state.promptBuffer = ""
    this.state.statusMessage = ""
    this.state.inputMode = "result"
    this.render()
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
    await this.cleanup()

    console.log("")
    console.log(THEME.secondary + THEME.bold + "  ⟨ Active Rollouts ⟩" + THEME.reset)
    console.log(THEME.dim + "  " + "═".repeat(40) + THEME.reset)
    console.log("")

    try {
      const active = Telemetry.getActive()

      if (active.length === 0) {
        console.log(THEME.muted + "  No active incantations" + THEME.reset)
      } else {
        for (const id of active) {
          const rollout = await Telemetry.getRollout(id)
          if (rollout) {
            console.log(TUI.formatRollout(rollout))
            console.log("")
          }
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
    console.log(`  ${THEME.secondary}d${THEME.reset}                   Dispatch`)
    console.log(`  ${THEME.secondary}s${THEME.reset}                   Speculate`)
    console.log(`  ${THEME.secondary}g${THEME.reset}                   Gates`)
    console.log(`  ${THEME.secondary}b${THEME.reset}                   Beads`)
    console.log(`  ${THEME.secondary}r${THEME.reset}                   Runs`)
    console.log(`  ${THEME.secondary}i${THEME.reset}                   Integrations`)
    console.log(`  ${THEME.secondary}Ctrl+S${THEME.reset}              Security overview`)
    console.log(`  ${THEME.secondary}Ctrl+P${THEME.reset}              Command palette`)
    console.log("")
    console.log(THEME.white + THEME.bold + "  Hunt Commands" + THEME.reset)
    console.log("")
    console.log(`  ${THEME.secondary}W${THEME.reset}                   Watch (live stream)`)
    console.log(`  ${THEME.secondary}X${THEME.reset}                   Scan (MCP explorer)`)
    console.log(`  ${THEME.secondary}T${THEME.reset}                   Timeline replay`)
    console.log(`  ${THEME.secondary}R${THEME.reset}                   Rule builder`)
    console.log(`  ${THEME.secondary}Q${THEME.reset}                   Query REPL`)
    console.log(`  ${THEME.secondary}D${THEME.reset}                   Diff (scan changes)`)
    console.log(`  ${THEME.secondary}E${THEME.reset}                   Evidence report`)
    console.log(`  ${THEME.secondary}M${THEME.reset}                   MITRE ATT&CK map`)
    console.log(`  ${THEME.secondary}P${THEME.reset}                   Playbook runner`)
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
