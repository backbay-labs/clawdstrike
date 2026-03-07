import { describe, expect, test } from "bun:test"
import type { AppController, AppState, InputMode, ScreenContext } from "../src/tui/types"
import {
  createInitialAuditLogState,
  createInitialDispatchSheetState,
  createInitialExternalExecutionSheetState,
  createInitialHuntState,
  createInitialInteractiveSessionState,
  createInitialRunListState,
} from "../src/tui/types"
import { createMainScreen } from "../src/tui/screens/main"
import { runsScreen } from "../src/tui/screens/runs"
import { runDetailScreen } from "../src/tui/screens/run-detail"
import { resultScreen } from "../src/tui/screens/result"
import { createManagedRun } from "../src/tui/runs"
import { THEME } from "../src/tui/theme"
import { stripAnsi } from "../src/tui/components/types"
import { TUIApp } from "../src/tui/app"

class TestApp implements AppController {
  public screen: InputMode | null = null
  public renderCount = 0
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
  quit(): void {}
  getCwd(): string {
    return process.cwd()
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

describe("dispatch sheet overlay", () => {
  test("accepts pasted prompt text chunks on the home surface", () => {
    const state = createState()
    const app = new TestApp()
    const screen = createMainScreen([])

    expect(screen.handleInput("reply with ok", createContext(state, app))).toBe(true)
    expect(state.promptBuffer).toBe("reply with ok")
  })

  test("keeps Enter in prompt focus routed through submitPrompt", () => {
    const state = createState()
    state.promptBuffer = "triage phase one"
    const app = new TestApp()
    const screen = createMainScreen([])

    expect(screen.handleInput("\r", createContext(state, app))).toBe(true)
    expect(app.submitted).toBe("dispatch")
  })

  test("renders and handles dispatch-sheet controls", () => {
    const state = createState()
    state.inputMode = "dispatch-sheet"
    state.dispatchSheet = {
      open: true,
      prompt: "ship the phase one base",
      action: "dispatch",
      mode: "managed",
      agentIndex: 0,
      focusedField: 2,
      error: null,
    }
    const app = new TestApp()
    const screen = createMainScreen([])
    const ctx = createContext(state, app, 120, 36)

    const output = stripAnsi(screen.render(ctx))
    expect(output).toContain("Dispatch Sheet")
    expect(output).toContain("ship the phase one base")

    expect(screen.handleInput("\x1b[C", ctx)).toBe(true)
    expect(state.dispatchSheet.mode).toBe("attach")

    expect(screen.handleInput("\r", ctx)).toBe(true)
    expect(app.launchedDispatchSheet).toBe(true)

    expect(screen.handleInput("\x1b", ctx)).toBe(true)
    expect(app.closedDispatchSheet).toBe(true)
  })
})

describe("run detail surface", () => {
  test("renders managed run summary, events, and verification", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "Investigate the failing run detail flow",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })

    run.phase = "review_ready"
    run.completedAt = "2026-03-06T08:00:03Z"
    run.routing = { toolchain: "codex", strategy: "single", gates: ["bun test"] }
    run.execution = { success: true, model: "gpt-5.2", tokens: { input: 12, output: 34 }, cost: 0.1234 }
    run.verification = {
      allPassed: true,
      criticalPassed: true,
      score: 97,
      summary: "All required checks passed.",
      results: [{ gate: "bun test", passed: true }],
    }
    run.result = {
      success: true,
      taskId: "task-123",
      agent: "Codex",
      action: "dispatch",
      routing: run.routing,
      execution: run.execution,
      verification: run.verification ?? undefined,
      duration: 4200,
    }
    run.events = [
      ...run.events,
      { timestamp: "2026-03-06T08:00:01Z", kind: "status", message: "Routing task" },
      { timestamp: "2026-03-06T08:00:02Z", kind: "log", message: "Running agent" },
      { timestamp: "2026-03-06T08:00:03Z", kind: "status", message: "Run ready for review" },
    ]

    state.runs.entries = [run]
    state.activeRunId = run.id
    state.runs.selectedRunId = run.id
    state.runDetailEvents = { offset: 0, selected: run.events.length - 1 }

    const output = stripAnsi(runDetailScreen.render(createContext(state, app, 120, 36)))
    expect(output).toContain("Managed Run Detail")
    expect(output).toContain(run.id)
    expect(output).toContain("Live Events")
    expect(output).toContain("Run ready for review")
    expect(output).toContain("All required checks passed.")
  })

  test("routes cancel and review actions through the controller", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "Review the finished run",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    run.result = {
      success: true,
      taskId: "task-456",
      agent: "Codex",
      action: "dispatch",
      duration: 1000,
    }
    state.runs.entries = [run]
    state.activeRunId = run.id

    const ctx = createContext(state, app)
    expect(runDetailScreen.handleInput("c", ctx)).toBe(true)
    expect(app.canceledRunId).toBe(run.id)

    expect(runDetailScreen.handleInput("\r", ctx)).toBe(true)
    expect(app.screen).toBe("result")
  })

  test("routes backlog shortcut through the controller", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "Return me to backlog",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    state.runs.entries = [run]
    state.activeRunId = run.id

    expect(runDetailScreen.handleInput("r", createContext(state, app))).toBe(true)
    expect(app.screen).toBe("runs")
  })

  test("shows the attach confirmation and routes attach actions through the controller", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "Attach me here",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
      mode: "attach",
    })
    state.runs.entries = [run]
    state.activeRunId = run.id
    state.pendingAttachRunId = run.id

    const ctx = createContext(state, app, 120, 36)
    const output = stripAnsi(runDetailScreen.render(ctx))
    expect(output).toContain("Attach To Run")
    expect(output).toContain("Enter open")

    expect(runDetailScreen.handleInput("\r", ctx)).toBe(true)
    expect(app.confirmedAttach).toBe(true)

    expect(runDetailScreen.handleInput("a", createContext({ ...state, pendingAttachRunId: null }, app))).toBe(true)
    expect(app.beganAttachRunId).toBe(run.id)
  })

  test("shows the external sheet and routes adapter and fallback actions through the controller", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "Open me in WezTerm",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
      mode: "external",
    })
    state.runs.entries = [run]
    state.activeRunId = run.id
    state.externalSheet = {
      runId: run.id,
      adapters: [
        { id: "wezterm", label: "WezTerm", description: "Launch a new WezTerm window." },
        { id: "terminal-app", label: "Terminal.app", description: "Launch macOS Terminal." },
      ],
      selectedIndex: 0,
      loading: false,
      error: null,
    }

    const ctx = createContext(state, app, 120, 36)
    const output = stripAnsi(runDetailScreen.render(ctx))
    expect(output).toContain("Open External Execution")
    expect(output).toContain("WezTerm")

    expect(runDetailScreen.handleInput("\x1b[B", ctx)).toBe(true)
    expect(state.externalSheet.selectedIndex).toBe(1)

    expect(runDetailScreen.handleInput("\r", ctx)).toBe(true)
    expect(app.confirmedExternal).toBe(true)

    expect(runDetailScreen.handleInput("m", ctx)).toBe(true)
    expect(app.launchedFallback).toEqual({ runId: run.id, mode: "managed" })
  })

  test("relaunches completed managed runs into interactive modes", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "Relaunch this prompt in another mode",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    run.phase = "review_ready"
    run.completedAt = "2026-03-06T08:00:03Z"
    run.result = {
      success: true,
      taskId: "task-789",
      agent: "Codex",
      action: "dispatch",
      duration: 1000,
    }
    state.runs.entries = [run]
    state.activeRunId = run.id

    const ctx = createContext(state, app)
    expect(runDetailScreen.handleInput("a", ctx)).toBe(true)
    const attachRelaunch = app.relaunchedRun as { runId: string; mode: "attach" | "external" } | null
    expect(attachRelaunch).not.toBeNull()
    expect(attachRelaunch?.runId).toBe(run.id)
    expect(attachRelaunch?.mode).toBe("attach")

    app.relaunchedRun = null
    expect(runDetailScreen.handleInput("o", ctx)).toBe(true)
    const externalRelaunch = app.relaunchedRun as { runId: string; mode: "attach" | "external" } | null
    expect(externalRelaunch).not.toBeNull()
    expect(externalRelaunch?.runId).toBe(run.id)
    expect(externalRelaunch?.mode).toBe("external")
  })
})

describe("result screen managed-run handoff", () => {
  test("returns to the active run detail when one is selected", () => {
    const state = createState()
    const app = new TestApp()
    state.activeRunId = "run_123"

    expect(resultScreen.handleInput("\r", createContext(state, app))).toBe(true)
    expect(app.openedRunId).toBe("run_123")
  })
})

describe("TUIApp phase one dispatch flow", () => {
  test("opens the dispatch sheet instead of running immediately", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        promptBuffer: string
        inputMode: string
        dispatchSheet: {
          open: boolean
          action: "dispatch" | "speculate"
          prompt: string
        }
      }
      render: () => void
      submitPrompt: (action: "dispatch" | "speculate") => Promise<void>
    }

    app.render = () => {}
    app.state.promptBuffer = "wire the dispatch sheet"

    await app.submitPrompt("dispatch")

    expect(app.state.inputMode).toBe("dispatch-sheet")
    expect(app.state.dispatchSheet.open).toBe(true)
    expect(app.state.dispatchSheet.action).toBe("dispatch")
    expect(app.state.dispatchSheet.prompt).toBe("wire the dispatch sheet")
  })

  test("launches a managed run through the sheet and preserves the result bridge", () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        promptBuffer: string
        inputMode: string
        activeRunId: string | null
        lastResult: { taskId: string; action: string } | null
        runs: {
          entries: Array<{
            id: string
            phase: string
            prompt: string
            result: { taskId: string } | null
            events: Array<{ message: string }>
          }>
        }
      }
      render: () => void
      openDispatchSheet: (action: "dispatch" | "speculate") => void
      launchDispatchSheet: () => void
      launchManagedRun: (run: { id: string; prompt: string; action: "dispatch" | "speculate" }) => Promise<void>
      finishRun: (
        run: { id: string; prompt: string; action: "dispatch" | "speculate" },
        result: { success: boolean; taskId: string; agent: string; action: "dispatch" | "speculate"; duration: number },
      ) => void
    }

    app.render = () => {}
    app.launchManagedRun = async (run) => {
      app.finishRun(run, {
        success: true,
        taskId: "task-12345678",
        agent: "Claude",
        action: "dispatch",
        duration: 25,
      })
    }

    app.state.promptBuffer = "launch foundation"
    app.openDispatchSheet("dispatch")
    app.launchDispatchSheet()

    expect(app.state.inputMode).toBe("run-detail")
    expect(app.state.activeRunId).not.toBeNull()
    expect(app.state.runs.entries).toHaveLength(1)
    expect(app.state.runs.entries[0]?.prompt).toBe("launch foundation")
    expect(app.state.runs.entries[0]?.phase).toBe("completed")
    expect(app.state.runs.entries[0]?.result?.taskId).toBe("task-12345678")
    expect(app.state.runs.entries[0]?.events.some((event) => event.message.includes("Run completed"))).toBe(true)
    expect(app.state.lastResult?.taskId).toBe("task-12345678")
    expect(app.state.lastResult?.action).toBe("dispatch")
  })

  test("stages attach mode in run detail and opens the attach confirmation", () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        promptBuffer: string
        inputMode: string
        activeRunId: string | null
        pendingAttachRunId: string | null
        runs: {
          entries: Array<{
            id: string
            mode: string
            attachState: string
            canAttach: boolean
          }>
        }
        dispatchSheet: {
          mode: "managed" | "attach" | "external"
          action: "dispatch" | "speculate"
          open: boolean
        }
      }
      render: () => void
      openDispatchSheet: (action: "dispatch" | "speculate") => void
      launchDispatchSheet: () => void
    }

    app.render = () => {}
    app.state.promptBuffer = "launch attached flow"
    app.openDispatchSheet("dispatch")
    app.state.dispatchSheet.mode = "attach"
    app.launchDispatchSheet()

    expect(app.state.inputMode).toBe("run-detail")
    expect(app.state.activeRunId).not.toBeNull()
    expect(app.state.pendingAttachRunId).toBe(app.state.activeRunId)
    expect(app.state.runs.entries[0]?.mode).toBe("attach")
    expect(app.state.runs.entries[0]?.attachState).toBe("detached")
    expect(app.state.runs.entries[0]?.canAttach).toBe(true)
  })

  test("stages external mode in run detail and opens the external selection sheet", async () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        promptBuffer: string
        inputMode: string
        agentIndex: number
        activeRunId: string | null
        dispatchSheet: {
          mode: "managed" | "attach" | "external"
          action: "dispatch" | "speculate"
          open: boolean
        }
        externalSheet: {
          runId: string | null
          loading: boolean
          adapters?: Array<{ id: string; label: string; description: string }>
          selectedIndex?: number
          error?: string | null
        }
        runs: {
          entries: Array<{
            id: string
            mode: string
            external: { status: string }
          }>
        }
      }
      render: () => void
      openDispatchSheet: (action: "dispatch" | "speculate") => void
      launchDispatchSheet: () => void
      launchExternalDispatchSheet: (
        prompt: string,
        action: "dispatch" | "speculate",
        agentIndex: number,
        agentLabel: string,
        agentId: string,
      ) => Promise<void>
    }

    app.render = () => {}
    app.launchExternalDispatchSheet = async (prompt, action, agentIndex, agentLabel, agentId) => {
      const run = createManagedRun({
        prompt,
        action,
        agentId,
        agentLabel,
        mode: "external",
      })
      app.state.agentIndex = agentIndex
      app.state.dispatchSheet = createInitialDispatchSheetState()
      app.state.promptBuffer = ""
      app.state.inputMode = "run-detail"
      app.state.activeRunId = run.id
      app.state.runs.entries = [run]
      app.state.externalSheet = {
        runId: run.id,
        loading: false,
        adapters: [{ id: "tmux-split", label: "tmux split", description: "Open in tmux split." }],
        selectedIndex: 0,
        error: null,
      }
    }
    app.state.promptBuffer = "launch external flow"
    app.openDispatchSheet("dispatch")
    app.state.dispatchSheet.mode = "external"
    app.launchDispatchSheet()
    await Promise.resolve()

    expect(app.state.inputMode).toBe("run-detail")
    expect(app.state.activeRunId).not.toBeNull()
    expect(app.state.externalSheet.runId).toBe(app.state.activeRunId)
    expect(app.state.runs.entries[0]?.mode).toBe("external")
    expect(app.state.runs.entries[0]?.external.status).toBe("idle")
  })

  test("keeps completed runs reopenable from the runs backlog without hijacking navigation", () => {
    const app = new TUIApp(process.cwd()) as unknown as {
      state: {
        inputMode: InputMode
        activeRunId: string | null
        lastResult: { taskId: string } | null
        runs: {
          entries: Array<{
            id: string
            phase: string
            completedAt: string | null
            result: { taskId: string } | null
          }>
          selectedRunId: string | null
        }
      }
      render: () => void
      replaceRun: (run: ReturnType<typeof createManagedRun>) => void
      finishRun: (
        run: ReturnType<typeof createManagedRun>,
        result: { success: boolean; taskId: string; agent: string; action: "dispatch" | "speculate"; duration: number },
      ) => void
      showRuns: () => Promise<void>
    }

    app.render = () => {}
    const run = createManagedRun({
      prompt: "Leave detail while execution finishes",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })

    app.replaceRun(run)
    app.state.inputMode = "main"
    app.finishRun(run, {
      success: true,
      taskId: "task-finished",
      agent: "Codex",
      action: "dispatch",
      duration: 99,
    })

    expect(app.state.inputMode as InputMode).toBe("main")
    expect(app.state.runs.entries[0]?.phase).toBe("completed")
    expect(app.state.runs.entries[0]?.completedAt).not.toBeNull()
    expect(app.state.runs.selectedRunId).toBe(app.state.runs.entries[0]?.id ?? null)

    void app.showRuns()
    expect(app.state.inputMode as InputMode).toBe("runs")
  })
})

describe("runs surface", () => {
  test("renders the managed backlog and opens review-ready runs into result", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "Review this managed run from the backlog",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    run.phase = "review_ready"
    run.completedAt = "2026-03-06T09:00:00Z"
    run.routing = { toolchain: "codex", strategy: "single", gates: ["bun test"] }
    run.verification = {
      allPassed: false,
      criticalPassed: true,
      score: 81,
      summary: "One gate failed but the run still needs operator review.",
      results: [{ gate: "bun test", passed: false }],
    }
    run.result = {
      success: true,
      taskId: "task-review",
      agent: "Codex",
      action: "dispatch",
      routing: run.routing,
      verification: run.verification ?? undefined,
      duration: 3200,
    }
    state.runs.entries = [run]
    state.runs.filter = "all"

    const ctx = createContext(state, app, 132, 36)
    const output = stripAnsi(runsScreen.render(ctx))
    expect(output).toContain("Managed Runs")
    expect(output).toContain("Review Guidance")
    expect(output).toContain("One gate failed but the run still needs operator review.")

    expect(runsScreen.handleInput("r", ctx)).toBe(true)
    expect(state.activeRunId).toBe(run.id)
    expect(state.lastResult?.taskId).toBe("task-review")
    expect(app.screen).toBe("result")
  })
})
