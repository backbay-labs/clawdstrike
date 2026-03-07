import { describe, expect, test } from "bun:test"
import { interactiveRunScreen } from "../src/tui/screens/interactive-run"
import type { AppController, AppState, InputMode, ScreenContext } from "../src/tui/types"
import {
  createInitialAuditLogState,
  createInitialDispatchSheetState,
  createInitialExternalExecutionSheetState,
  createInitialHuntState,
  createInitialInteractiveSessionState,
  createInitialRunListState,
} from "../src/tui/types"
import { createManagedRun } from "../src/tui/runs"
import { THEME } from "../src/tui/theme"
import { stripAnsi } from "../src/tui/components/types"

class TestApp implements AppController {
  public screen: InputMode | null = null
  public sentInputs: string[] = []
  public stagedTaskSends = 0
  public updatedTaskText: string | null = null
  public focus: "pty" | "controls" | "staged_task" | null = null
  public toggledControls = 0

  setScreen(mode: InputMode): void {
    this.screen = mode
  }

  launchDispatchSheet(): void {}
  closeDispatchSheet(): void {}
  openRun(): void {}
  beginAttachRun(): void {}
  confirmAttachRun(): void {}
  cancelAttachRun(): void {}
  beginExternalRun(): void {}
  confirmExternalRun(): void {}
  cancelExternalRun(): void {}
  launchRunInMode(): void {}
  relaunchRunInMode(): void {}
  cancelRun(): void {}
  render(): void {}
  runHealthcheck(): void {}
  connectHushd(): void {}
  submitPrompt(): void {}
  runGates(): void {}
  showBeads(): void {}
  showRuns(): void {}
  showHelp(): void {}
  quit(): void {}
  getCwd(): string {
    return process.cwd()
  }
  refreshDesktopAgent(): void {}
  interactiveSendInput(input: string): void {
    this.sentInputs.push(input)
  }
  interactiveSendStagedTask(): void {
    this.stagedTaskSends += 1
  }
  interactiveUpdateStagedTask(text: string): void {
    this.updatedTaskText = text
  }
  interactiveSetFocus(focus: "pty" | "controls" | "staged_task"): void {
    this.focus = focus
  }
  interactiveToggleControls(): void {
    this.toggledControls += 1
  }
}

function createState(): AppState {
  return {
    promptBuffer: "",
    agentIndex: 0,
    homeActionIndex: 0,
    homeFocus: "prompt",
    homePromptTraceStartFrame: 0,
    homeActionsTraceStartFrame: 0,
    inputMode: "interactive-run",
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

function createContext(state: AppState, app: AppController): ScreenContext {
  return {
    state,
    width: 120,
    height: 36,
    theme: THEME,
    app,
  }
}

describe("interactive run surface", () => {
  test("renders the embedded session shell for the active run", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "reply with ok",
      action: "dispatch",
      agentId: "claude",
      agentLabel: "Claude",
      mode: "attach",
    })

    run.interactiveSurface = "embedded"
    run.interactivePhase = "awaiting_first_input"
    run.interactiveSessionId = "pty_embedded_123"
    state.runs.entries = [run]
    state.activeRunId = run.id
    state.runs.selectedRunId = run.id
    state.interactiveSession = {
      ...state.interactiveSession,
      runId: run.id,
      sessionId: "pty_embedded_123",
      phase: "awaiting_first_input",
      stagedTask: {
        text: run.prompt,
        sent: false,
        editable: true,
      },
    }

    const output = stripAnsi(interactiveRunScreen.render(createContext(state, app)))
    expect(output).toContain("Interactive Run")
    expect(output).toContain("Session Rail")
    expect(output).toContain("Task Bar")
    expect(output).toContain("Transcript")
    expect(output).toContain("reply with ok")
    expect(output).toContain("Ctrl+G")
  })

  test("returns to run detail from the scaffold surface", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "reply with ok",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })

    state.runs.entries = [run]
    state.activeRunId = run.id

    expect(interactiveRunScreen.handleInput("\x1b", createContext(state, app))).toBe(true)
    expect(app.screen).toBe("run-detail")
  })

  test("opens controls from Ctrl+G", () => {
    const state = createState()
    const app = new TestApp()
    state.interactiveSession.focus = "pty"

    expect(interactiveRunScreen.handleInput("\x07", createContext(state, app))).toBe(true)
    expect(app.toggledControls).toBe(1)
  })

  test("sends the staged task from staged task focus", () => {
    const state = createState()
    const app = new TestApp()
    state.interactiveSession.focus = "staged_task"
    state.interactiveSession.stagedTask.text = "reply with ok"

    expect(interactiveRunScreen.handleInput("\r", createContext(state, app))).toBe(true)
    expect(app.stagedTaskSends).toBe(1)
  })

  test("accepts pasted staged task chunks", () => {
    const state = createState()
    const app = new TestApp()
    state.interactiveSession.focus = "staged_task"
    state.interactiveSession.stagedTask.editable = true
    state.interactiveSession.stagedTask.text = "reply"

    expect(interactiveRunScreen.handleInput(" with ok", createContext(state, app))).toBe(true)
    expect(app.updatedTaskText).toBe("reply with ok")
  })

  test("forwards printable input to the PTY when PTY focus is active", () => {
    const state = createState()
    const app = new TestApp()
    state.interactiveSession.focus = "pty"

    expect(interactiveRunScreen.handleInput("h", createContext(state, app))).toBe(true)
    expect(app.sentInputs).toEqual(["h"])
  })

  test("shows a waiting hint while Claude is still preparing the first visible response", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "hi",
      action: "dispatch",
      agentId: "claude",
      agentLabel: "Claude",
      mode: "attach",
    })
    run.interactiveSurface = "embedded"
    run.interactiveSessionId = "pty_embedded_wait"
    state.runs.entries = [run]
    state.activeRunId = run.id
    state.runs.selectedRunId = run.id
    state.interactiveSession.runId = run.id
    state.interactiveSession.sessionId = run.interactiveSessionId
    state.interactiveSession.toolchain = "claude"
    state.interactiveSession.phase = "running"
    state.interactiveSession.focus = "pty"
    state.interactiveSession.stagedTask.text = "hi"
    state.interactiveSession.stagedTask.sent = true
    state.interactiveSession.scrollback = ["────────────────────"]

    const output = stripAnsi(interactiveRunScreen.render(createContext(state, app)))
    expect(output).toContain("Waiting for interactive output")
    expect(output).toContain("Claude is processing the staged task")
  })

  test("surfaces recent activity while Claude redraw output is still settling", () => {
    const state = createState()
    const app = new TestApp()
    const run = createManagedRun({
      prompt: "hi",
      action: "dispatch",
      agentId: "claude",
      agentLabel: "Claude",
      mode: "attach",
    })
    run.interactiveSurface = "embedded"
    run.interactiveSessionId = "pty_embedded_activity"
    state.runs.entries = [run]
    state.activeRunId = run.id
    state.runs.selectedRunId = run.id
    state.interactiveSession.runId = run.id
    state.interactiveSession.sessionId = run.interactiveSessionId
    state.interactiveSession.toolchain = "claude"
    state.interactiveSession.phase = "running"
    state.interactiveSession.focus = "pty"
    state.interactiveSession.stagedTask.text = "hi"
    state.interactiveSession.stagedTask.sent = true
    state.interactiveSession.scrollback = ["› staged task sent: hi", "hi"]
    state.interactiveSession.activityLines = ["Medium /model", "Embellishing…"]

    const output = stripAnsi(interactiveRunScreen.render(createContext(state, app)))
    expect(output).toContain("Recent Activity")
    expect(output).toContain("Embellishing")
  })
})
