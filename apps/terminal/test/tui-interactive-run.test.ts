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

describe("interactive run scaffold", () => {
  test("renders the phase six shell for the active run", () => {
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
    expect(output).toContain("Phase 6 scaffold only.")
    expect(output).toContain("Staged Task")
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
})
