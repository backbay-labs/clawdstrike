import { describe, expect, test } from "bun:test"
import type { AppState } from "../src/tui/types"
import {
  createInitialAuditLogState,
  createInitialDispatchSheetState,
  createInitialExternalExecutionSheetState,
  createInitialHuntState,
  createInitialInteractiveSessionState,
  createInitialRunListState,
} from "../src/tui/types"
import { buildInvestigationReport, getInvestigationCounts, updateInvestigation } from "../src/tui/investigation"
import { getSurfaceMeta } from "../src/tui/surfaces"

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

describe("investigation helpers", () => {
  test("tracks shared investigation counts", () => {
    const state = createState()

    updateInvestigation(state, {
      origin: "query",
      title: "Hunt Query",
      summary: "One event matched.",
      query: "deny events",
      events: [
        {
          timestamp: new Date().toISOString(),
          source: "receipt",
          kind: "policy_violation",
          verdict: "deny",
          summary: "Denied write to policy file",
          details: { path: "/tmp/policy.yaml" },
        },
      ],
      findings: ["deny: Denied write to policy file"],
    })

    expect(getInvestigationCounts(state.hunt.investigation)).toEqual({
      events: 1,
      findings: 1,
    })
  })

  test("builds a report from investigation context", () => {
    const state = createState()

    updateInvestigation(state, {
      origin: "timeline",
      title: "Timeline Replay",
      summary: "Suspicious network activity detected.",
      query: "source=hubble verdict=deny",
      events: [
        {
          timestamp: new Date().toISOString(),
          source: "hubble",
          kind: "network_connect",
          verdict: "deny",
          summary: "Denied connection to example.com:443",
          details: { host: "example.com", port: 443 },
        },
      ],
      findings: ["deny: Denied connection to example.com:443"],
    })

    const report = buildInvestigationReport(state)

    expect(report).not.toBeNull()
    expect(report!.title).toBe("Timeline Replay")
    expect(report!.severity).toBe("high")
    expect(report!.evidence).toHaveLength(1)
    expect(report!.alert.matched_events).toHaveLength(1)
  })
})

describe("surface metadata", () => {
  test("marks experimental hunt screens explicitly", () => {
    expect(getSurfaceMeta("hunt-diff").stage).toBe("experimental")
    expect(getSurfaceMeta("hunt-report").stage).toBe("supported")
  })
})
