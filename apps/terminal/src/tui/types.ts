/**
 * TUI Types - Core type definitions for the screen-based architecture.
 */

import type { ThemeColors } from "./theme"
import type { HealthSummary } from "../health"
import type { DaemonEvent, AuditStats, PolicyResponse } from "../hushd"
import type { DetectionResult } from "../config"
import type {
  TimelineEvent,
  Alert,
  ScanPathResult,
  ScanDiff,
  HuntReport,
  WatchStats,
  RuleCondition,
} from "../hunt/types"
import type { ListViewport } from "./components/scrollable-list"
import type { TreeViewport } from "./components/tree-view"
import type { FormState } from "./components/form"
import type { LogState } from "./components/streaming-log"
import type { GridSelection } from "./components/grid"

// =============================================================================
// SCREEN SYSTEM
// =============================================================================

/**
 * Context passed to every screen method.
 * Provides access to shared state, dimensions, and theme.
 */
export interface ScreenContext {
  state: AppState
  width: number
  height: number
  theme: ThemeColors
  /** Reference to the app for triggering actions */
  app: AppController
}

/**
 * Screen interface - each screen implements render + input handling.
 */
export interface Screen {
  /** Render the screen content as a single string */
  render(ctx: ScreenContext): string
  /** Handle a keypress. Return true if the key was consumed. */
  handleInput(key: string, ctx: ScreenContext): boolean
  /** Called when this screen becomes active */
  onEnter?(ctx: ScreenContext): void
  /** Called when this screen is being left */
  onExit?(ctx: ScreenContext): void
}

/**
 * Minimal interface for screens to call back into the app.
 */
export interface AppController {
  /** Navigate to a different screen */
  setScreen(mode: InputMode): void
  /** Trigger a re-render */
  render(): void
  /** Run healthcheck */
  runHealthcheck(): void
  /** Reconnect to hushd */
  connectHushd(): void
  /** Submit a prompt */
  submitPrompt(action: "dispatch" | "speculate"): void
  /** Run quality gates */
  runGates(): void
  /** Show beads (exits TUI) */
  showBeads(): void
  /** Show runs (exits TUI) */
  showRuns(): void
  /** Show help (exits TUI) */
  showHelp(): void
  /** Quit the app */
  quit(): void
  /** Get CWD */
  getCwd(): string
}

// =============================================================================
// COMMANDS
// =============================================================================

export interface Command {
  key: string
  label: string
  description: string
  action: () => Promise<void> | void
}

// =============================================================================
// INPUT MODES
// =============================================================================

export type InputMode =
  | "main"
  | "commands"
  | "integrations"
  | "security"
  | "audit"
  | "policy"
  | "result"
  | "setup"
  // Hunt screens
  | "hunt-watch"
  | "hunt-scan"
  | "hunt-timeline"
  | "hunt-rule-builder"
  | "hunt-query"
  | "hunt-diff"
  | "hunt-report"
  | "hunt-mitre"
  | "hunt-playbook"

// =============================================================================
// DISPATCH RESULT
// =============================================================================

export interface DispatchResultInfo {
  success: boolean
  taskId: string
  agent: string
  action: "dispatch" | "speculate"
  routing?: { toolchain: string; strategy: string; gates: string[] }
  execution?: {
    success: boolean
    error?: string
    model?: string
    tokens?: { input: number; output: number }
    cost?: number
  }
  verification?: {
    allPassed: boolean
    score: number
    summary: string
    results: Array<{ gate: string; passed: boolean }>
  }
  error?: string
  duration: number
}

// =============================================================================
// HUNT STATE
// =============================================================================

export interface HuntWatchState {
  log: LogState
  running: boolean
  filter: "all" | "allow" | "deny" | "audit"
  stats: WatchStats | null
  lastAlert: Alert | null
  alertFadeTimer: ReturnType<typeof setTimeout> | null
}

export interface HuntScanState {
  results: ScanPathResult[]
  tree: TreeViewport
  loading: boolean
  error: string | null
  selectedDetail: string | null
}

export interface HuntTimelineState {
  events: TimelineEvent[]
  list: ListViewport
  expandedIndex: number | null
  sourceFilters: { tetragon: boolean; hubble: boolean; receipt: boolean; spine: boolean }
  loading: boolean
  error: string | null
}

export interface HuntRuleBuilderState {
  form: FormState
  conditions: RuleCondition[]
  conditionList: ListViewport
  dryRunResults: Alert[]
  dryRunning: boolean
  saving: boolean
  error: string | null
  statusMessage: string | null
}

export interface HuntQueryState {
  mode: "nl" | "structured"
  nlInput: string
  structuredForm: FormState
  results: TimelineEvent[]
  resultList: ListViewport
  loading: boolean
  error: string | null
}

export interface HuntDiffState {
  current: ScanPathResult[]
  previous: ScanPathResult[]
  diff: ScanDiff | null
  list: ListViewport
  expandedServer: string | null
  loading: boolean
  error: string | null
}

export interface HuntReportState {
  report: HuntReport | null
  list: ListViewport
  expandedEvidence: number | null
  error: string | null
}

export interface HuntMitreState {
  grid: GridSelection
  matrix: number[][]
  tactics: string[]
  techniques: string[]
  events: TimelineEvent[]
  drilldownEvents: TimelineEvent[]
  drilldownList: ListViewport
  loading: boolean
  error: string | null
}

export interface HuntPlaybookState {
  steps: import("../hunt/types").PlaybookStep[]
  selectedStep: number
  detailList: ListViewport
  running: boolean
  error: string | null
  report: HuntReport | null
}

export interface HuntState {
  watch: HuntWatchState
  scan: HuntScanState
  timeline: HuntTimelineState
  ruleBuilder: HuntRuleBuilderState
  query: HuntQueryState
  diff: HuntDiffState
  report: HuntReportState
  mitre: HuntMitreState
  playbook: HuntPlaybookState
}

// =============================================================================
// APP STATE
// =============================================================================

export interface AppState {
  // Input
  promptBuffer: string
  agentIndex: number

  // UI mode
  inputMode: InputMode
  commandIndex: number

  // Status
  statusMessage: string
  isRunning: boolean
  activeRuns: number
  openBeads: number
  lastRefresh: Date

  // Health
  health: HealthSummary | null
  healthChecking: boolean

  // Animation
  animationFrame: number

  // Security (hushd)
  hushdConnected: boolean
  recentEvents: DaemonEvent[]
  auditStats: AuditStats | null
  activePolicy: PolicyResponse | null
  securityError: string | null

  // Last dispatch result
  lastResult: DispatchResultInfo | null

  // Setup wizard
  setupDetection: DetectionResult | null
  setupStep: "detecting" | "review" | "done"
  setupSandboxIndex: number

  // Hunt
  hunt: HuntState
}

// =============================================================================
// FACTORY
// =============================================================================

export function createInitialHuntState(): HuntState {
  return {
    watch: {
      log: { lines: [], maxLines: 1000, viewport: 0, paused: false },
      running: false,
      filter: "all",
      stats: null,
      lastAlert: null,
      alertFadeTimer: null,
    },
    scan: {
      results: [],
      tree: { offset: 0, selected: 0, expandedKeys: new Set() },
      loading: false,
      error: null,
      selectedDetail: null,
    },
    timeline: {
      events: [],
      list: { offset: 0, selected: 0 },
      expandedIndex: null,
      sourceFilters: { tetragon: true, hubble: true, receipt: true, spine: true },
      loading: false,
      error: null,
    },
    ruleBuilder: {
      form: {
        fields: [
          { type: "text", label: "Name", value: "", placeholder: "rule-name" },
          { type: "select", label: "Severity", options: ["low", "medium", "high", "critical"], selectedIndex: 1 },
          { type: "text", label: "Window (s)", value: "300", placeholder: "300" },
          { type: "text", label: "Description", value: "", placeholder: "Rule description" },
        ],
        focusedIndex: 0,
      },
      conditions: [],
      conditionList: { offset: 0, selected: 0 },
      dryRunResults: [],
      dryRunning: false,
      saving: false,
      error: null,
      statusMessage: null,
    },
    query: {
      mode: "nl",
      nlInput: "",
      structuredForm: {
        fields: [
          { type: "select", label: "Source", options: ["any", "tetragon", "hubble", "receipt", "spine"], selectedIndex: 0 },
          { type: "select", label: "Verdict", options: ["any", "allow", "deny", "audit"], selectedIndex: 0 },
          { type: "text", label: "Since", value: "", placeholder: "1h, 24h, 7d" },
          { type: "text", label: "Limit", value: "50", placeholder: "50" },
        ],
        focusedIndex: 0,
      },
      results: [],
      resultList: { offset: 0, selected: 0 },
      loading: false,
      error: null,
    },
    diff: {
      current: [],
      previous: [],
      diff: null,
      list: { offset: 0, selected: 0 },
      expandedServer: null,
      loading: false,
      error: null,
    },
    report: {
      report: null,
      list: { offset: 0, selected: 0 },
      expandedEvidence: null,
      error: null,
    },
    mitre: {
      grid: { row: 0, col: 0 },
      matrix: [],
      tactics: [],
      techniques: [],
      events: [],
      drilldownEvents: [],
      drilldownList: { offset: 0, selected: 0 },
      loading: false,
      error: null,
    },
    playbook: {
      steps: [],
      selectedStep: 0,
      detailList: { offset: 0, selected: 0 },
      running: false,
      error: null,
      report: null,
    },
  }
}
