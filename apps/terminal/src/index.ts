/**
 * clawdstrike - Security-Aware AI Coding Agent Orchestrator
 *
 * A security-aware orchestration engine that dispatches coding tasks to native AI CLIs
 * (Codex, Claude Code, OpenCode) while preserving subscription authentication.
 *
 * Features:
 * - Intelligent task routing based on risk, size, and task characteristics
 * - Speculate+Vote: parallel multi-agent execution for high-stakes tasks
 * - Quality gates (pytest, mypy, ruff) with fail-fast semantics
 * - Beads work graph integration for issue tracking
 * - Git worktree isolation for safe concurrent execution
 *
 * @module clawdstrike
 */

// Core types
export * from "./types"

// Namespace modules
export { Router, type RouterConfig, type RoutingRule } from "./router"
export {
  Dispatcher,
  type ExecutionRequest,
  type Adapter,
  type AdapterResult,
} from "./dispatcher"
export {
  Workcell,
  PoolConfig,
  type PoolStatus,
  type GCResult,
} from "./workcell"
export { Verifier, type Gate, type GateConfig, type VerifyOptions } from "./verifier"
export { Speculate, type SpeculateOptions, type VoteInput } from "./speculate"
export {
  PatchLifecycle,
  type CaptureOptions,
  type MergeOptions,
  type MergeResult,
} from "./patch"
export {
  Beads,
  JSONL,
  type BeadsConfig,
  type QueryOptions,
  type ReadyIssue,
} from "./beads"
export { Telemetry, type TelemetryConfig, type AnalyticsEvent } from "./telemetry"
export { TUI } from "./tui"
export { Health, type HealthStatus, type HealthSummary, type HealthCheckOptions } from "./health"
export { MCP } from "./mcp"
export { Hushd, type HushdClient } from "./hushd"
export { Config, type ProjectConfig, type DetectionResult } from "./config"

// Tools
export {
  tools,
  getTool,
  registerTools,
  executeTool,
  dispatchTool,
  speculateTool,
  gateTool,
  type ToolDefinition,
  type ToolContext,
  type DispatchParams,
  type DispatchResult,
  type SpeculateParams,
  type SpeculateToolResult,
  type GateParams,
  type GateToolResult,
} from "./tools"

/**
 * clawdstrike version
 */
export const VERSION = "0.1.0"

/**
 * clawdstrike initialization options
 */
export interface InitOptions {
  beadsPath?: string
  telemetryDir?: string
  telemetryEnabled?: boolean
  poolConfig?: Partial<import("./workcell").PoolConfig>
}

// Module state
let initialized = false

/**
 * Initialize clawdstrike with configuration
 */
export async function init(options: InitOptions = {}): Promise<void> {
  if (initialized) {
    return
  }

  const {
    beadsPath = ".beads",
    telemetryDir = ".clawdstrike/runs",
    telemetryEnabled = true,
  } = options

  // Initialize Beads
  const { Beads } = await import("./beads")
  await Beads.init({ path: beadsPath })

  // Initialize Telemetry
  const { Telemetry } = await import("./telemetry")
  Telemetry.init({
    outputDir: telemetryDir,
    enabled: telemetryEnabled,
  })

  // Initialize Hushd client
  const { Hushd } = await import("./hushd")
  Hushd.init()

  initialized = true
}

/**
 * Shutdown clawdstrike cleanly
 */
export async function shutdown(): Promise<void> {
  if (!initialized) {
    return
  }

  // Stop MCP server
  const { MCP } = await import("./mcp")
  await MCP.stop()

  // Reset Beads
  const { Beads } = await import("./beads")
  Beads.reset()

  // Reset Telemetry
  const { Telemetry } = await import("./telemetry")
  Telemetry.reset()

  // Destroy all workcells
  const { Workcell } = await import("./workcell")
  await Workcell.destroyAll()

  // Clear health cache
  const { Health } = await import("./health")
  Health.clearCache()

  // Reset Hushd
  const { Hushd } = await import("./hushd")
  Hushd.reset()

  initialized = false
}

/**
 * Check if clawdstrike is initialized
 */
export function isInitialized(): boolean {
  return initialized
}
