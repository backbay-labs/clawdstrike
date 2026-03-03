/**
 * TUI - Terminal User Interface for ClawdStrike
 *
 * Provides formatted output for terminal display including:
 * - Status indicators
 * - Progress display
 * - Result formatting
 * - Color support
 */

import type {
  Toolchain,
  TaskStatus,
  GateResult,
  GateResults,
  ExecutionResult,
  RoutingDecision,
  SpeculationResult,
  Rollout,
} from "../types"

// =============================================================================
// COLORS AND STYLING
// =============================================================================

const COLORS = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",

  // Foreground
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  white: "\x1b[37m",
  gray: "\x1b[90m",
} as const

const ICONS = {
  check: "✓",
  cross: "✗",
  warning: "⚠",
  info: "ℹ",
  spinner: ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
  arrow: "→",
  bullet: "•",
  box: "□",
  boxChecked: "■",
} as const

// Module state
let useColors = true
let spinnerFrame = 0

/**
 * TUI namespace - Terminal output formatting
 */
export namespace TUI {
  /**
   * Enable or disable color output
   */
  export function setColors(enabled: boolean): void {
    useColors = enabled
  }

  /**
   * Check if colors are enabled
   */
  export function colorsEnabled(): boolean {
    return useColors
  }

  // ===========================================================================
  // COLOR HELPERS
  // ===========================================================================

  function c(color: keyof typeof COLORS, text: string): string {
    if (!useColors) return text
    return `${COLORS[color]}${text}${COLORS.reset}`
  }

  function bold(text: string): string {
    return c("bold", text)
  }

  function dim(text: string): string {
    return c("dim", text)
  }

  // ===========================================================================
  // STATUS FORMATTING
  // ===========================================================================

  /**
   * Format task status with color
   */
  export function formatStatus(status: TaskStatus): string {
    switch (status) {
      case "pending":
        return c("gray", `${ICONS.box} pending`)
      case "routing":
        return c("cyan", `${ICONS.arrow} routing`)
      case "executing":
        return c("blue", `${ICONS.spinner[0]} executing`)
      case "verifying":
        return c("yellow", `${ICONS.spinner[0]} verifying`)
      case "completed":
        return c("green", `${ICONS.check} completed`)
      case "failed":
        return c("red", `${ICONS.cross} failed`)
      case "cancelled":
        return c("gray", `${ICONS.cross} cancelled`)
      default:
        return status
    }
  }

  /**
   * Format toolchain name with color
   */
  export function formatToolchain(toolchain: Toolchain): string {
    switch (toolchain) {
      case "codex":
        return c("magenta", "codex")
      case "claude":
        return c("cyan", "claude")
      case "opencode":
        return c("green", "opencode")
      case "crush":
        return c("yellow", "crush")
      default:
        return toolchain
    }
  }

  /**
   * Format gate result
   */
  export function formatGateResult(result: GateResult): string {
    const icon = result.passed ? c("green", ICONS.check) : c("red", ICONS.cross)
    const name = result.critical ? bold(result.gate) : result.gate
    const timing = dim(
      `${result.timing.completedAt - result.timing.startedAt}ms`
    )

    const diagnostics = result.diagnostics ?? []
    const errors = diagnostics.filter((d) => d.severity === "error").length
    const warnings = diagnostics.filter((d) => d.severity === "warning").length

    let suffix = ""
    if (errors > 0) {
      suffix += c("red", ` ${errors} error${errors > 1 ? "s" : ""}`)
    }
    if (warnings > 0) {
      suffix += c("yellow", ` ${warnings} warning${warnings > 1 ? "s" : ""}`)
    }

    return `${icon} ${name} ${timing}${suffix}`
  }

  /**
   * Format gate results summary
   */
  export function formatGateResults(results: GateResults): string {
    const lines: string[] = []

    // Header
    const icon = results.allPassed
      ? c("green", ICONS.check)
      : c("red", ICONS.cross)
    const score = results.allPassed
      ? c("green", `${results.score}/100`)
      : c("red", `${results.score}/100`)
    lines.push(`${icon} Gates: ${score}`)

    // Individual results
    for (const result of results.results) {
      lines.push(`  ${formatGateResult(result)}`)
    }

    // Summary
    lines.push(dim(`  ${results.summary}`))

    return lines.join("\n")
  }

  // ===========================================================================
  // EXECUTION FORMATTING
  // ===========================================================================

  /**
   * Format execution result
   */
  export function formatExecutionResult(result: ExecutionResult): string {
    const lines: string[] = []

    // Header
    const icon = result.success
      ? c("green", ICONS.check)
      : c("red", ICONS.cross)
    const toolchain = formatToolchain(result.toolchain)
    const duration = result.telemetry.completedAt - result.telemetry.startedAt
    lines.push(
      `${icon} Execution: ${toolchain} ${dim(`(${formatDuration(duration)})`)}`
    )

    // Model info
    if (result.telemetry.model) {
      lines.push(dim(`  Model: ${result.telemetry.model}`))
    }

    // Token usage
    if (result.telemetry.tokens) {
      const { input, output } = result.telemetry.tokens
      lines.push(dim(`  Tokens: ${input} in / ${output} out`))
    }

    // Cost
    if (result.telemetry.cost) {
      lines.push(dim(`  Cost: $${result.telemetry.cost.toFixed(4)}`))
    }

    // Error
    if (result.error) {
      lines.push(c("red", `  Error: ${result.error}`))
    }

    // Patch
    if (result.patch) {
      const patchLines = result.patch.split("\n").length
      lines.push(dim(`  Patch: ${patchLines} lines`))
    }

    return lines.join("\n")
  }

  /**
   * Format routing decision
   */
  export function formatRouting(decision: RoutingDecision): string {
    const lines: string[] = []

    const toolchain = formatToolchain(decision.toolchain)
    const strategy =
      decision.strategy === "speculate"
        ? c("yellow", "speculate")
        : c("cyan", "single")

    lines.push(`${ICONS.arrow} Routing: ${toolchain} (${strategy})`)
    lines.push(dim(`  Gates: ${decision.gates.join(", ")}`))
    lines.push(dim(`  Retries: ${decision.retries}, Priority: ${decision.priority}`))

    if (decision.speculation) {
      const toolchains = decision.speculation.toolchains
        .map(formatToolchain)
        .join(", ")
      lines.push(dim(`  Speculation: ${toolchains}`))
      lines.push(dim(`  Vote: ${decision.speculation.voteStrategy}`))
    }

    if (decision.reasoning) {
      lines.push(dim(`  Reason: ${decision.reasoning}`))
    }

    return lines.join("\n")
  }

  // ===========================================================================
  // SPECULATION FORMATTING
  // ===========================================================================

  /**
   * Format speculation result
   */
  export function formatSpeculationResult(result: SpeculationResult): string {
    const lines: string[] = []

    // Header
    const hasWinner = result.winner !== undefined
    const icon = hasWinner ? c("green", ICONS.check) : c("red", ICONS.cross)
    lines.push(`${icon} Speculation Result`)

    // Winner
    if (result.winner) {
      const toolchain = formatToolchain(result.winner.toolchain)
      const score = c("green", `${result.winner.gateResults.score}/100`)
      lines.push(`  ${ICONS.arrow} Winner: ${toolchain} (${score})`)
    } else {
      lines.push(c("red", `  ${ICONS.cross} No passing result`))
    }

    // All results
    lines.push(dim(`  Attempts: ${result.allResults.length}`))
    for (const r of result.allResults) {
      const toolchain = formatToolchain(r.toolchain)
      const passed = r.result?.success && r.gateResults?.allPassed
      const icon = passed ? c("green", ICONS.check) : c("red", ICONS.cross)
      const score = r.gateResults?.score ?? 0
      const isWinner = r.workcellId === result.winner?.workcellId
      const suffix = isWinner ? c("green", " ← winner") : ""
      lines.push(`    ${icon} ${toolchain}: ${score}/100${suffix}`)
    }

    // Timing
    const duration = result.timing.completedAt - result.timing.startedAt
    lines.push(dim(`  Duration: ${formatDuration(duration)}`))

    return lines.join("\n")
  }

  // ===========================================================================
  // ROLLOUT FORMATTING
  // ===========================================================================

  /**
   * Format rollout summary
   */
  export function formatRollout(rollout: Rollout): string {
    const lines: string[] = []

    // Header
    const status = formatStatus(rollout.status)
    lines.push(`${bold("Rollout")} ${dim(rollout.id.slice(0, 8))} ${status}`)

    // Task
    lines.push(dim(`  Task: ${rollout.taskId.slice(0, 8)}`))

    // Routing
    if (rollout.routing) {
      const toolchain = formatToolchain(rollout.routing.toolchain)
      lines.push(`  Toolchain: ${toolchain}`)
    }

    // Execution
    if (rollout.execution) {
      const success = rollout.execution.success
        ? c("green", "success")
        : c("red", "failed")
      lines.push(`  Execution: ${success}`)
    }

    // Verification
    if (rollout.verification) {
      const passed = rollout.verification.allPassed
        ? c("green", "passed")
        : c("red", "failed")
      const score = rollout.verification.score
      lines.push(`  Gates: ${passed} (${score}/100)`)
    }

    // Timing
    if (rollout.completedAt) {
      const duration = rollout.completedAt - rollout.startedAt
      lines.push(dim(`  Duration: ${formatDuration(duration)}`))
    }

    // Events
    if (rollout.events.length > 0) {
      lines.push(dim(`  Events: ${rollout.events.length}`))
    }

    return lines.join("\n")
  }

  // ===========================================================================
  // PROGRESS DISPLAY
  // ===========================================================================

  /**
   * Get spinner character (call repeatedly for animation)
   */
  export function spinner(): string {
    spinnerFrame = (spinnerFrame + 1) % ICONS.spinner.length
    return c("cyan", ICONS.spinner[spinnerFrame])
  }

  /**
   * Format progress message
   */
  export function progress(message: string): string {
    return `${spinner()} ${message}`
  }

  /**
   * Format success message
   */
  export function success(message: string): string {
    return `${c("green", ICONS.check)} ${message}`
  }

  /**
   * Format error message
   */
  export function error(message: string): string {
    return `${c("red", ICONS.cross)} ${message}`
  }

  /**
   * Format warning message
   */
  export function warning(message: string): string {
    return `${c("yellow", ICONS.warning)} ${message}`
  }

  /**
   * Format info message
   */
  export function info(message: string): string {
    return `${c("blue", ICONS.info)} ${message}`
  }

  // ===========================================================================
  // HELPERS
  // ===========================================================================

  /**
   * Format duration in human-readable format
   */
  export function formatDuration(ms: number): string {
    if (ms < 1000) return `${ms}ms`
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
    const minutes = Math.floor(ms / 60000)
    const seconds = Math.floor((ms % 60000) / 1000)
    return `${minutes}m ${seconds}s`
  }

  /**
   * Format a table of key-value pairs
   */
  export function formatTable(
    rows: Array<[string, string]>,
    options: { indent?: number; separator?: string } = {}
  ): string {
    const { indent = 0, separator = ": " } = options
    const maxKeyLen = Math.max(...rows.map(([k]) => k.length))
    const prefix = " ".repeat(indent)

    return rows
      .map(([key, value]) => {
        const paddedKey = key.padEnd(maxKeyLen)
        return `${prefix}${dim(paddedKey)}${separator}${value}`
      })
      .join("\n")
  }

  /**
   * Create a horizontal divider
   */
  export function divider(width: number = 40): string {
    return dim("─".repeat(width))
  }

  /**
   * Create a header with title
   */
  export function header(title: string): string {
    return `${bold(title)}\n${divider(title.length)}`
  }
}

export { launchTUI, TUIApp } from "./app"

export default TUI
