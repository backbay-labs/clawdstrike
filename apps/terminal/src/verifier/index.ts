/**
 * Verifier - Quality gate orchestrator
 *
 * Runs quality checks (pytest, mypy, ruff, etc.) on patches.
 * Implements fail-fast semantics and score calculation.
 */

import type { GateResult, GateResults, WorkcellInfo, Diagnostic } from "../types"
import { PytestGate } from "./gates/pytest"
import { MypyGate } from "./gates/mypy"
import { RuffGate } from "./gates/ruff"
import { ClawdStrikeGate } from "./gates/clawdstrike"

export interface GateConfig {
  name: string
  command: string
  critical: boolean
  timeout?: number
  parseOutput?: (output: string) => Diagnostic[]
}

export interface Gate {
  info: {
    id: string
    name: string
    description: string
    critical: boolean
  }
  isAvailable(workcell: WorkcellInfo): Promise<boolean>
  run(workcell: WorkcellInfo, signal: AbortSignal): Promise<GateResult>
}

export interface GateInfo {
  id: string
  name: string
  description: string
  critical: boolean
}

export interface VerifyOptions {
  gates: string[]
  failFast?: boolean
  timeout?: number
}

// Gate registry - stores all available gates
const gateRegistry = new Map<string, Gate>()

// Initialize with built-in gates
function initializeBuiltinGates(): void {
  if (gateRegistry.size === 0) {
    gateRegistry.set("pytest", PytestGate)
    gateRegistry.set("mypy", MypyGate)
    gateRegistry.set("ruff", RuffGate)
    gateRegistry.set("clawdstrike", ClawdStrikeGate)
  }
}

// Ensure gates are initialized
initializeBuiltinGates()

/**
 * Verifier namespace - Quality gate operations
 */
export namespace Verifier {
  /**
   * Run all specified gates on workcell
   */
  export async function run(
    workcell: WorkcellInfo,
    options: VerifyOptions
  ): Promise<GateResults> {
    const { gates, failFast = true, timeout = 300000 } = options
    const results: GateResult[] = []

    // Create abort controller for overall timeout
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), timeout)

    try {
      for (const gateName of gates) {
        if (controller.signal.aborted) {
          break
        }

        const result = await runGate(workcell, gateName, controller.signal)
        results.push(result)

        // Fail-fast: stop on critical gate failure
        if (failFast && !result.passed && result.critical) {
          break
        }
      }
    } finally {
      clearTimeout(timeoutId)
    }

    // Calculate aggregated results
    const allPassed = results.every((r) => r.passed)
    const criticalPassed = results
      .filter((r) => r.critical)
      .every((r) => r.passed)
    const score = calculateScore(results)

    const gateResults: GateResults = {
      allPassed,
      criticalPassed,
      results,
      score,
      summary: "",
    }

    // Generate summary
    gateResults.summary = generateSummary(gateResults)

    return gateResults
  }

  /**
   * Run a single gate
   */
  export async function runGate(
    workcell: WorkcellInfo,
    gateName: string,
    signal?: AbortSignal
  ): Promise<GateResult> {
    initializeBuiltinGates()

    const gate = gateRegistry.get(gateName)
    if (!gate) {
      return {
        gate: gateName,
        passed: false,
        critical: false,
        output: `Gate "${gateName}" not found`,
        timing: { startedAt: Date.now(), completedAt: Date.now() },
      }
    }

    // Check if gate is available
    const isAvailable = await gate.isAvailable(workcell)
    if (!isAvailable) {
      return {
        gate: gate.info.id,
        passed: true, // Skip unavailable gates (pass by default)
        critical: gate.info.critical,
        output: `Gate "${gate.info.name}" not available (skipped)`,
        timing: { startedAt: Date.now(), completedAt: Date.now() },
      }
    }

    // Run the gate
    const abortSignal = signal || new AbortController().signal
    return gate.run(workcell, abortSignal)
  }

  /**
   * List all registered gates
   */
  export function listGates(): GateInfo[] {
    initializeBuiltinGates()
    return Array.from(gateRegistry.values()).map((gate) => ({
      id: gate.info.id,
      name: gate.info.name,
      description: gate.info.description,
      critical: gate.info.critical,
    }))
  }

  /**
   * Get available gates (alias for backwards compatibility)
   */
  export function getAvailableGates(): Gate[] {
    initializeBuiltinGates()
    return Array.from(gateRegistry.values())
  }

  /**
   * Register a custom gate
   */
  export function registerGate(gate: Gate): void {
    gateRegistry.set(gate.info.id, gate)
  }

  /**
   * Unregister a gate (useful for testing)
   */
  export function unregisterGate(gateId: string): boolean {
    return gateRegistry.delete(gateId)
  }

  /**
   * Get a specific gate by ID
   */
  export function getGate(gateId: string): Gate | undefined {
    initializeBuiltinGates()
    return gateRegistry.get(gateId)
  }

  /**
   * Calculate score from gate results
   *
   * Score = 100 - (errors * 10) - (warnings * 2)
   * Minimum score is 0
   */
  export function calculateScore(results: GateResult[]): number {
    let score = 100

    for (const result of results) {
      if (!result.diagnostics) continue

      for (const diag of result.diagnostics) {
        if (diag.severity === "error") {
          score -= 10
        } else if (diag.severity === "warning") {
          score -= 2
        }
        // info severity doesn't affect score
      }
    }

    // Also penalize failed gates without diagnostics
    for (const result of results) {
      if (!result.passed && (!result.diagnostics || result.diagnostics.length === 0)) {
        score -= result.critical ? 50 : 20
      }
    }

    return Math.max(0, score)
  }

  /**
   * Generate summary from gate results
   */
  export function generateSummary(results: GateResults): string {
    const lines: string[] = []

    // Overall status
    if (results.allPassed) {
      lines.push("✓ All gates passed")
    } else if (results.criticalPassed) {
      lines.push("⚠ Some gates failed (non-critical)")
    } else {
      lines.push("✗ Critical gate(s) failed")
    }

    lines.push(`Score: ${results.score}/100`)
    lines.push("")

    // Per-gate summary
    for (const result of results.results) {
      const status = result.passed ? "✓" : "✗"
      const critical = result.critical ? " (critical)" : ""
      const duration = result.timing.completedAt - result.timing.startedAt
      lines.push(`${status} ${result.gate}${critical} [${duration}ms]`)

      // Show diagnostic counts
      if (result.diagnostics && result.diagnostics.length > 0) {
        const errors = result.diagnostics.filter((d) => d.severity === "error").length
        const warnings = result.diagnostics.filter((d) => d.severity === "warning").length
        const infos = result.diagnostics.filter((d) => d.severity === "info").length

        const counts: string[] = []
        if (errors > 0) counts.push(`${errors} error${errors > 1 ? "s" : ""}`)
        if (warnings > 0) counts.push(`${warnings} warning${warnings > 1 ? "s" : ""}`)
        if (infos > 0) counts.push(`${infos} info`)

        if (counts.length > 0) {
          lines.push(`  ${counts.join(", ")}`)
        }
      }
    }

    return lines.join("\n")
  }
}

export default Verifier
