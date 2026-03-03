/**
 * Telemetry - Execution tracking and rollout generation
 *
 * Generates comprehensive telemetry for analysis and improvement.
 * Creates rollout.json files for each execution.
 */

import * as fs from "node:fs/promises"
import * as path from "node:path"
import type {
  Rollout,
  TelemetryEvent,
  TaskId,
  TaskStatus,
  RoutingDecision,
  ExecutionResult,
  GateResults,
} from "../types"

export interface TelemetryConfig {
  outputDir: string
  enabled: boolean
  verbose?: boolean
}

export interface AnalyticsEvent {
  event: string
  timestamp: string
  properties: Record<string, unknown>
}

// Module state
let config: TelemetryConfig | null = null
const activeRollouts = new Map<string, Rollout>()

/**
 * Telemetry namespace - Execution tracking operations
 */
export namespace Telemetry {
  /**
   * Initialize telemetry system
   */
  export function init(cfg: TelemetryConfig): void {
    config = cfg
  }

  /**
   * Get current config (returns default if not initialized)
   */
  function getConfig(): TelemetryConfig {
    return config ?? { outputDir: ".clawdstrike/runs", enabled: true }
  }

  /**
   * Start a new rollout
   */
  export function startRollout(taskId: TaskId): Rollout {
    const rollout: Rollout = {
      id: crypto.randomUUID(),
      taskId,
      startedAt: Date.now(),
      status: "pending",
      events: [],
    }

    activeRollouts.set(rollout.id, rollout)
    return rollout
  }

  /**
   * Record an event
   */
  export function recordEvent(
    rolloutId: string,
    event: Omit<TelemetryEvent, "timestamp">
  ): void {
    const rollout = activeRollouts.get(rolloutId)
    if (!rollout) {
      return // Silently ignore if rollout not found
    }

    rollout.events.push({
      ...event,
      timestamp: Date.now(),
    })
  }

  /**
   * Update rollout status
   */
  export function updateStatus(rolloutId: string, status: TaskStatus): void {
    const rollout = activeRollouts.get(rolloutId)
    if (rollout) {
      rollout.status = status
    }
  }

  /**
   * Set routing decision on rollout
   */
  export function setRouting(
    rolloutId: string,
    routing: RoutingDecision
  ): void {
    const rollout = activeRollouts.get(rolloutId)
    if (rollout) {
      rollout.routing = routing
    }
  }

  /**
   * Set execution result on rollout
   */
  export function setExecution(
    rolloutId: string,
    execution: ExecutionResult
  ): void {
    const rollout = activeRollouts.get(rolloutId)
    if (rollout) {
      rollout.execution = execution
    }
  }

  /**
   * Set verification results on rollout
   */
  export function setVerification(
    rolloutId: string,
    verification: GateResults
  ): void {
    const rollout = activeRollouts.get(rolloutId)
    if (rollout) {
      rollout.verification = verification
    }
  }

  /**
   * Complete and save rollout
   */
  export async function completeRollout(rolloutId: string): Promise<string> {
    const rollout = activeRollouts.get(rolloutId)
    if (!rollout) {
      throw new Error(`Rollout not found: ${rolloutId}`)
    }

    rollout.completedAt = Date.now()
    activeRollouts.delete(rolloutId)

    const cfg = getConfig()
    if (!cfg.enabled) {
      return ""
    }

    // Write rollout to file
    const filePath = await write(rollout)
    return filePath
  }

  /**
   * Write rollout to .clawdstrike/runs/
   */
  async function write(rollout: Rollout): Promise<string> {
    const cfg = getConfig()
    const runDir = path.join(cfg.outputDir, rollout.id)
    await fs.mkdir(runDir, { recursive: true })

    const filePath = path.join(runDir, "rollout.json")
    await Bun.write(filePath, JSON.stringify(rollout, null, 2))

    return filePath
  }

  /**
   * Get rollout by ID (from active or disk)
   */
  export async function getRollout(id: string): Promise<Rollout | undefined> {
    // Check active rollouts first
    const active = activeRollouts.get(id)
    if (active) {
      return active
    }

    // Try to read from disk
    const cfg = getConfig()
    const filePath = path.join(cfg.outputDir, id, "rollout.json")

    try {
      const content = await Bun.file(filePath).text()
      return JSON.parse(content) as Rollout
    } catch {
      return undefined
    }
  }

  /**
   * List rollouts for a task
   */
  export async function listRollouts(taskId?: TaskId): Promise<Rollout[]> {
    const cfg = getConfig()
    const rollouts: Rollout[] = []

    try {
      const entries = await fs.readdir(cfg.outputDir, { withFileTypes: true })

      for (const entry of entries) {
        if (!entry.isDirectory()) continue

        const filePath = path.join(cfg.outputDir, entry.name, "rollout.json")
        try {
          const content = await Bun.file(filePath).text()
          const rollout = JSON.parse(content) as Rollout

          if (!taskId || rollout.taskId === taskId) {
            rollouts.push(rollout)
          }
        } catch {
          // Skip invalid files
        }
      }
    } catch {
      // Directory doesn't exist, return empty
    }

    // Sort by startedAt descending
    return rollouts.sort((a, b) => b.startedAt - a.startedAt)
  }

  /**
   * Export rollouts to analytics format
   */
  export function toAnalytics(rollout: Rollout): AnalyticsEvent {
    return {
      event: "clawdstrike_execution",
      timestamp: new Date(rollout.startedAt).toISOString(),
      properties: {
        rolloutId: rollout.id,
        taskId: rollout.taskId,
        toolchain: rollout.routing?.toolchain,
        strategy: rollout.routing?.strategy,
        outcome: rollout.status,
        duration: rollout.completedAt
          ? rollout.completedAt - rollout.startedAt
          : undefined,
        gateScore: rollout.verification?.score,
        gatesPassed: rollout.verification?.allPassed,
        tokensUsed: rollout.execution?.telemetry?.tokens
          ? (rollout.execution.telemetry.tokens.input ?? 0) +
            (rollout.execution.telemetry.tokens.output ?? 0)
          : undefined,
        cost: rollout.execution?.telemetry?.cost,
        model: rollout.execution?.telemetry?.model,
      },
    }
  }

  /**
   * Export multiple rollouts to analytics format
   */
  export function exportAnalytics(rollouts: Rollout[]): AnalyticsEvent[] {
    return rollouts.map(toAnalytics)
  }

  /**
   * Get active rollout IDs
   */
  export function getActive(): string[] {
    return Array.from(activeRollouts.keys())
  }

  /**
   * Check if telemetry is initialized
   */
  export function isInitialized(): boolean {
    return config !== null
  }

  /**
   * Reset telemetry state (mainly for testing)
   */
  export function reset(): void {
    config = null
    activeRollouts.clear()
  }
}

export default Telemetry
