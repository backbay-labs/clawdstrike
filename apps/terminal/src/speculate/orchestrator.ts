/**
 * Orchestrator - Parallel multi-agent execution
 *
 * Manages parallel workcell acquisition, execution, and cleanup.
 * Coordinates with Dispatcher and Verifier for the full speculation flow.
 */

import type {
  TaskInput,
  SpeculationConfig,
  SpeculationResult,
  ExecutionResult,
  GateResults,
  Toolchain,
  WorkcellId,
} from "../types"
import { Workcell } from "../workcell"
import { Dispatcher } from "../dispatcher"
import { Verifier } from "../verifier"
import { Voter, type CandidateResult } from "./voter"

/**
 * Progress callback for speculation status updates
 */
export type ProgressCallback = (
  toolchain: Toolchain,
  status: "acquiring" | "executing" | "verifying" | "completed" | "failed",
  workcellId?: WorkcellId
) => void

/**
 * Orchestrator options
 */
export interface OrchestratorOptions {
  task: TaskInput
  config: SpeculationConfig
  gates?: string[]
  onProgress?: ProgressCallback
}

/**
 * Internal execution result for each workcell
 */
interface ExecutionEntry {
  workcellId: WorkcellId
  toolchain: Toolchain
  result?: CandidateResult["result"]
  gateResults?: GateResults
  error?: string
}

/**
 * Orchestrator namespace - Parallel execution management
 */
export namespace Orchestrator {
  // Track active speculations for cancellation
  const activeSpeculations = new Map<
    string,
    { controller: AbortController; workcellIds: WorkcellId[] }
  >()

  /**
   * Run speculation across multiple toolchains in parallel
   */
  export async function run(
    options: OrchestratorOptions
  ): Promise<SpeculationResult> {
    const { task, config, gates = [], onProgress } = options
    const startedAt = Date.now()
    const taskId = task.id || crypto.randomUUID()

    // Create abort controller for timeout and cancellation
    const controller = new AbortController()
    const workcellIds: WorkcellId[] = []

    // Register for cancellation
    activeSpeculations.set(taskId, { controller, workcellIds })

    // Set up timeout
    const timeoutId = setTimeout(() => {
      controller.abort()
    }, config.timeout)

    try {
      // Phase 1: Acquire workcells in parallel
      const workcells = await Promise.all(
        config.toolchains.map(async (toolchain) => {
          onProgress?.(toolchain, "acquiring")
          try {
            const wc = await Workcell.acquire(task.context.projectId, toolchain, {
              cwd: task.context.cwd,
            })
            workcellIds.push(wc.id)
            return { toolchain, workcell: wc, error: undefined }
          } catch (err) {
            return {
              toolchain,
              workcell: undefined,
              error: err instanceof Error ? err.message : String(err),
            }
          }
        })
      )

      // Check if aborted during acquisition
      if (controller.signal.aborted) {
        return createAbortedResult(startedAt, workcells)
      }

      // Phase 2: Execute all in parallel
      const executions = await Promise.allSettled(
        workcells.map(async ({ toolchain, workcell, error }) => {
          // Skip if workcell acquisition failed
          if (!workcell || error) {
            return {
              workcellId: "" as WorkcellId,
              toolchain,
              error: error || "Failed to acquire workcell",
            } satisfies ExecutionEntry
          }

          onProgress?.(toolchain, "executing", workcell.id)

          try {
            // Execute the task
            const result = await Dispatcher.execute({
              task,
              workcell,
              toolchain,
              timeout: Math.floor(config.timeout / 2), // Half timeout for execution
            })

            // Check for abort
            if (controller.signal.aborted) {
              return {
                workcellId: workcell.id,
                toolchain,
                error: "Aborted",
              } satisfies ExecutionEntry
            }

            // Run gates if execution succeeded
            let gateResults: GateResults | undefined
            if (result.success && gates.length > 0) {
              onProgress?.(toolchain, "verifying", workcell.id)
              gateResults = await Verifier.run(workcell, {
                gates,
                failFast: true,
                timeout: Math.floor(config.timeout / 2), // Half timeout for gates
              })
            }

            onProgress?.(toolchain, "completed", workcell.id)

            return {
              workcellId: workcell.id,
              toolchain,
              result,
              gateResults,
            } satisfies ExecutionEntry
          } catch (err) {
            onProgress?.(toolchain, "failed", workcell.id)
            return {
              workcellId: workcell.id,
              toolchain,
              error: err instanceof Error ? err.message : String(err),
            } satisfies ExecutionEntry
          }
        })
      )

      clearTimeout(timeoutId)
      const completedAt = Date.now()

      // Collect results
      const allResults: CandidateResult[] = executions.map((exec, i) => {
        const toolchain = config.toolchains[i]
        const workcellId = workcells[i]?.workcell?.id || ("" as WorkcellId)

        if (exec.status === "fulfilled") {
          const entry = exec.value
          const fallbackResult: ExecutionResult = {
            taskId,
            workcellId: entry.workcellId || workcellId,
            toolchain: entry.toolchain,
            success: false,
            output: "",
            error: entry.error,
            telemetry: { startedAt, completedAt },
          }
          return {
            workcellId: entry.workcellId || workcellId,
            toolchain: entry.toolchain,
            result: entry.result || fallbackResult,
            gateResults: entry.gateResults,
            error: entry.error,
          }
        } else {
          const fallbackResult: ExecutionResult = {
            taskId,
            workcellId,
            toolchain,
            success: false,
            output: "",
            error: exec.reason?.message ?? "Unknown error",
            telemetry: { startedAt, completedAt },
          }
          return {
            workcellId,
            toolchain,
            result: fallbackResult,
            error: exec.reason?.message ?? "Unknown error",
          }
        }
      })

      // Phase 3: Vote for winner
      const passingCandidates = allResults.filter(
        (r) => r.result.success && r.gateResults?.allPassed
      )
      const winner =
        passingCandidates.length > 0
          ? Voter.select(passingCandidates, config.voteStrategy)
          : undefined

      // Phase 4: Cleanup non-winners
      for (const result of allResults) {
        if (!result.workcellId) continue

        if (result.workcellId === winner?.workcellId) {
          // Winner: keep workcell with patch intact
          // Patch will be extracted in PatchLifecycle.capture()
          continue
        }

        // Non-winners: release workcell
        try {
          await Workcell.release(result.workcellId, { reset: true })
        } catch {
          // Ignore cleanup errors
        }
      }

      // Build vote tally for telemetry
      const votes: Record<string, number> = {}
      if (passingCandidates.length > 0) {
        const tally = Voter.getVoteTally(passingCandidates, config.voteStrategy)
        for (const [wcId, { score }] of tally) {
          votes[wcId] = score
        }
      }

      return {
        winner: winner
          ? {
              workcellId: winner.workcellId,
              toolchain: winner.toolchain,
              result: winner.result,
              gateResults: winner.gateResults!,
            }
          : undefined,
        allResults: allResults.map((r) => ({
          workcellId: r.workcellId,
          toolchain: r.toolchain,
          result: r.result,
          gateResults: r.gateResults,
          error: r.error,
        })),
        votes,
        timing: {
          startedAt,
          completedAt,
        },
      }
    } finally {
      clearTimeout(timeoutId)
      activeSpeculations.delete(taskId)
    }
  }

  /**
   * Cancel an active speculation
   */
  export function cancel(taskId: string): boolean {
    const speculation = activeSpeculations.get(taskId)
    if (!speculation) return false

    speculation.controller.abort()
    return true
  }

  /**
   * Get active speculation IDs
   */
  export function getActive(): string[] {
    return Array.from(activeSpeculations.keys())
  }

  /**
   * Create result for aborted speculation
   */
  function createAbortedResult(
    startedAt: number,
    workcells: Array<{
      toolchain: Toolchain
      workcell?: { id: WorkcellId }
      error?: string
    }>
  ): SpeculationResult {
    const completedAt = Date.now()
    return {
      winner: undefined,
      allResults: workcells.map((w) => ({
        workcellId: w.workcell?.id || ("" as WorkcellId),
        toolchain: w.toolchain,
        success: false,
        gatesPassed: false,
        error: "Speculation aborted",
      })),
      timing: { startedAt, completedAt },
    }
  }
}

export default Orchestrator
