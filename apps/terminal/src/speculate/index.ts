/**
 * Speculate - Parallel multi-agent execution (Speculate+Vote)
 *
 * Runs multiple agents in parallel and selects the best result.
 * Implements voting strategies: first_pass, best_score, consensus.
 */

import type {
  TaskInput,
  SpeculationConfig,
  SpeculationResult,
  ExecutionResult,
  GateResults,
  Toolchain,
  VoteStrategy,
  WorkcellId,
} from "../types"
import { Orchestrator, type ProgressCallback } from "./orchestrator"
import { Voter, type CandidateResult } from "./voter"

// Re-export submodules
export { Orchestrator } from "./orchestrator"
export { Voter, type CandidateResult } from "./voter"

export interface SpeculateOptions {
  task: TaskInput
  config: SpeculationConfig
  gates?: string[]
  onProgress?: ProgressCallback
}

export interface VoteInput {
  workcellId: WorkcellId
  toolchain: Toolchain
  result: ExecutionResult
  gateResults: GateResults
}

/**
 * Speculate namespace - Parallel execution operations
 */
export namespace Speculate {
  /**
   * Run speculation with multiple toolchains
   *
   * Acquires workcells in parallel, executes tasks, runs gates,
   * votes for winner, and cleans up non-winners.
   */
  export async function run(
    options: SpeculateOptions
  ): Promise<SpeculationResult> {
    return Orchestrator.run({
      task: options.task,
      config: options.config,
      gates: options.gates,
      onProgress: options.onProgress,
    })
  }

  /**
   * Vote on results using specified strategy
   */
  export function vote(
    results: VoteInput[],
    strategy: VoteStrategy
  ): VoteInput | undefined {
    // Convert VoteInput to CandidateResult for Voter
    const candidates: CandidateResult[] = results.map((r) => ({
      workcellId: r.workcellId,
      toolchain: r.toolchain,
      result: r.result,
      gateResults: r.gateResults,
    }))

    const winner = Voter.select(candidates, strategy)
    if (!winner) return undefined

    // Convert back to VoteInput
    return results.find((r) => r.workcellId === winner.workcellId)
  }

  /**
   * First-pass voting: first passing result wins
   */
  export function voteFirstPass(results: VoteInput[]): VoteInput | undefined {
    const passing = results.filter((r) => r.gateResults.allPassed)
    if (passing.length === 0) return undefined

    // Convert to CandidateResult
    const candidates: CandidateResult[] = passing.map((r) => ({
      workcellId: r.workcellId,
      toolchain: r.toolchain,
      result: r.result,
      gateResults: r.gateResults,
    }))

    const winner = Voter.selectFirstPass(candidates)
    return results.find((r) => r.workcellId === winner.workcellId)
  }

  /**
   * Best-score voting: highest gate score wins
   */
  export function voteBestScore(results: VoteInput[]): VoteInput | undefined {
    const passing = results.filter((r) => r.gateResults.allPassed)
    if (passing.length === 0) return undefined

    // Convert to CandidateResult
    const candidates: CandidateResult[] = passing.map((r) => ({
      workcellId: r.workcellId,
      toolchain: r.toolchain,
      result: r.result,
      gateResults: r.gateResults,
    }))

    const winner = Voter.selectBestScore(candidates)
    return results.find((r) => r.workcellId === winner.workcellId)
  }

  /**
   * Consensus voting: most similar patch wins
   */
  export function voteConsensus(results: VoteInput[]): VoteInput | undefined {
    const passing = results.filter((r) => r.gateResults.allPassed)
    if (passing.length === 0) return undefined

    // Convert to CandidateResult
    const candidates: CandidateResult[] = passing.map((r) => ({
      workcellId: r.workcellId,
      toolchain: r.toolchain,
      result: r.result,
      gateResults: r.gateResults,
    }))

    const winner = Voter.selectConsensus(candidates)
    return results.find((r) => r.workcellId === winner.workcellId)
  }

  /**
   * Cancel a running speculation by task ID
   */
  export function cancel(taskId: string): boolean {
    return Orchestrator.cancel(taskId)
  }

  /**
   * Get list of active speculation task IDs
   */
  export function getActive(): string[] {
    return Orchestrator.getActive()
  }

  /**
   * Calculate patch similarity between two patches
   * Useful for consensus voting debugging
   */
  export function calculateSimilarity(a: string, b: string): number {
    return Voter.calculateSimilarity(a, b)
  }
}

export default Speculate
