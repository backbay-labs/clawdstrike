/**
 * Voter - Voting strategies for Speculate+Vote
 *
 * Implements three strategies for selecting the best result:
 * - first_pass: First candidate that completes and passes all gates
 * - best_score: Candidate with highest gate score
 * - consensus: Candidate whose patch is most similar to others
 */

import type {
  ExecutionResult,
  GateResults,
  Toolchain,
  VoteStrategy,
  WorkcellId,
} from "../types"

/**
 * Candidate result from speculation
 */
export interface CandidateResult {
  workcellId: WorkcellId
  toolchain: Toolchain
  result: ExecutionResult
  gateResults?: GateResults
  error?: string
}

/**
 * Voter namespace - Voting strategy implementations
 */
export namespace Voter {
  /**
   * Select winner from candidates using specified strategy
   */
  export function select(
    candidates: CandidateResult[],
    strategy: VoteStrategy
  ): CandidateResult | undefined {
    // Filter to only passing candidates
    const passing = candidates.filter(
      (c) => c.result.success && c.gateResults?.allPassed
    )

    if (passing.length === 0) return undefined
    if (passing.length === 1) return passing[0]

    switch (strategy) {
      case "first_pass":
        return selectFirstPass(passing)
      case "best_score":
        return selectBestScore(passing)
      case "consensus":
        return selectConsensus(passing)
      default:
        return passing[0]
    }
  }

  /**
   * First one that passes all gates (fastest completion time)
   * Good for straightforward tasks where speed matters
   */
  export function selectFirstPass(
    candidates: CandidateResult[]
  ): CandidateResult {
    // Return the one that completed first
    return candidates.reduce((earliest, curr) => {
      const earliestTime = earliest.result.telemetry.completedAt
      const currTime = curr.result.telemetry.completedAt
      return currTime < earliestTime ? curr : earliest
    })
  }

  /**
   * Highest gate score wins
   * Best for quality-critical tasks
   */
  export function selectBestScore(
    candidates: CandidateResult[]
  ): CandidateResult {
    return candidates.reduce((best, curr) => {
      const bestScore = best.gateResults?.score ?? 0
      const currScore = curr.gateResults?.score ?? 0
      return currScore > bestScore ? curr : best
    })
  }

  /**
   * Most similar patch wins (for consistency)
   * Best for determinism-critical tasks where multiple agents
   * should converge on the same solution
   */
  export function selectConsensus(
    candidates: CandidateResult[]
  ): CandidateResult {
    // Calculate pairwise patch similarity
    const patches = candidates.map((c) => c.result.patch ?? "")
    const similarities = new Map<WorkcellId, number>()

    for (let i = 0; i < patches.length; i++) {
      let totalSimilarity = 0
      for (let j = 0; j < patches.length; j++) {
        if (i !== j) {
          totalSimilarity += calculateSimilarity(patches[i], patches[j])
        }
      }
      similarities.set(candidates[i].workcellId, totalSimilarity)
    }

    // Return candidate with highest total similarity
    return candidates.reduce((best, curr) => {
      const bestSim = similarities.get(best.workcellId) ?? 0
      const currSim = similarities.get(curr.workcellId) ?? 0
      return currSim > bestSim ? curr : best
    })
  }

  /**
   * Calculate similarity between two patches using Jaccard index
   * Returns value between 0 (completely different) and 1 (identical)
   */
  export function calculateSimilarity(a: string, b: string): number {
    if (a === b) return 1
    if (!a || !b) return 0

    const linesA = new Set(a.split("\n").filter((l) => l.trim()))
    const linesB = new Set(b.split("\n").filter((l) => l.trim()))

    if (linesA.size === 0 && linesB.size === 0) return 1
    if (linesA.size === 0 || linesB.size === 0) return 0

    const intersection = new Set([...linesA].filter((x) => linesB.has(x)))
    const union = new Set([...linesA, ...linesB])

    return intersection.size / union.size
  }

  /**
   * Get votes tally for each candidate
   * Useful for debugging and telemetry
   */
  export function getVoteTally(
    candidates: CandidateResult[],
    strategy: VoteStrategy
  ): Map<WorkcellId, { score: number; reason: string }> {
    const tally = new Map<WorkcellId, { score: number; reason: string }>()

    for (const candidate of candidates) {
      let score = 0
      let reason = ""

      if (!candidate.result.success) {
        reason = "execution failed"
      } else if (!candidate.gateResults?.allPassed) {
        reason = "gates failed"
      } else {
        switch (strategy) {
          case "first_pass":
            score = -candidate.result.telemetry.completedAt // Lower is better
            reason = `completed at ${candidate.result.telemetry.completedAt}`
            break
          case "best_score":
            score = candidate.gateResults?.score ?? 0
            reason = `gate score ${score}`
            break
          case "consensus":
            // Calculate total similarity to others
            const patches = candidates.map((c) => c.result.patch ?? "")
            const idx = candidates.indexOf(candidate)
            for (let j = 0; j < patches.length; j++) {
              if (idx !== j) {
                score += calculateSimilarity(
                  candidate.result.patch ?? "",
                  patches[j]
                )
              }
            }
            reason = `similarity score ${score.toFixed(2)}`
            break
        }
      }

      tally.set(candidate.workcellId, { score, reason })
    }

    return tally
  }
}

export default Voter
