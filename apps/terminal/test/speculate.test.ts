/**
 * Speculate tests
 *
 * Tests for the Speculate+Vote module including voting strategies
 * and orchestrator functionality.
 */

import { describe, expect, test } from "bun:test"
import { Speculate, Voter } from "../src/speculate"
import type { CandidateResult } from "../src/speculate/voter"
import type { ExecutionResult, GateResults, WorkcellId } from "../src/types"

// Helper to create mock execution result
function makeExecutionResult(
  overrides: Partial<ExecutionResult> = {}
): ExecutionResult {
  return {
    taskId: crypto.randomUUID(),
    workcellId: crypto.randomUUID() as WorkcellId,
    toolchain: "claude",
    success: true,
    output: "success",
    telemetry: {
      startedAt: Date.now() - 1000,
      completedAt: Date.now(),
    },
    ...overrides,
  }
}

// Helper to create mock gate results
function makeGateResults(
  overrides: Partial<GateResults> = {}
): GateResults {
  return {
    allPassed: true,
    criticalPassed: true,
    results: [],
    score: 100,
    summary: "All gates passed",
    ...overrides,
  }
}

// Helper to create mock candidate
function makeCandidate(
  overrides: Partial<{
    workcellId: string
    toolchain: string
    success: boolean
    allPassed: boolean
    score: number
    completedAt: number
    patch: string
  }> = {}
): CandidateResult {
  const workcellId = (overrides.workcellId || crypto.randomUUID()) as WorkcellId
  return {
    workcellId,
    toolchain: (overrides.toolchain || "claude") as CandidateResult["toolchain"],
    result: makeExecutionResult({
      workcellId,
      toolchain: (overrides.toolchain || "claude") as CandidateResult["toolchain"],
      success: overrides.success ?? true,
      patch: overrides.patch,
      telemetry: {
        startedAt: Date.now() - 1000,
        completedAt: overrides.completedAt ?? Date.now(),
      },
    }),
    gateResults: makeGateResults({
      allPassed: overrides.allPassed ?? true,
      score: overrides.score ?? 100,
    }),
  }
}

describe("Voter", () => {
  describe("select", () => {
    test("returns undefined for empty candidates", () => {
      expect(Voter.select([], "first_pass")).toBeUndefined()
    })

    test("returns single candidate", () => {
      const candidate = makeCandidate()
      const result = Voter.select([candidate], "first_pass")
      expect(result).toBe(candidate)
    })

    test("filters out failed executions", () => {
      const failed = makeCandidate({ success: false })
      const passed = makeCandidate({ success: true })

      const result = Voter.select([failed, passed], "first_pass")
      expect(result?.workcellId).toBe(passed.workcellId)
    })

    test("filters out failed gates", () => {
      const failedGates = makeCandidate({ allPassed: false })
      const passedGates = makeCandidate({ allPassed: true })

      const result = Voter.select([failedGates, passedGates], "first_pass")
      expect(result?.workcellId).toBe(passedGates.workcellId)
    })

    test("returns undefined when all fail", () => {
      const failed1 = makeCandidate({ success: false })
      const failed2 = makeCandidate({ allPassed: false })

      expect(Voter.select([failed1, failed2], "first_pass")).toBeUndefined()
    })
  })

  describe("selectFirstPass", () => {
    test("selects earliest completed candidate", () => {
      const early = makeCandidate({ completedAt: 1000 })
      const late = makeCandidate({ completedAt: 2000 })

      const result = Voter.selectFirstPass([late, early])
      expect(result.workcellId).toBe(early.workcellId)
    })
  })

  describe("selectBestScore", () => {
    test("selects highest scoring candidate", () => {
      const lowScore = makeCandidate({ score: 80 })
      const highScore = makeCandidate({ score: 100 })
      const midScore = makeCandidate({ score: 90 })

      const result = Voter.selectBestScore([lowScore, highScore, midScore])
      expect(result.workcellId).toBe(highScore.workcellId)
    })
  })

  describe("selectConsensus", () => {
    test("selects candidate with most similar patches", () => {
      const patchA = "line 1\nline 2\nline 3"
      const patchB = "line 1\nline 2\nline 3" // Same as A
      const patchC = "completely different\ncontent"

      const candidateA = makeCandidate({ patch: patchA })
      const candidateB = makeCandidate({ patch: patchB })
      const candidateC = makeCandidate({ patch: patchC })

      const result = Voter.selectConsensus([candidateA, candidateB, candidateC])
      // A and B are identical, so they should have higher similarity
      expect([candidateA.workcellId, candidateB.workcellId]).toContain(
        result.workcellId
      )
    })
  })

  describe("calculateSimilarity", () => {
    test("returns 1 for identical strings", () => {
      expect(Voter.calculateSimilarity("abc", "abc")).toBe(1)
    })

    test("returns 0 for completely different strings", () => {
      expect(Voter.calculateSimilarity("abc", "xyz")).toBe(0)
    })

    test("returns 0 for empty strings", () => {
      expect(Voter.calculateSimilarity("", "abc")).toBe(0)
      expect(Voter.calculateSimilarity("abc", "")).toBe(0)
    })

    test("returns 1 for both empty", () => {
      expect(Voter.calculateSimilarity("", "")).toBe(1)
    })

    test("calculates partial similarity", () => {
      const a = "line1\nline2\nline3"
      const b = "line1\nline2\ndifferent"
      const sim = Voter.calculateSimilarity(a, b)
      // 2 common lines out of 4 unique = 0.5
      expect(sim).toBeCloseTo(0.5, 1)
    })
  })

  describe("getVoteTally", () => {
    test("returns scores for each candidate", () => {
      const candidates = [
        makeCandidate({ score: 100 }),
        makeCandidate({ score: 80 }),
      ]

      const tally = Voter.getVoteTally(candidates, "best_score")

      expect(tally.size).toBe(2)
      for (const candidate of candidates) {
        expect(tally.has(candidate.workcellId)).toBe(true)
      }
    })

    test("marks failed candidates", () => {
      const failed = makeCandidate({ success: false })
      const tally = Voter.getVoteTally([failed], "first_pass")

      expect(tally.get(failed.workcellId)?.reason).toBe("execution failed")
    })
  })
})

describe("Speculate namespace", () => {
  describe("vote", () => {
    test("votes using specified strategy", () => {
      const candidates = [
        {
          workcellId: "wc1" as WorkcellId,
          toolchain: "claude" as const,
          result: makeExecutionResult({ success: true }),
          gateResults: makeGateResults({ allPassed: true, score: 80 }),
        },
        {
          workcellId: "wc2" as WorkcellId,
          toolchain: "codex" as const,
          result: makeExecutionResult({ success: true }),
          gateResults: makeGateResults({ allPassed: true, score: 100 }),
        },
      ]

      const winner = Speculate.vote(candidates, "best_score")
      expect(winner?.workcellId).toBe("wc2")
    })

    test("returns undefined for no passing candidates", () => {
      const candidates = [
        {
          workcellId: "wc1" as WorkcellId,
          toolchain: "claude" as const,
          result: makeExecutionResult({ success: false }),
          gateResults: makeGateResults({ allPassed: false }),
        },
      ]

      expect(Speculate.vote(candidates, "first_pass")).toBeUndefined()
    })
  })

  describe("voteFirstPass", () => {
    test("returns first passing candidate", () => {
      const candidates = [
        {
          workcellId: "wc1" as WorkcellId,
          toolchain: "claude" as const,
          result: makeExecutionResult({
            success: true,
            telemetry: { startedAt: 0, completedAt: 1000 },
          }),
          gateResults: makeGateResults({ allPassed: true }),
        },
        {
          workcellId: "wc2" as WorkcellId,
          toolchain: "codex" as const,
          result: makeExecutionResult({
            success: true,
            telemetry: { startedAt: 0, completedAt: 500 },
          }),
          gateResults: makeGateResults({ allPassed: true }),
        },
      ]

      const winner = Speculate.voteFirstPass(candidates)
      expect(winner?.workcellId).toBe("wc2") // Earlier completion
    })
  })

  describe("voteBestScore", () => {
    test("returns highest scoring candidate", () => {
      const candidates = [
        {
          workcellId: "wc1" as WorkcellId,
          toolchain: "claude" as const,
          result: makeExecutionResult({ success: true }),
          gateResults: makeGateResults({ allPassed: true, score: 90 }),
        },
        {
          workcellId: "wc2" as WorkcellId,
          toolchain: "codex" as const,
          result: makeExecutionResult({ success: true }),
          gateResults: makeGateResults({ allPassed: true, score: 100 }),
        },
      ]

      const winner = Speculate.voteBestScore(candidates)
      expect(winner?.workcellId).toBe("wc2")
    })
  })

  describe("voteConsensus", () => {
    test("returns most similar candidate", () => {
      const samePatch = "same content"
      const candidates = [
        {
          workcellId: "wc1" as WorkcellId,
          toolchain: "claude" as const,
          result: makeExecutionResult({ success: true, patch: samePatch }),
          gateResults: makeGateResults({ allPassed: true }),
        },
        {
          workcellId: "wc2" as WorkcellId,
          toolchain: "codex" as const,
          result: makeExecutionResult({ success: true, patch: samePatch }),
          gateResults: makeGateResults({ allPassed: true }),
        },
        {
          workcellId: "wc3" as WorkcellId,
          toolchain: "opencode" as const,
          result: makeExecutionResult({ success: true, patch: "different" }),
          gateResults: makeGateResults({ allPassed: true }),
        },
      ]

      const winner = Speculate.voteConsensus(candidates)
      // wc1 and wc2 have the same patch, so one of them should win
      expect(winner).toBeDefined()
      expect(["wc1", "wc2"]).toContain(winner!.workcellId)
    })
  })

  describe("calculateSimilarity", () => {
    test("calculates similarity correctly", () => {
      expect(Speculate.calculateSimilarity("a\nb", "a\nb")).toBe(1)
      expect(Speculate.calculateSimilarity("a", "b")).toBe(0)
    })
  })

  describe("cancel", () => {
    test("returns false for non-existent task", () => {
      expect(Speculate.cancel("non-existent")).toBe(false)
    })
  })

  describe("getActive", () => {
    test("returns empty array when no active speculations", () => {
      expect(Speculate.getActive()).toEqual([])
    })
  })
})
