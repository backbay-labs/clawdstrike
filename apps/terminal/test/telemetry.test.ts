/**
 * Telemetry tests
 *
 * Tests for the Telemetry execution tracking system.
 */

import { describe, expect, test, beforeEach, afterEach } from "bun:test"
import * as fs from "node:fs/promises"
import * as path from "node:path"
import * as os from "node:os"
import { Telemetry } from "../src/telemetry"
import type { TaskId, RoutingDecision, ExecutionResult, GateResults } from "../src/types"

// Create temp directory for tests
let tempDir: string

beforeEach(async () => {
  tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "clawdstrike-telemetry-test-"))
  Telemetry.reset()
  Telemetry.init({ outputDir: tempDir, enabled: true })
})

afterEach(async () => {
  Telemetry.reset()
  await fs.rm(tempDir, { recursive: true, force: true })
})

// Helper to create mock task ID
function makeTaskId(): TaskId {
  return crypto.randomUUID() as TaskId
}

// Helper to create mock routing decision
function makeRoutingDecision(taskId: TaskId): RoutingDecision {
  return {
    taskId,
    toolchain: "claude",
    strategy: "single",
    gates: ["pytest", "mypy"],
    retries: 2,
    priority: 50,
  }
}

// Helper to create mock execution result
function makeExecutionResult(taskId: TaskId): ExecutionResult {
  return {
    taskId,
    workcellId: crypto.randomUUID(),
    toolchain: "claude",
    success: true,
    output: "Task completed successfully",
    telemetry: {
      startedAt: Date.now() - 1000,
      completedAt: Date.now(),
      model: "claude-3-opus",
      tokens: { input: 100, output: 50 },
      cost: 0.01,
    },
  }
}

// Helper to create mock gate results
function makeGateResults(): GateResults {
  return {
    allPassed: true,
    criticalPassed: true,
    results: [],
    score: 100,
    summary: "All gates passed",
  }
}

describe("Telemetry", () => {
  describe("init", () => {
    test("initializes telemetry", () => {
      expect(Telemetry.isInitialized()).toBe(true)
    })
  })

  describe("startRollout", () => {
    test("creates new rollout", () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)

      expect(rollout.id).toBeDefined()
      expect(rollout.taskId).toBe(taskId)
      expect(rollout.status).toBe("pending")
      expect(rollout.events).toEqual([])
    })

    test("tracks active rollout", () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)

      expect(Telemetry.getActive()).toContain(rollout.id)
    })
  })

  describe("recordEvent", () => {
    test("adds event to rollout", () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)

      Telemetry.recordEvent(rollout.id, {
        type: "routing_started",
        taskId,
      })

      expect(rollout.events).toHaveLength(1)
      expect(rollout.events[0].type).toBe("routing_started")
      expect(rollout.events[0].timestamp).toBeDefined()
    })

    test("silently ignores unknown rollout", () => {
      // Should not throw
      Telemetry.recordEvent("unknown-id", { type: "test" })
    })
  })

  describe("updateStatus", () => {
    test("updates rollout status", () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)

      Telemetry.updateStatus(rollout.id, "executing")

      expect(rollout.status).toBe("executing")
    })
  })

  describe("setRouting", () => {
    test("sets routing decision", () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)
      const routing = makeRoutingDecision(taskId)

      Telemetry.setRouting(rollout.id, routing)

      expect(rollout.routing).toBe(routing)
    })
  })

  describe("setExecution", () => {
    test("sets execution result", () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)
      const execution = makeExecutionResult(taskId)

      Telemetry.setExecution(rollout.id, execution)

      expect(rollout.execution).toBe(execution)
    })
  })

  describe("setVerification", () => {
    test("sets verification results", () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)
      const verification = makeGateResults()

      Telemetry.setVerification(rollout.id, verification)

      expect(rollout.verification).toBe(verification)
    })
  })

  describe("completeRollout", () => {
    test("completes and saves rollout", async () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)

      const filePath = await Telemetry.completeRollout(rollout.id)

      expect(filePath).toContain(rollout.id)
      expect(Telemetry.getActive()).not.toContain(rollout.id)

      // Verify file exists
      const exists = await Bun.file(filePath).exists()
      expect(exists).toBe(true)
    })

    test("throws for unknown rollout", async () => {
      expect(Telemetry.completeRollout("unknown-id")).rejects.toThrow(
        "Rollout not found"
      )
    })

    test("sets completedAt", async () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)

      await Telemetry.completeRollout(rollout.id)

      // Read from disk
      const saved = await Telemetry.getRollout(rollout.id)
      expect(saved?.completedAt).toBeDefined()
    })
  })

  describe("getRollout", () => {
    test("returns active rollout", async () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)

      const found = await Telemetry.getRollout(rollout.id)
      expect(found?.id).toBe(rollout.id)
    })

    test("returns saved rollout", async () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)
      Telemetry.setRouting(rollout.id, makeRoutingDecision(taskId))

      await Telemetry.completeRollout(rollout.id)

      const found = await Telemetry.getRollout(rollout.id)
      expect(found?.id).toBe(rollout.id)
      expect(found?.routing).toBeDefined()
    })

    test("returns undefined for unknown rollout", async () => {
      const found = await Telemetry.getRollout("unknown-id")
      expect(found).toBeUndefined()
    })
  })

  describe("listRollouts", () => {
    test("returns empty for no rollouts", async () => {
      const rollouts = await Telemetry.listRollouts()
      expect(rollouts).toEqual([])
    })

    test("returns all saved rollouts", async () => {
      const taskId1 = makeTaskId()
      const taskId2 = makeTaskId()

      const r1 = Telemetry.startRollout(taskId1)
      await Telemetry.completeRollout(r1.id)

      const r2 = Telemetry.startRollout(taskId2)
      await Telemetry.completeRollout(r2.id)

      const rollouts = await Telemetry.listRollouts()
      expect(rollouts).toHaveLength(2)
    })

    test("filters by taskId", async () => {
      const taskId1 = makeTaskId()
      const taskId2 = makeTaskId()

      const r1 = Telemetry.startRollout(taskId1)
      await Telemetry.completeRollout(r1.id)

      const r2 = Telemetry.startRollout(taskId2)
      await Telemetry.completeRollout(r2.id)

      const filtered = await Telemetry.listRollouts(taskId1)
      expect(filtered).toHaveLength(1)
      expect(filtered[0].taskId).toBe(taskId1)
    })

    test("sorts by startedAt descending", async () => {
      const taskId = makeTaskId()

      const r1 = Telemetry.startRollout(taskId)
      await Telemetry.completeRollout(r1.id)

      // Small delay to ensure different timestamps
      await new Promise((r) => setTimeout(r, 10))

      const r2 = Telemetry.startRollout(taskId)
      await Telemetry.completeRollout(r2.id)

      const rollouts = await Telemetry.listRollouts()
      expect(rollouts[0].id).toBe(r2.id) // Most recent first
    })
  })

  describe("toAnalytics", () => {
    test("converts rollout to analytics event", () => {
      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)

      Telemetry.setRouting(rollout.id, makeRoutingDecision(taskId))
      Telemetry.setExecution(rollout.id, makeExecutionResult(taskId))
      Telemetry.setVerification(rollout.id, makeGateResults())
      Telemetry.updateStatus(rollout.id, "completed")
      rollout.completedAt = Date.now()

      const event = Telemetry.toAnalytics(rollout)

      expect(event.event).toBe("clawdstrike_execution")
      expect(event.properties.taskId).toBe(taskId)
      expect(event.properties.toolchain).toBe("claude")
      expect(event.properties.strategy).toBe("single")
      expect(event.properties.outcome).toBe("completed")
      expect(event.properties.gateScore).toBe(100)
      expect(event.properties.tokensUsed).toBe(150)
      expect(event.properties.cost).toBe(0.01)
    })
  })

  describe("exportAnalytics", () => {
    test("converts multiple rollouts", () => {
      const taskId1 = makeTaskId()
      const taskId2 = makeTaskId()

      const r1 = Telemetry.startRollout(taskId1)
      const r2 = Telemetry.startRollout(taskId2)

      const events = Telemetry.exportAnalytics([r1, r2])

      expect(events).toHaveLength(2)
      expect(events[0].properties.taskId).toBe(taskId1)
      expect(events[1].properties.taskId).toBe(taskId2)
    })
  })

  describe("disabled telemetry", () => {
    test("returns empty path when disabled", async () => {
      Telemetry.reset()
      Telemetry.init({ outputDir: tempDir, enabled: false })

      const taskId = makeTaskId()
      const rollout = Telemetry.startRollout(taskId)
      const filePath = await Telemetry.completeRollout(rollout.id)

      expect(filePath).toBe("")
    })
  })
})
