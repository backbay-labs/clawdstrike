import { describe, expect, test } from "bun:test"
import { createManagedRun, executeManagedRun, isRunTerminal } from "../src/tui/runs"
import type { RunRecord } from "../src/tui/types"

describe("tui managed runs", () => {
  test("transitions a dispatch run through execution to review-ready", async () => {
    const run = createManagedRun({
      prompt: "Investigate the failed terminal flow",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    const updates: RunRecord[] = []

    const finalRun = await executeManagedRun(run, {
      cwd: process.cwd(),
      projectId: "default",
      executeTool: async () => ({
        success: true,
        taskId: "task-1",
        routing: { toolchain: "codex", strategy: "single", gates: ["bun test"] },
        result: {
          success: true,
          telemetry: {
            model: "gpt-5.2",
            tokens: { input: 11, output: 22 },
            cost: 0.0456,
          },
        },
        verification: {
          allPassed: true,
          score: 96,
          summary: "Checks passed",
          results: [{ gate: "bun test", passed: true }],
        },
      }),
      onUpdate: (nextRun) => updates.push(nextRun),
    })

    expect(updates.map((entry) => entry.phase)).toEqual(["routing", "executing", "verifying", "review_ready"])
    expect(finalRun.phase).toBe("review_ready")
    expect(finalRun.result?.success).toBe(true)
    expect(finalRun.verification?.score).toBe(96)
    expect(finalRun.events.at(-1)?.message).toBe("Run ready for review")
    expect(isRunTerminal(finalRun.phase)).toBe(true)
  })

  test("marks a canceled run without overriding it on late completion", async () => {
    const run = createManagedRun({
      prompt: "Cancel this run before it frames the result",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    let aborted = false

    const finalRun = await executeManagedRun(run, {
      cwd: process.cwd(),
      projectId: "default",
      executeTool: async () => {
        aborted = true
        return {
          success: true,
          taskId: "task-2",
        }
      },
      shouldAbort: () => aborted,
    })

    expect(finalRun.phase).toBe("canceled")
    expect(finalRun.events.at(-1)?.message).toContain("canceled")
  })

  test("records failures as managed run errors", async () => {
    const run = createManagedRun({
      prompt: "Force the executor to fail",
      action: "speculate",
      agentId: "codex",
      agentLabel: "Codex",
    })

    const finalRun = await executeManagedRun(run, {
      cwd: process.cwd(),
      projectId: "default",
      executeTool: async () => {
        throw new Error("tool exploded")
      },
    })

    expect(finalRun.phase).toBe("failed")
    expect(finalRun.error).toBe("tool exploded")
    expect(finalRun.result?.success).toBe(false)
    expect(finalRun.events.at(-1)?.message).toBe("Run failed: tool exploded")
  })
})
