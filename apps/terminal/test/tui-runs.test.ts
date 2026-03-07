import { describe, expect, test } from "bun:test"
import {
  canRunAttach,
  canRunExternal,
  createManagedRun,
  executeManagedRun,
  filterRuns,
  getExternalAdapterLabel,
  getRunAttachDisabledReason,
  getRunExternalDisabledReason,
  getRunExternalSurfaceSummary,
  getRunReviewRoute,
  isRunTerminal,
} from "../src/tui/runs"
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
          criticalPassed: true,
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
    expect(finalRun.completedAt).not.toBeNull()
    expect(finalRun.events.at(-1)?.message).toBe("Run ready for review")
    expect(getRunReviewRoute(finalRun)).toBe("result")
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
    expect(finalRun.completedAt).not.toBeNull()
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
    expect(finalRun.completedAt).not.toBeNull()
    expect(finalRun.events.at(-1)?.message).toBe("Run failed: tool exploded")
  })

  test("keeps non-critical verification failures reviewable", async () => {
    const run = createManagedRun({
      prompt: "Say hi",
      action: "dispatch",
      agentId: "claude",
      agentLabel: "Claude",
    })

    const finalRun = await executeManagedRun(run, {
      cwd: process.cwd(),
      projectId: "default",
      executeTool: async () => ({
        success: false,
        taskId: "task-verify",
        routing: { toolchain: "claude", strategy: "single", gates: ["ruff"] },
        result: {
          success: true,
          telemetry: {
            model: "claude-opus-4-6",
            tokens: { input: 3, output: 10 },
            cost: 0.0333,
          },
        },
        verification: {
          allPassed: false,
          criticalPassed: true,
          score: 96,
          summary: "Some gates failed (non-critical)",
          results: [{ gate: "ruff", passed: false }],
        },
      }),
    })

    expect(finalRun.phase).toBe("review_ready")
    expect(finalRun.result?.success).toBe(true)
    expect(finalRun.execution?.success).toBe(true)
    expect(finalRun.error).toBeNull()
    expect(finalRun.events.at(-1)?.message).toBe("Run ready for review")
  })

  test("filters active and review-ready runs without dropping completed backlog entries", () => {
    const active = createManagedRun({
      prompt: "Keep routing",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    active.phase = "executing"

    const reviewReady = createManagedRun({
      prompt: "Review me",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    reviewReady.phase = "review_ready"
    reviewReady.result = {
      success: true,
      taskId: "task-review",
      agent: "Codex",
      action: "dispatch",
      duration: 1234,
    }
    reviewReady.completedAt = "2026-03-06T09:00:00Z"

    const failed = createManagedRun({
      prompt: "I failed",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })
    failed.phase = "failed"
    failed.completedAt = "2026-03-06T10:00:00Z"

    const entries = [active, reviewReady, failed]
    expect(filterRuns(entries, "active").map((run) => run.id)).toEqual([active.id])
    expect(filterRuns(entries, "review_ready").map((run) => run.id)).toEqual([reviewReady.id])
    expect(filterRuns(entries, "all").map((run) => run.id)).toEqual([active.id, reviewReady.id, failed.id])
  })

  test("marks attach-mode dispatch runs as attachable and leaves managed runs detached", () => {
    const attachRun = createManagedRun({
      prompt: "Open an interactive coding session",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
      mode: "attach",
    })
    const managedRun = createManagedRun({
      prompt: "Stay managed",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })

    expect(attachRun.canAttach).toBe(true)
    expect(canRunAttach(attachRun)).toBe(true)
    expect(managedRun.canAttach).toBe(false)
    expect(getRunAttachDisabledReason(managedRun)).toBe("Attach is only available for runs launched in attach mode.")
  })

  test("marks external-mode dispatch runs as eligible for adapter launch", () => {
    const externalRun = createManagedRun({
      prompt: "Open an external coding session",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
      mode: "external",
    })
    const managedRun = createManagedRun({
      prompt: "Stay local",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
    })

    expect(canRunExternal(externalRun)).toBe(true)
    expect(externalRun.external.status).toBe("idle")
    expect(getRunExternalDisabledReason(managedRun)).toBe("External execution is only available for runs launched in external mode.")
  })

  test("formats external adapter labels from the registry", () => {
    expect(getExternalAdapterLabel("terminal-app")).toBe("Terminal.app")
    expect(getExternalAdapterLabel("tmux-split")).toBe("tmux split")
    expect(getExternalAdapterLabel("unknown-adapter")).toBe("unknown-adapter")
    expect(getExternalAdapterLabel(null)).toBe("none")
  })

  test("summarizes running and completed external runs", () => {
    const run = createManagedRun({
      prompt: "Check reopen copy",
      action: "dispatch",
      agentId: "codex",
      agentLabel: "Codex",
      mode: "external",
    })

    run.external = {
      kind: "terminal-app",
      adapterId: "terminal-app",
      ref: "terminal-app",
      status: "running",
      error: null,
    }
    expect(getRunExternalSurfaceSummary(run)).toBe("Terminal.app live")

    run.external.status = "idle"
    run.phase = "completed"
    expect(getRunExternalSurfaceSummary(run)).toBe("Terminal.app completed")
  })
})
