/**
 * Type validation tests
 *
 * Verifies that Zod schemas validate correctly and type exports work.
 */

import { describe, expect, test } from "bun:test"
import {
  TaskId,
  WorkcellId,
  BeadId,
  Toolchain,
  TaskInput,
  TaskStatus,
  GateResult,
  GateResults,
  WorkcellInfo,
  WorkcellStatus,
  SpeculationConfig,
  RoutingDecision,
  Patch,
  PatchStatus,
  Bead,
  BeadStatus,
} from "../src/types"

describe("Identifiers", () => {
  test("TaskId validates UUIDs", () => {
    const valid = "123e4567-e89b-12d3-a456-426614174000"
    expect(TaskId.parse(valid)).toBe(valid)

    expect(() => TaskId.parse("not-a-uuid")).toThrow()
  })

  test("WorkcellId validates UUIDs", () => {
    const valid = "550e8400-e29b-41d4-a716-446655440000"
    expect(WorkcellId.parse(valid)).toBe(valid)
  })

  test("BeadId validates project-number format", () => {
    expect(BeadId.parse("PROJ-123")).toBe("PROJ-123")
    expect(BeadId.parse("ABC-1")).toBe("ABC-1")

    expect(() => BeadId.parse("invalid")).toThrow()
    expect(() => BeadId.parse("proj-123")).toThrow() // lowercase
    expect(() => BeadId.parse("PROJ123")).toThrow() // missing dash
  })
})

describe("Toolchain", () => {
  test("validates valid toolchains", () => {
    expect(Toolchain.parse("codex")).toBe("codex")
    expect(Toolchain.parse("claude")).toBe("claude")
    expect(Toolchain.parse("opencode")).toBe("opencode")
    expect(Toolchain.parse("crush")).toBe("crush")
  })

  test("rejects invalid toolchains", () => {
    expect(() => Toolchain.parse("invalid")).toThrow()
    expect(() => Toolchain.parse("")).toThrow()
  })
})

describe("TaskInput", () => {
  test("validates minimal task input", () => {
    const task = {
      prompt: "Fix the bug",
      context: {
        cwd: "/project",
        projectId: "my-project",
      },
    }

    const parsed = TaskInput.parse(task)
    expect(parsed.prompt).toBe("Fix the bug")
    expect(parsed.context.cwd).toBe("/project")
  })

  test("validates full task input", () => {
    const task = {
      id: "123e4567-e89b-12d3-a456-426614174000",
      prompt: "Implement feature X",
      context: {
        cwd: "/project",
        projectId: "my-project",
        branch: "feature/x",
        files: ["src/main.ts"],
        env: { NODE_ENV: "test" },
      },
      labels: ["dk_risk:high", "dk_size:m"],
      hint: "codex",
      gates: ["pytest", "mypy"],
      beadId: "PROJ-42",
      timeout: 300000,
    }

    const parsed = TaskInput.parse(task)
    expect(parsed.labels).toEqual(["dk_risk:high", "dk_size:m"])
    expect(parsed.hint).toBe("codex")
  })

  test("rejects empty prompt", () => {
    const task = {
      prompt: "",
      context: { cwd: "/", projectId: "p" },
    }
    expect(() => TaskInput.parse(task)).toThrow()
  })
})

describe("TaskStatus", () => {
  test("validates all status values", () => {
    const statuses = [
      "pending",
      "routing",
      "executing",
      "verifying",
      "completed",
      "failed",
      "cancelled",
    ] as const

    for (const status of statuses) {
      expect(TaskStatus.parse(status)).toBe(status)
    }
  })
})

describe("WorkcellInfo", () => {
  test("validates workcell info", () => {
    const info = {
      id: "550e8400-e29b-41d4-a716-446655440000",
      name: "workcell-1",
      directory: "/tmp/workcells/wc-1",
      branch: "main",
      status: "warm",
      projectId: "my-project",
      createdAt: Date.now(),
    }

    const parsed = WorkcellInfo.parse(info)
    expect(parsed.status).toBe("warm")
    expect(parsed.useCount).toBe(0) // default
  })

  test("validates all workcell statuses", () => {
    const statuses = ["creating", "warm", "in_use", "cleaning", "destroyed"] as const

    for (const status of statuses) {
      expect(WorkcellStatus.parse(status)).toBe(status)
    }
  })
})

describe("SpeculationConfig", () => {
  test("validates speculation config", () => {
    const config = {
      count: 3,
      toolchains: ["codex", "claude", "opencode"],
      voteStrategy: "first_pass",
    }

    const parsed = SpeculationConfig.parse(config)
    expect(parsed.count).toBe(3)
    expect(parsed.timeout).toBe(300000) // default
  })

  test("rejects invalid count", () => {
    const config = {
      count: 1, // min is 2
      toolchains: ["codex"],
      voteStrategy: "first_pass",
    }

    expect(() => SpeculationConfig.parse(config)).toThrow()
  })
})

describe("GateResult", () => {
  test("validates gate result", () => {
    const result = {
      gate: "pytest",
      passed: true,
      critical: true,
      output: "All tests passed",
      timing: {
        startedAt: Date.now() - 1000,
        completedAt: Date.now(),
      },
    }

    const parsed = GateResult.parse(result)
    expect(parsed.passed).toBe(true)
  })

  test("validates gate result with diagnostics", () => {
    const result = {
      gate: "mypy",
      passed: false,
      critical: false,
      output: "Found 2 errors",
      diagnostics: [
        {
          file: "src/main.py",
          line: 42,
          column: 10,
          severity: "error",
          message: "Incompatible types",
          source: "mypy",
        },
      ],
      timing: {
        startedAt: Date.now() - 1000,
        completedAt: Date.now(),
      },
    }

    const parsed = GateResult.parse(result)
    expect(parsed.diagnostics).toHaveLength(1)
    expect(parsed.diagnostics![0].severity).toBe("error")
  })
})

describe("GateResults", () => {
  test("validates combined gate results", () => {
    const results = {
      allPassed: false,
      criticalPassed: true,
      results: [
        {
          gate: "pytest",
          passed: true,
          critical: true,
          output: "OK",
          timing: { startedAt: 0, completedAt: 1 },
        },
        {
          gate: "mypy",
          passed: false,
          critical: false,
          output: "Errors",
          timing: { startedAt: 1, completedAt: 2 },
        },
      ],
      score: 80,
      summary: "1/2 gates passed",
    }

    const parsed = GateResults.parse(results)
    expect(parsed.score).toBe(80)
    expect(parsed.criticalPassed).toBe(true)
  })
})

describe("Patch", () => {
  test("validates patch", () => {
    const patch = {
      id: "123e4567-e89b-12d3-a456-426614174000",
      workcellId: "550e8400-e29b-41d4-a716-446655440000",
      taskId: "660e8400-e29b-41d4-a716-446655440000",
      diff: "--- a/file.ts\n+++ b/file.ts\n@@ -1 +1 @@\n-old\n+new",
      stats: {
        filesChanged: 1,
        insertions: 1,
        deletions: 1,
      },
      files: ["file.ts"],
      status: "captured",
      createdAt: Date.now(),
    }

    const parsed = Patch.parse(patch)
    expect(parsed.status).toBe("captured")
  })

  test("validates all patch statuses", () => {
    const statuses = [
      "captured",
      "validating",
      "validated",
      "rejected",
      "staged",
      "approved",
      "merging",
      "merged",
      "failed",
    ] as const

    for (const status of statuses) {
      expect(PatchStatus.parse(status)).toBe(status)
    }
  })
})

describe("Bead", () => {
  test("validates bead (issue)", () => {
    const bead = {
      id: "PROJ-42",
      title: "Fix authentication bug",
      description: "Users can't log in",
      status: "open",
      priority: "p1",
      labels: ["bug", "auth"],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }

    const parsed = Bead.parse(bead)
    expect(parsed.priority).toBe("p1")
  })

  test("validates all bead statuses", () => {
    const statuses = ["open", "in_progress", "blocked", "completed", "cancelled"] as const

    for (const status of statuses) {
      expect(BeadStatus.parse(status)).toBe(status)
    }
  })
})

describe("RoutingDecision", () => {
  test("validates routing decision", () => {
    const decision = {
      taskId: "123e4567-e89b-12d3-a456-426614174000",
      toolchain: "codex",
      strategy: "single",
      gates: ["pytest", "mypy", "ruff"],
    }

    const parsed = RoutingDecision.parse(decision)
    expect(parsed.retries).toBe(1) // default
    expect(parsed.priority).toBe(50) // default
  })

  test("validates speculate decision", () => {
    const decision = {
      taskId: "123e4567-e89b-12d3-a456-426614174000",
      toolchain: "codex",
      strategy: "speculate",
      speculation: {
        count: 3,
        toolchains: ["codex", "claude", "opencode"],
        voteStrategy: "first_pass",
      },
      gates: ["pytest"],
      reasoning: "High risk task requires parallel execution",
    }

    const parsed = RoutingDecision.parse(decision)
    expect(parsed.strategy).toBe("speculate")
    expect(parsed.speculation?.count).toBe(3)
  })
})
