/**
 * TUI tests
 *
 * Tests for the Terminal User Interface formatting.
 */

import { describe, expect, test, beforeEach } from "bun:test"
import { TUI } from "../src/tui"
import type { GateResult, GateResults, ExecutionResult, RoutingDecision } from "../src/types"

describe("TUI", () => {
  beforeEach(() => {
    TUI.setColors(false) // Disable colors for testing
  })

  describe("formatStatus", () => {
    test("formats pending status", () => {
      expect(TUI.formatStatus("pending")).toContain("pending")
    })

    test("formats completed status", () => {
      expect(TUI.formatStatus("completed")).toContain("completed")
      expect(TUI.formatStatus("completed")).toContain("✓")
    })

    test("formats failed status", () => {
      expect(TUI.formatStatus("failed")).toContain("failed")
      expect(TUI.formatStatus("failed")).toContain("✗")
    })

    test("formats all statuses", () => {
      const statuses = ["pending", "routing", "executing", "verifying", "completed", "failed", "cancelled"] as const
      for (const status of statuses) {
        expect(TUI.formatStatus(status)).toContain(status)
      }
    })
  })

  describe("formatToolchain", () => {
    test("formats codex", () => {
      expect(TUI.formatToolchain("codex")).toBe("codex")
    })

    test("formats claude", () => {
      expect(TUI.formatToolchain("claude")).toBe("claude")
    })

    test("formats opencode", () => {
      expect(TUI.formatToolchain("opencode")).toBe("opencode")
    })

    test("formats crush", () => {
      expect(TUI.formatToolchain("crush")).toBe("crush")
    })
  })

  describe("formatGateResult", () => {
    test("formats passed gate", () => {
      const result: GateResult = {
        gate: "pytest",
        passed: true,
        critical: true,
        output: "",
        timing: { startedAt: 0, completedAt: 100 },
      }

      const formatted = TUI.formatGateResult(result)
      expect(formatted).toContain("✓")
      expect(formatted).toContain("pytest")
      expect(formatted).toContain("100ms")
    })

    test("formats failed gate", () => {
      const result: GateResult = {
        gate: "mypy",
        passed: false,
        critical: true,
        output: "",
        timing: { startedAt: 0, completedAt: 500 },
      }

      const formatted = TUI.formatGateResult(result)
      expect(formatted).toContain("✗")
      expect(formatted).toContain("mypy")
    })

    test("includes error count", () => {
      const result: GateResult = {
        gate: "ruff",
        passed: false,
        critical: false,
        output: "",
        diagnostics: [
          { severity: "error", message: "Error 1" },
          { severity: "error", message: "Error 2" },
          { severity: "warning", message: "Warning 1" },
        ],
        timing: { startedAt: 0, completedAt: 200 },
      }

      const formatted = TUI.formatGateResult(result)
      expect(formatted).toContain("2 errors")
      expect(formatted).toContain("1 warning")
    })
  })

  describe("formatGateResults", () => {
    test("formats passing results", () => {
      const results: GateResults = {
        allPassed: true,
        criticalPassed: true,
        results: [
          { gate: "pytest", passed: true, critical: true, output: "", timing: { startedAt: 0, completedAt: 100 } },
          { gate: "mypy", passed: true, critical: true, output: "", timing: { startedAt: 0, completedAt: 200 } },
        ],
        score: 100,
        summary: "All gates passed",
      }

      const formatted = TUI.formatGateResults(results)
      expect(formatted).toContain("Gates:")
      expect(formatted).toContain("100/100")
      expect(formatted).toContain("pytest")
      expect(formatted).toContain("mypy")
    })

    test("formats failing results", () => {
      const results: GateResults = {
        allPassed: false,
        criticalPassed: false,
        results: [
          { gate: "pytest", passed: false, critical: true, output: "", timing: { startedAt: 0, completedAt: 100 } },
        ],
        score: 0,
        summary: "Critical gate failed: pytest",
      }

      const formatted = TUI.formatGateResults(results)
      expect(formatted).toContain("0/100")
    })
  })

  describe("formatExecutionResult", () => {
    test("formats successful execution", () => {
      const result: ExecutionResult = {
        taskId: "task-123",
        workcellId: "wc-456",
        toolchain: "claude",
        success: true,
        output: "Done",
        telemetry: {
          startedAt: 0,
          completedAt: 5000,
          model: "claude-3-opus",
          tokens: { input: 100, output: 50 },
          cost: 0.01,
        },
      }

      const formatted = TUI.formatExecutionResult(result)
      expect(formatted).toContain("✓")
      expect(formatted).toContain("claude")
      expect(formatted).toContain("claude-3-opus")
      expect(formatted).toContain("100 in / 50 out")
      expect(formatted).toContain("$0.01")
    })

    test("formats failed execution", () => {
      const result: ExecutionResult = {
        taskId: "task-123",
        workcellId: "wc-456",
        toolchain: "codex",
        success: false,
        output: "",
        error: "Timeout exceeded",
        telemetry: {
          startedAt: 0,
          completedAt: 60000,
        },
      }

      const formatted = TUI.formatExecutionResult(result)
      expect(formatted).toContain("✗")
      expect(formatted).toContain("Timeout exceeded")
    })
  })

  describe("formatRouting", () => {
    test("formats single strategy", () => {
      const decision: RoutingDecision = {
        taskId: "task-123",
        toolchain: "claude",
        strategy: "single",
        gates: ["pytest", "mypy"],
        retries: 2,
        priority: 50,
      }

      const formatted = TUI.formatRouting(decision)
      expect(formatted).toContain("claude")
      expect(formatted).toContain("single")
      expect(formatted).toContain("pytest, mypy")
    })

    test("formats speculate strategy", () => {
      const decision: RoutingDecision = {
        taskId: "task-123",
        toolchain: "codex",
        strategy: "speculate",
        gates: ["pytest"],
        retries: 1,
        priority: 100,
        speculation: {
          count: 3,
          toolchains: ["codex", "claude", "opencode"],
          voteStrategy: "first_pass",
          timeout: 300000,
        },
      }

      const formatted = TUI.formatRouting(decision)
      expect(formatted).toContain("speculate")
      expect(formatted).toContain("codex")
      expect(formatted).toContain("claude")
      expect(formatted).toContain("first_pass")
    })
  })

  describe("formatDuration", () => {
    test("formats milliseconds", () => {
      expect(TUI.formatDuration(500)).toBe("500ms")
    })

    test("formats seconds", () => {
      expect(TUI.formatDuration(5000)).toBe("5.0s")
    })

    test("formats minutes", () => {
      expect(TUI.formatDuration(125000)).toBe("2m 5s")
    })
  })

  describe("message helpers", () => {
    test("success includes checkmark", () => {
      expect(TUI.success("Done")).toContain("✓")
      expect(TUI.success("Done")).toContain("Done")
    })

    test("error includes cross", () => {
      expect(TUI.error("Failed")).toContain("✗")
      expect(TUI.error("Failed")).toContain("Failed")
    })

    test("warning includes warning icon", () => {
      expect(TUI.warning("Caution")).toContain("⚠")
    })

    test("info includes info icon", () => {
      expect(TUI.info("Note")).toContain("ℹ")
    })
  })

  describe("formatTable", () => {
    test("formats key-value pairs", () => {
      const rows: Array<[string, string]> = [
        ["Name", "Test"],
        ["Status", "Active"],
      ]

      const formatted = TUI.formatTable(rows)
      expect(formatted).toContain("Name")
      expect(formatted).toContain("Test")
      expect(formatted).toContain("Status")
      expect(formatted).toContain("Active")
    })

    test("supports indent", () => {
      const rows: Array<[string, string]> = [["Key", "Value"]]
      const formatted = TUI.formatTable(rows, { indent: 2 })
      expect(formatted.startsWith("  ")).toBe(true)
    })
  })

  describe("colors", () => {
    test("can enable colors", () => {
      TUI.setColors(true)
      expect(TUI.colorsEnabled()).toBe(true)
    })

    test("can disable colors", () => {
      TUI.setColors(false)
      expect(TUI.colorsEnabled()).toBe(false)
    })
  })
})
