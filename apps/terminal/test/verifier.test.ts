/**
 * Verifier and Gates tests
 *
 * Tests for the Verifier namespace and individual gate implementations.
 */

import { describe, expect, test } from "bun:test"
import { Verifier } from "../src/verifier"
import { parseDiagnostics as parsePytestDiagnostics } from "../src/verifier/gates/pytest"
import { parseDiagnostics as parseMypyDiagnostics } from "../src/verifier/gates/mypy"
import { parseDiagnostics as parseRuffDiagnostics } from "../src/verifier/gates/ruff"
import type { GateResult, WorkcellInfo } from "../src/types"

// Helper to create minimal workcell info
function makeWorkcell(overrides: Partial<WorkcellInfo> = {}): WorkcellInfo {
  return {
    id: crypto.randomUUID(),
    name: "test-workcell",
    directory: "/tmp/test-workcell",
    branch: "test-branch",
    status: "warm",
    projectId: "test-project",
    createdAt: Date.now(),
    useCount: 0,
    ...overrides,
  }
}

describe("Gate Diagnostic Parsers", () => {
  describe("pytest parseDiagnostics", () => {
    test("parses FAILED lines", () => {
      const output = `FAILED tests/test_foo.py::test_bar - AssertionError
FAILED tests/test_baz.py::test_qux - ValueError: invalid`

      const diagnostics = parsePytestDiagnostics(output)

      expect(diagnostics).toHaveLength(2)
      expect(diagnostics[0].file).toBe("tests/test_foo.py")
      expect(diagnostics[0].severity).toBe("error")
      expect(diagnostics[0].message).toBe("AssertionError")
      expect(diagnostics[0].source).toBe("pytest")

      expect(diagnostics[1].file).toBe("tests/test_baz.py")
      expect(diagnostics[1].message).toBe("ValueError: invalid")
    })

    test("parses ERROR lines", () => {
      const output = `ERROR tests/test_foo.py::test_bar - ModuleNotFoundError
ERROR tests/conftest.py - SyntaxError`

      const diagnostics = parsePytestDiagnostics(output)

      expect(diagnostics).toHaveLength(2)
      expect(diagnostics[0].file).toBe("tests/test_foo.py")
      expect(diagnostics[0].severity).toBe("error")
      expect(diagnostics[0].message).toBe("ModuleNotFoundError")

      expect(diagnostics[1].file).toBe("tests/conftest.py")
      expect(diagnostics[1].message).toBe("SyntaxError")
    })

    test("parses file:line: error format", () => {
      const output = `tests/test_foo.py:25: AssertionError: expected True`

      const diagnostics = parsePytestDiagnostics(output)

      expect(diagnostics).toHaveLength(1)
      expect(diagnostics[0].file).toBe("tests/test_foo.py")
      expect(diagnostics[0].line).toBe(25)
      expect(diagnostics[0].severity).toBe("error")
    })

    test("returns empty array for clean output", () => {
      const output = `
============================= test session starts ==============================
collected 5 items
tests/test_foo.py .....
============================== 5 passed in 0.05s ===============================`

      const diagnostics = parsePytestDiagnostics(output)
      expect(diagnostics).toHaveLength(0)
    })
  })

  describe("mypy parseDiagnostics", () => {
    test("parses error with column", () => {
      const output = `src/foo.py:10:5: error: Incompatible types in assignment [assignment]
src/bar.py:20:10: error: Missing return statement [return]`

      const diagnostics = parseMypyDiagnostics(output)

      expect(diagnostics).toHaveLength(2)
      expect(diagnostics[0].file).toBe("src/foo.py")
      expect(diagnostics[0].line).toBe(10)
      expect(diagnostics[0].column).toBe(5)
      expect(diagnostics[0].severity).toBe("error")
      expect(diagnostics[0].message).toBe("Incompatible types in assignment")
      expect(diagnostics[0].code).toBe("assignment")
      expect(diagnostics[0].source).toBe("mypy")
    })

    test("parses warnings and notes", () => {
      const output = `src/foo.py:5:1: warning: Unused variable [var-annotated]
src/foo.py:10:1: note: See https://docs.python.org`

      const diagnostics = parseMypyDiagnostics(output)

      expect(diagnostics).toHaveLength(2)
      expect(diagnostics[0].severity).toBe("warning")
      expect(diagnostics[1].severity).toBe("info")
    })

    test("parses simple format without column", () => {
      const output = `src/foo.py:10: error: Something wrong [error-code]`

      const diagnostics = parseMypyDiagnostics(output)

      expect(diagnostics).toHaveLength(1)
      expect(diagnostics[0].file).toBe("src/foo.py")
      expect(diagnostics[0].line).toBe(10)
      expect(diagnostics[0].column).toBeUndefined()
    })

    test("returns empty array for success output", () => {
      const output = `Success: no issues found in 10 source files`

      const diagnostics = parseMypyDiagnostics(output)
      expect(diagnostics).toHaveLength(0)
    })
  })

  describe("ruff parseDiagnostics", () => {
    test("parses JSON format", () => {
      const output = JSON.stringify([
        {
          code: "E501",
          message: "Line too long",
          filename: "src/foo.py",
          location: { row: 10, column: 80 },
          end_location: { row: 10, column: 150 },
        },
        {
          code: "F401",
          message: "Unused import",
          filename: "src/bar.py",
          location: { row: 1, column: 1 },
          fix: { applicability: "safe", message: "Remove import", edits: [] },
        },
      ])

      const diagnostics = parseRuffDiagnostics(output)

      expect(diagnostics).toHaveLength(2)
      expect(diagnostics[0].file).toBe("src/foo.py")
      expect(diagnostics[0].line).toBe(10)
      expect(diagnostics[0].column).toBe(80)
      expect(diagnostics[0].severity).toBe("error") // no fix
      expect(diagnostics[0].message).toBe("Line too long")
      expect(diagnostics[0].code).toBe("E501")
      expect(diagnostics[0].source).toBe("ruff")

      expect(diagnostics[1].severity).toBe("warning") // has fix
    })

    test("falls back to text format on invalid JSON", () => {
      const output = `src/foo.py:10:80: E501 Line too long
src/bar.py:1:1: F401 Unused import`

      const diagnostics = parseRuffDiagnostics(output)

      expect(diagnostics).toHaveLength(2)
      expect(diagnostics[0].file).toBe("src/foo.py")
      expect(diagnostics[0].line).toBe(10)
      expect(diagnostics[0].column).toBe(80)
      expect(diagnostics[0].code).toBe("E501")
      expect(diagnostics[0].message).toBe("Line too long")
    })

    test("returns empty array for empty JSON array", () => {
      const output = "[]"
      const diagnostics = parseRuffDiagnostics(output)
      expect(diagnostics).toHaveLength(0)
    })
  })
})

describe("Verifier namespace", () => {
  describe("listGates", () => {
    test("lists all registered gates", () => {
      const gates = Verifier.listGates()

      expect(gates).toHaveLength(4)
      expect(gates.map((g) => g.id)).toContain("pytest")
      expect(gates.map((g) => g.id)).toContain("mypy")
      expect(gates.map((g) => g.id)).toContain("ruff")
      expect(gates.map((g) => g.id)).toContain("clawdstrike")
    })

    test("includes gate metadata", () => {
      const gates = Verifier.listGates()
      const pytest = gates.find((g) => g.id === "pytest")

      expect(pytest).toBeDefined()
      expect(pytest?.name).toBe("Pytest")
      expect(pytest?.description).toBeDefined()
      expect(pytest?.critical).toBe(true)
    })
  })

  describe("getGate", () => {
    test("returns gate by ID", () => {
      const gate = Verifier.getGate("pytest")
      expect(gate).toBeDefined()
      expect(gate?.info.id).toBe("pytest")
    })

    test("returns undefined for unknown gate", () => {
      const gate = Verifier.getGate("unknown")
      expect(gate).toBeUndefined()
    })
  })

  describe("registerGate / unregisterGate", () => {
    test("can register and unregister custom gate", () => {
      const customGate = {
        info: {
          id: "custom-test",
          name: "Custom Test",
          description: "A custom test gate",
          critical: false,
        },
        isAvailable: async () => true,
        run: async () => ({
          gate: "custom-test",
          passed: true,
          critical: false,
          output: "OK",
          timing: { startedAt: Date.now(), completedAt: Date.now() },
        }),
      }

      Verifier.registerGate(customGate)
      expect(Verifier.getGate("custom-test")).toBeDefined()

      Verifier.unregisterGate("custom-test")
      expect(Verifier.getGate("custom-test")).toBeUndefined()
    })
  })

  describe("calculateScore", () => {
    test("returns 100 for all passing gates", () => {
      const results: GateResult[] = [
        {
          gate: "pytest",
          passed: true,
          critical: true,
          output: "OK",
          timing: { startedAt: 0, completedAt: 0 },
        },
        {
          gate: "mypy",
          passed: true,
          critical: false,
          output: "OK",
          timing: { startedAt: 0, completedAt: 0 },
        },
      ]

      expect(Verifier.calculateScore(results)).toBe(100)
    })

    test("deducts 10 points per error", () => {
      const results: GateResult[] = [
        {
          gate: "mypy",
          passed: false,
          critical: false,
          output: "errors",
          diagnostics: [
            { file: "a.py", line: 1, severity: "error", message: "error 1" },
            { file: "b.py", line: 2, severity: "error", message: "error 2" },
          ],
          timing: { startedAt: 0, completedAt: 0 },
        },
      ]

      expect(Verifier.calculateScore(results)).toBe(80) // 100 - 2*10
    })

    test("deducts 2 points per warning", () => {
      const results: GateResult[] = [
        {
          gate: "ruff",
          passed: false,
          critical: false,
          output: "warnings",
          diagnostics: [
            { file: "a.py", line: 1, severity: "warning", message: "warning 1" },
            { file: "b.py", line: 2, severity: "warning", message: "warning 2" },
            { file: "c.py", line: 3, severity: "warning", message: "warning 3" },
          ],
          timing: { startedAt: 0, completedAt: 0 },
        },
      ]

      expect(Verifier.calculateScore(results)).toBe(94) // 100 - 3*2
    })

    test("penalizes failed gates without diagnostics", () => {
      const results: GateResult[] = [
        {
          gate: "pytest",
          passed: false,
          critical: true,
          output: "failed",
          timing: { startedAt: 0, completedAt: 0 },
        },
      ]

      expect(Verifier.calculateScore(results)).toBe(50) // 100 - 50 (critical)
    })

    test("minimum score is 0", () => {
      const results: GateResult[] = [
        {
          gate: "mypy",
          passed: false,
          critical: false,
          output: "many errors",
          diagnostics: Array(20)
            .fill(null)
            .map((_, i) => ({ file: `f${i}.py`, line: i, severity: "error" as const, message: `error ${i}` })),
          timing: { startedAt: 0, completedAt: 0 },
        },
      ]

      expect(Verifier.calculateScore(results)).toBe(0) // 100 - 20*10 = -100, capped at 0
    })
  })

  describe("generateSummary", () => {
    test("generates summary for all passed", () => {
      const summary = Verifier.generateSummary({
        allPassed: true,
        criticalPassed: true,
        results: [
          {
            gate: "pytest",
            passed: true,
            critical: true,
            output: "OK",
            timing: { startedAt: 0, completedAt: 100 },
          },
        ],
        score: 100,
        summary: "",
      })

      expect(summary).toContain("All gates passed")
      expect(summary).toContain("Score: 100/100")
      expect(summary).toContain("pytest")
    })

    test("generates summary for critical failure", () => {
      const summary = Verifier.generateSummary({
        allPassed: false,
        criticalPassed: false,
        results: [
          {
            gate: "pytest",
            passed: false,
            critical: true,
            output: "failed",
            timing: { startedAt: 0, completedAt: 100 },
          },
        ],
        score: 50,
        summary: "",
      })

      expect(summary).toContain("Critical gate(s) failed")
      expect(summary).toContain("Score: 50/100")
    })

    test("generates summary with diagnostic counts", () => {
      const summary = Verifier.generateSummary({
        allPassed: false,
        criticalPassed: true,
        results: [
          {
            gate: "mypy",
            passed: false,
            critical: false,
            output: "errors",
            diagnostics: [
              { file: "a.py", line: 1, severity: "error", message: "err" },
              { file: "b.py", line: 2, severity: "warning", message: "warn" },
              { file: "c.py", line: 3, severity: "warning", message: "warn" },
            ],
            timing: { startedAt: 0, completedAt: 100 },
          },
        ],
        score: 86,
        summary: "",
      })

      expect(summary).toContain("1 error")
      expect(summary).toContain("2 warnings")
    })
  })

  describe("runGate", () => {
    test("returns skipped result for unknown gate", async () => {
      const workcell = makeWorkcell()
      const result = await Verifier.runGate(workcell, "unknown-gate")

      expect(result.passed).toBe(false)
      expect(result.output).toContain("not found")
    })

    test("returns skipped result for unavailable gate", async () => {
      // Register a gate that's never available
      const unavailableGate = {
        info: {
          id: "unavailable-test",
          name: "Unavailable",
          description: "Never available",
          critical: false,
        },
        isAvailable: async () => false,
        run: async () => ({
          gate: "unavailable-test",
          passed: false,
          critical: false,
          output: "should not run",
          timing: { startedAt: 0, completedAt: 0 },
        }),
      }

      Verifier.registerGate(unavailableGate)
      const result = await Verifier.runGate(makeWorkcell(), "unavailable-test")
      Verifier.unregisterGate("unavailable-test")

      expect(result.passed).toBe(true) // skipped gates pass
      expect(result.output).toContain("skipped")
    })
  })

  describe("run", () => {
    test("runs multiple gates and aggregates results", async () => {
      // Register mock gates for testing
      const mockGate1 = {
        info: { id: "mock1", name: "Mock 1", description: "test", critical: false },
        isAvailable: async () => true,
        run: async () => ({
          gate: "mock1",
          passed: true,
          critical: false,
          output: "OK",
          timing: { startedAt: Date.now(), completedAt: Date.now() },
        }),
      }
      const mockGate2 = {
        info: { id: "mock2", name: "Mock 2", description: "test", critical: false },
        isAvailable: async () => true,
        run: async () => ({
          gate: "mock2",
          passed: true,
          critical: false,
          output: "OK",
          timing: { startedAt: Date.now(), completedAt: Date.now() },
        }),
      }

      Verifier.registerGate(mockGate1)
      Verifier.registerGate(mockGate2)

      const results = await Verifier.run(makeWorkcell(), {
        gates: ["mock1", "mock2"],
      })

      Verifier.unregisterGate("mock1")
      Verifier.unregisterGate("mock2")

      expect(results.allPassed).toBe(true)
      expect(results.criticalPassed).toBe(true)
      expect(results.results).toHaveLength(2)
      expect(results.score).toBe(100)
      expect(results.summary).toContain("All gates passed")
    })

    test("fail-fast stops on critical failure", async () => {
      let gate2Ran = false

      const failingGate = {
        info: { id: "failing", name: "Failing", description: "test", critical: true },
        isAvailable: async () => true,
        run: async () => ({
          gate: "failing",
          passed: false,
          critical: true,
          output: "FAIL",
          timing: { startedAt: Date.now(), completedAt: Date.now() },
        }),
      }
      const secondGate = {
        info: { id: "second", name: "Second", description: "test", critical: false },
        isAvailable: async () => true,
        run: async () => {
          gate2Ran = true
          return {
            gate: "second",
            passed: true,
            critical: false,
            output: "OK",
            timing: { startedAt: Date.now(), completedAt: Date.now() },
          }
        },
      }

      Verifier.registerGate(failingGate)
      Verifier.registerGate(secondGate)

      const results = await Verifier.run(makeWorkcell(), {
        gates: ["failing", "second"],
        failFast: true,
      })

      Verifier.unregisterGate("failing")
      Verifier.unregisterGate("second")

      expect(results.allPassed).toBe(false)
      expect(results.criticalPassed).toBe(false)
      expect(results.results).toHaveLength(1) // only first gate ran
      expect(gate2Ran).toBe(false)
    })

    test("continues on non-critical failure with fail-fast", async () => {
      const nonCriticalFail = {
        info: { id: "noncrit", name: "NonCrit", description: "test", critical: false },
        isAvailable: async () => true,
        run: async () => ({
          gate: "noncrit",
          passed: false,
          critical: false,
          output: "FAIL",
          timing: { startedAt: Date.now(), completedAt: Date.now() },
        }),
      }
      const secondGate = {
        info: { id: "second2", name: "Second", description: "test", critical: false },
        isAvailable: async () => true,
        run: async () => ({
          gate: "second2",
          passed: true,
          critical: false,
          output: "OK",
          timing: { startedAt: Date.now(), completedAt: Date.now() },
        }),
      }

      Verifier.registerGate(nonCriticalFail)
      Verifier.registerGate(secondGate)

      const results = await Verifier.run(makeWorkcell(), {
        gates: ["noncrit", "second2"],
        failFast: true,
      })

      Verifier.unregisterGate("noncrit")
      Verifier.unregisterGate("second2")

      expect(results.results).toHaveLength(2) // both gates ran
      expect(results.criticalPassed).toBe(true) // no critical gates
    })
  })
})
