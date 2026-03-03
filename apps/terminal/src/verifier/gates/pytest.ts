/**
 * Pytest Gate - Python test runner
 *
 * Runs Python tests with pytest and parses output for diagnostics.
 */

import { $ } from "bun"
import { join } from "path"
import type { Gate } from "../index"
import type { GateResult, WorkcellInfo, Diagnostic } from "../../types"

/**
 * Default pytest configuration
 */
export const DEFAULT_CONFIG = {
  timeout: 300000, // 5 minutes
  args: ["-v", "--tb=short", "-q"],
  cwd: undefined as string | undefined,
  filePatterns: ["**/*.py", "**/test_*.py", "**/*_test.py"],
}

/**
 * Parse pytest output for diagnostics
 */
export function parseDiagnostics(output: string): Diagnostic[] {
  const diagnostics: Diagnostic[] = []

  // Parse FAILED lines: FAILED tests/test_foo.py::test_bar - AssertionError
  const failedRegex = /FAILED\s+([^:]+)::(\w+)(?:\s+-\s+(.+))?/gm
  let match
  while ((match = failedRegex.exec(output)) !== null) {
    diagnostics.push({
      file: match[1],
      severity: "error",
      message: match[3] || `Test ${match[2]} failed`,
      source: "pytest",
    })
  }

  // Parse ERROR lines: ERROR tests/conftest.py - SyntaxError
  // or: ERROR tests/test_foo.py::test_bar - ModuleNotFoundError
  const errorRegex = /ERROR\s+([^\s:]+(?:\.[^\s:]+)*)(?:::(\w+))?(?:\s+-\s+(.+))?/gm
  while ((match = errorRegex.exec(output)) !== null) {
    diagnostics.push({
      file: match[1],
      severity: "error",
      message: match[3] || `Error in ${match[2] || "collection"}`,
      source: "pytest",
    })
  }

  // Parse file:line: error format (assertion errors, etc.)
  const lineErrorRegex = /^([^\s:]+\.py):(\d+):\s*(\w+(?:Error|Exception)?):?\s*(.*)$/gm
  while ((match = lineErrorRegex.exec(output)) !== null) {
    diagnostics.push({
      file: match[1],
      line: parseInt(match[2]),
      severity: "error",
      message: `${match[3]}${match[4] ? ": " + match[4] : ""}`,
      source: "pytest",
    })
  }

  return diagnostics
}

export const PytestGate: Gate = {
  info: {
    id: "pytest",
    name: "Pytest",
    description: "Run Python tests with pytest",
    critical: true,
  },

  async isAvailable(workcell: WorkcellInfo): Promise<boolean> {
    // Check for pytest command
    const which = await $`which pytest`.quiet().nothrow()
    if (which.exitCode !== 0) {
      return false
    }

    // Check for test files in workcell
    const findTests = await $`find ${workcell.directory} -name "test_*.py" -o -name "*_test.py" 2>/dev/null | head -1`
      .quiet()
      .nothrow()

    return findTests.stdout.toString().trim().length > 0
  },

  async run(
    workcell: WorkcellInfo,
    signal: AbortSignal
  ): Promise<GateResult> {
    const startedAt = Date.now()

    // Resolve working directory
    const cwd = DEFAULT_CONFIG.cwd
      ? join(workcell.directory, DEFAULT_CONFIG.cwd)
      : workcell.directory

    const args = DEFAULT_CONFIG.args

    try {
      // Run pytest
      const proc = Bun.spawn(["pytest", ...args], {
        cwd,
        env: {
          ...process.env,
          PYTHONDONTWRITEBYTECODE: "1",
          CLAWDSTRIKE_SANDBOX: "1",
        },
        stdout: "pipe",
        stderr: "pipe",
      })

      // Handle abort signal
      const abortHandler = () => proc.kill()
      signal.addEventListener("abort", abortHandler)

      // Set up timeout
      const timeoutId = setTimeout(() => {
        proc.kill()
      }, DEFAULT_CONFIG.timeout)

      const [stdout, stderr] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ])
      const exitCode = await proc.exited

      clearTimeout(timeoutId)
      signal.removeEventListener("abort", abortHandler)

      const output = stdout + stderr
      const completedAt = Date.now()

      if (signal.aborted) {
        return {
          gate: this.info.id,
          passed: false,
          critical: this.info.critical,
          output: "Gate cancelled",
          timing: { startedAt, completedAt },
        }
      }

      return {
        gate: this.info.id,
        passed: exitCode === 0,
        critical: this.info.critical,
        output,
        diagnostics: parseDiagnostics(output),
        timing: { startedAt, completedAt },
      }
    } catch (error) {
      const completedAt = Date.now()
      return {
        gate: this.info.id,
        passed: false,
        critical: this.info.critical,
        output: error instanceof Error ? error.message : String(error),
        timing: { startedAt, completedAt },
      }
    }
  },
}

export default PytestGate
