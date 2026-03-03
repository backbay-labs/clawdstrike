/**
 * Ruff Gate - Python linter and formatter
 *
 * Runs ruff check and format verification on Python code.
 * Outputs JSON format for easy diagnostic parsing.
 */

import { $ } from "bun"
import { join } from "path"
import type { Gate } from "../index"
import type { GateResult, WorkcellInfo, Diagnostic, Severity } from "../../types"

/**
 * Default ruff configuration
 */
export const DEFAULT_CONFIG = {
  timeout: 60000, // 1 minute
  checkArgs: ["check", "--output-format=json", "."],
  formatArgs: ["format", "--check", "."],
  cwd: undefined as string | undefined,
  filePatterns: ["**/*.py"],
}

/**
 * Ruff JSON diagnostic format
 */
interface RuffDiagnostic {
  code: string
  message: string
  filename: string
  location: {
    row: number
    column: number
  }
  end_location?: {
    row: number
    column: number
  }
  fix?: {
    applicability: string
    message: string
    edits: unknown[]
  }
  url?: string
}

/**
 * Parse ruff JSON output for diagnostics
 */
export function parseDiagnostics(output: string): Diagnostic[] {
  try {
    const issues = JSON.parse(output) as RuffDiagnostic[]
    return issues.map((issue) => ({
      file: issue.filename,
      line: issue.location.row,
      column: issue.location.column,
      severity: (issue.fix ? "warning" : "error") as Severity,
      message: issue.message,
      code: issue.code,
      source: "ruff",
    }))
  } catch {
    // Fallback: parse text output
    const diagnostics: Diagnostic[] = []
    const lineRegex = /^(.+):(\d+):(\d+):\s*(\w+)\s+(.+)$/gm
    let match
    while ((match = lineRegex.exec(output)) !== null) {
      diagnostics.push({
        file: match[1],
        line: parseInt(match[2]),
        column: parseInt(match[3]),
        severity: "warning",
        message: match[5],
        code: match[4],
        source: "ruff",
      })
    }
    return diagnostics
  }
}

export const RuffGate: Gate = {
  info: {
    id: "ruff",
    name: "Ruff",
    description: "Python linter and formatter",
    critical: false,
  },

  async isAvailable(_workcell: WorkcellInfo): Promise<boolean> {
    // Check for ruff command (available if installed, regardless of workcell contents)
    const which = await $`which ruff`.quiet().nothrow()
    return which.exitCode === 0
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

    try {
      // Run ruff check
      const checkProc = Bun.spawn(["ruff", ...DEFAULT_CONFIG.checkArgs], {
        cwd,
        env: {
          ...process.env,
          CLAWDSTRIKE_SANDBOX: "1",
        },
        stdout: "pipe",
        stderr: "pipe",
      })

      // Handle abort signal
      const abortHandler = () => {
        checkProc.kill()
      }
      signal.addEventListener("abort", abortHandler)

      // Set up timeout
      const timeoutId = setTimeout(() => {
        checkProc.kill()
      }, DEFAULT_CONFIG.timeout)

      const [checkStdout, checkStderr] = await Promise.all([
        new Response(checkProc.stdout).text(),
        new Response(checkProc.stderr).text(),
      ])
      const checkExitCode = await checkProc.exited

      clearTimeout(timeoutId)
      signal.removeEventListener("abort", abortHandler)

      if (signal.aborted) {
        return {
          gate: this.info.id,
          passed: false,
          critical: this.info.critical,
          output: "Gate cancelled",
          timing: { startedAt, completedAt: Date.now() },
        }
      }

      // Run ruff format --check
      const formatProc = Bun.spawn(["ruff", ...DEFAULT_CONFIG.formatArgs], {
        cwd,
        env: {
          ...process.env,
          CLAWDSTRIKE_SANDBOX: "1",
        },
        stdout: "pipe",
        stderr: "pipe",
      })

      const formatTimeoutId = setTimeout(() => {
        formatProc.kill()
      }, DEFAULT_CONFIG.timeout)

      const [formatStdout, formatStderr] = await Promise.all([
        new Response(formatProc.stdout).text(),
        new Response(formatProc.stderr).text(),
      ])
      const formatExitCode = await formatProc.exited

      clearTimeout(formatTimeoutId)

      const completedAt = Date.now()

      // Combine outputs
      const checkOutput = checkStdout + checkStderr
      const formatOutput = formatStdout + formatStderr
      const output = `=== ruff check ===\n${checkOutput}\n=== ruff format --check ===\n${formatOutput}`

      // Parse diagnostics from check output (JSON format)
      const diagnostics = parseDiagnostics(checkStdout)

      // Add format issues as diagnostics
      if (formatExitCode !== 0 && formatOutput.trim()) {
        // Parse files that would be reformatted
        const reformatRegex = /^Would reformat:\s*(.+)$/gm
        let match
        while ((match = reformatRegex.exec(formatOutput)) !== null) {
          diagnostics.push({
            file: match[1],
            severity: "warning",
            message: "File would be reformatted",
            code: "format",
            source: "ruff",
          })
        }
      }

      return {
        gate: this.info.id,
        passed: checkExitCode === 0 && formatExitCode === 0,
        critical: this.info.critical,
        output,
        diagnostics,
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

export default RuffGate
