/**
 * Mypy Gate - Python type checker
 *
 * Runs mypy type checking on Python code and parses output for diagnostics.
 */

import { $ } from "bun"
import { join } from "path"
import { stat } from "fs/promises"
import type { Gate } from "../index"
import type { GateResult, WorkcellInfo, Diagnostic, Severity } from "../../types"

/**
 * Default mypy configuration
 */
export const DEFAULT_CONFIG = {
  timeout: 120000, // 2 minutes
  args: ["--show-column-numbers"],
  cwd: undefined as string | undefined,
  filePatterns: ["**/*.py"],
}

/**
 * Parse mypy output for diagnostics
 *
 * Mypy output format: file.py:line:col: error: message [error-code]
 */
export function parseDiagnostics(output: string): Diagnostic[] {
  const diagnostics: Diagnostic[] = []

  // Parse mypy error/warning/note lines
  // Example: foo.py:10:5: error: Incompatible types [assignment]
  const errorRegex = /^(.+):(\d+):(\d+):\s*(error|warning|note):\s*(.+?)(?:\s+\[([^\]]+)\])?$/gm
  let match: RegExpExecArray | null
  while ((match = errorRegex.exec(output)) !== null) {
    const severityMap: Record<string, Severity> = {
      error: "error",
      warning: "warning",
      note: "info",
    }

    diagnostics.push({
      file: match[1],
      line: parseInt(match[2]),
      column: parseInt(match[3]),
      severity: severityMap[match[4]] || "error",
      message: match[5],
      code: match[6],
      source: "mypy",
    })
  }

  // Also parse simpler format without column (older mypy versions)
  // Format: file.py:line: error/warning/note: message [code]
  // Use non-greedy match for filename and ensure the line number is followed
  // directly by severity (not another number indicating column)
  const simpleRegex = /^([^:]+\.py):(\d+):\s+(error|warning|note):\s*(.+?)(?:\s+\[([^\]]+)\])?$/gm
  let simpleMatch: RegExpExecArray | null
  while ((simpleMatch = simpleRegex.exec(output)) !== null) {
    const file = simpleMatch[1]
    const line = parseInt(simpleMatch[2])
    const severity = simpleMatch[3]
    const message = simpleMatch[4]
    const code = simpleMatch[5]

    // Still check for duplicates in case both regexes somehow match
    const alreadyParsed = diagnostics.some(
      (d) => d.file === file && d.line === line
    )
    if (!alreadyParsed) {
      const severityMap: Record<string, Severity> = {
        error: "error",
        warning: "warning",
        note: "info",
      }

      diagnostics.push({
        file,
        line,
        severity: severityMap[severity] || "error",
        message,
        code,
        source: "mypy",
      })
    }
  }

  return diagnostics
}

/**
 * Check if mypy config exists
 */
async function hasConfig(directory: string): Promise<boolean> {
  const configFiles = ["mypy.ini", "pyproject.toml", ".mypy.ini", "setup.cfg"]

  for (const file of configFiles) {
    try {
      await stat(join(directory, file))
      return true
    } catch {
      // File doesn't exist
    }
  }
  return false
}

export const MypyGate: Gate = {
  info: {
    id: "mypy",
    name: "Mypy",
    description: "Python static type checker",
    critical: false,
  },

  async isAvailable(workcell: WorkcellInfo): Promise<boolean> {
    // Check for mypy command
    const which = await $`which mypy`.quiet().nothrow()
    if (which.exitCode !== 0) {
      return false
    }

    // Check for Python files in workcell
    const findPy = await $`find ${workcell.directory} -name "*.py" -not -path "*/.venv/*" -not -path "*/venv/*" 2>/dev/null | head -1`
      .quiet()
      .nothrow()

    return findPy.stdout.toString().trim().length > 0
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
      // Check for mypy config to determine args
      const configExists = await hasConfig(cwd)
      const args = configExists
        ? [...DEFAULT_CONFIG.args, "."]
        : [...DEFAULT_CONFIG.args, "--ignore-missing-imports", "."]

      // Run mypy
      const proc = Bun.spawn(["mypy", ...args], {
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

export default MypyGate
