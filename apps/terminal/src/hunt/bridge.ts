// hunt/bridge.ts - Core CLI bridge for clawdstrike hunt subcommands

import type { WatchJsonLine } from "./types"

const DEFAULT_TIMEOUT_MS = 30_000
const HUNT_BINARY = "clawdstrike"

export interface HuntCommandResult<T> {
  ok: boolean
  data?: T
  error?: string
  exitCode: number
}

export interface HuntStreamHandle {
  kill(): void
}

export interface HuntCommandOptions {
  cwd?: string
  timeout?: number
  env?: Record<string, string>
}

/**
 * Run a clawdstrike hunt subcommand and parse JSON output.
 *
 * Spawns `clawdstrike hunt <args> --json`, collects stdout,
 * parses the result as JSON, and returns a typed result envelope.
 */
export async function runHuntCommand<T>(
  args: string[],
  opts?: HuntCommandOptions,
): Promise<HuntCommandResult<T>> {
  const timeout = opts?.timeout ?? DEFAULT_TIMEOUT_MS

  const proc = Bun.spawn([HUNT_BINARY, "hunt", ...args, "--json"], {
    cwd: opts?.cwd,
    env: opts?.env ? { ...process.env, ...opts.env } : undefined,
    stdout: "pipe",
    stderr: "pipe",
  })

  const timer = timeout > 0
    ? setTimeout(() => proc.kill(), timeout)
    : undefined

  try {
    const [stdoutText, stderrText, exitCode] = await Promise.all([
      new Response(proc.stdout).text(),
      new Response(proc.stderr).text(),
      proc.exited,
    ])

    if (timer) clearTimeout(timer)

    if (exitCode !== 0) {
      const errorMessage = stderrText.trim() || `Process exited with code ${exitCode}`
      return { ok: false, error: errorMessage, exitCode }
    }

    const trimmed = stdoutText.trim()
    if (!trimmed) {
      return { ok: true, data: undefined, exitCode: 0 }
    }

    try {
      const data = JSON.parse(trimmed) as T
      return { ok: true, data, exitCode: 0 }
    } catch {
      return {
        ok: false,
        error: `Failed to parse JSON output: ${trimmed.slice(0, 200)}`,
        exitCode: 0,
      }
    }
  } catch (err) {
    if (timer) clearTimeout(timer)
    const message = err instanceof Error ? err.message : String(err)
    return { ok: false, error: message, exitCode: -1 }
  }
}

/**
 * Spawn a long-running hunt process (e.g., watch mode) that emits
 * newline-delimited JSON (NDJSON) on stdout.
 *
 * Each line is parsed as JSON and dispatched to onLine. Parse errors
 * or process failures are dispatched to onError.
 *
 * Returns a handle with a kill() method to terminate the process.
 */
export function spawnHuntStream(
  args: string[],
  onLine: (line: WatchJsonLine) => void,
  onError: (error: string) => void,
  opts?: HuntCommandOptions,
): HuntStreamHandle {
  const proc = Bun.spawn([HUNT_BINARY, "hunt", ...args, "--json"], {
    cwd: opts?.cwd,
    env: opts?.env ? { ...process.env, ...opts.env } : undefined,
    stdout: "pipe",
    stderr: "pipe",
  })

  // Read stdout line-by-line in the background
  const readLines = async () => {
    const reader = proc.stdout.getReader()
    const decoder = new TextDecoder()
    let buffer = ""

    try {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split("\n")
        // Keep the last (possibly incomplete) chunk in the buffer
        buffer = lines.pop() ?? ""

        for (const raw of lines) {
          const trimmed = raw.trim()
          if (!trimmed) continue
          try {
            const parsed = JSON.parse(trimmed) as WatchJsonLine
            onLine(parsed)
          } catch {
            onError(`Failed to parse stream line: ${trimmed.slice(0, 200)}`)
          }
        }
      }

      // Flush remaining buffer
      const remaining = buffer.trim()
      if (remaining) {
        try {
          const parsed = JSON.parse(remaining) as WatchJsonLine
          onLine(parsed)
        } catch {
          onError(`Failed to parse final stream chunk: ${remaining.slice(0, 200)}`)
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      onError(`Stream read error: ${message}`)
    }
  }

  // Read stderr for error reporting
  const readStderr = async () => {
    const text = await new Response(proc.stderr).text()
    const trimmed = text.trim()
    if (trimmed) {
      onError(trimmed)
    }
  }

  readLines()
  readStderr()

  return {
    kill() {
      proc.kill()
    },
  }
}
