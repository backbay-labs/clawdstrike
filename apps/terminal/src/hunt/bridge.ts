// hunt/bridge.ts - Core CLI bridge for clawdstrike hunt subcommands

import * as fs from "node:fs"
import * as os from "node:os"
import * as path from "node:path"
import { fileURLToPath } from "node:url"
import type { WatchJsonLine } from "./types"

const DEFAULT_TIMEOUT_MS = 30_000
const HUNT_BINARY_ENV = "CLAWDSTRIKE_TUI_HUNT_BINARY"
const DEFAULT_BINARY = process.platform === "win32" ? "clawdstrike.exe" : "clawdstrike"
const HUNT_BINARY_NAMES = process.platform === "win32"
  ? ["clawdstrike.exe", "hush.exe"]
  : ["clawdstrike", "hush"]

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

export interface HuntJsonEnvelope<T> {
  version?: number
  command?: string
  exit_code?: number
  error?: {
    kind?: string
    message?: string
  } | null
  data?: T
}

function uniquePaths(paths: Array<string | null | undefined>): string[] {
  const seen = new Set<string>()
  const resolved: string[] = []

  for (const candidate of paths) {
    if (!candidate) continue
    const normalized = path.resolve(candidate)
    if (seen.has(normalized)) continue
    seen.add(normalized)
    resolved.push(normalized)
  }

  return resolved
}

function resolveRuntimeScriptPath(): string | null {
  return process.env.CLAWDSTRIKE_TUI_RUNTIME_SCRIPT ?? Bun.main ?? process.argv[1] ?? null
}

function findBinaryInDir(dir: string): string | null {
  for (const name of HUNT_BINARY_NAMES) {
    const candidate = path.join(dir, name)
    if (fs.existsSync(candidate)) return candidate
  }
  return null
}

export function findRepoHuntBinary(start: string): string | null {
  let current = path.resolve(start)

  try {
    if (fs.existsSync(current) && fs.statSync(current).isFile()) {
      current = path.dirname(current)
    }
  } catch {
    return null
  }

  while (true) {
    for (const profile of ["debug", "release"]) {
      const candidate = findBinaryInDir(path.join(current, "target", profile))
      if (candidate) return candidate
    }

    const parent = path.dirname(current)
    if (parent === current) break
    current = parent
  }

  return null
}

function resolveInstalledHuntBinary(scriptPath: string): string | null {
  const scriptDir = path.dirname(path.resolve(scriptPath))
  return findBinaryInDir(path.resolve(scriptDir, "../../../bin"))
}

export function resolveHuntBinary(cwd: string = process.cwd()): string {
  const override = process.env[HUNT_BINARY_ENV]
  if (override?.trim()) return override.trim()

  const runtimeScript = resolveRuntimeScriptPath()
  if (runtimeScript) {
    const installedBinary = resolveInstalledHuntBinary(runtimeScript)
    if (installedBinary) return installedBinary
  }

  for (const start of uniquePaths([
    cwd,
    process.cwd(),
    runtimeScript ? path.dirname(runtimeScript) : null,
  ])) {
    const repoBinary = findRepoHuntBinary(start)
    if (repoBinary) return repoBinary
  }

  return DEFAULT_BINARY
}

function listRuleFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return []

  try {
    if (!fs.statSync(dir).isDirectory()) return []
    return fs.readdirSync(dir)
      .filter((entry) => entry.endsWith(".yaml") || entry.endsWith(".yml"))
      .sort((a, b) => a.localeCompare(b))
      .map((entry) => path.join(dir, entry))
  } catch {
    return []
  }
}

function resolveBundledWatchRule(): string | null {
  const bundled = fileURLToPath(new URL("./rules/default-watch.yaml", import.meta.url))
  return fs.existsSync(bundled) ? bundled : null
}

export function resolveDefaultWatchRules(cwd: string = process.cwd()): string[] {
  const localRules = listRuleFiles(path.join(cwd, ".clawdstrike", "rules"))
  if (localRules.length > 0) return localRules

  const homeRules = listRuleFiles(path.join(os.homedir(), ".clawdstrike", "rules"))
  if (homeRules.length > 0) return homeRules

  const bundled = resolveBundledWatchRule()
  return bundled ? [bundled] : []
}

function buildHuntCommand(args: string[], opts?: HuntCommandOptions): string[] {
  return [resolveHuntBinary(opts?.cwd), "hunt", ...args, "--json"]
}

function extractStructuredStreamError(payload: string): string | null {
  const trimmed = payload.trim()
  if (!trimmed) return null

  try {
    const parsed = JSON.parse(trimmed) as {
      error?: { message?: string }
      message?: string
    }
    if (parsed.error?.message) return parsed.error.message
    if (typeof parsed.message === "string") return parsed.message
  } catch {
    // Fall through to the raw payload preview.
  }

  return trimmed.slice(0, 240)
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

  try {
    const proc = Bun.spawn(buildHuntCommand(args, opts), {
      cwd: opts?.cwd,
      env: opts?.env ? { ...process.env, ...opts.env } : undefined,
      stdout: "pipe",
      stderr: "pipe",
    })

    const timer = timeout > 0
      ? setTimeout(() => proc.kill(), timeout)
      : undefined

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
    const message = err instanceof Error ? err.message : String(err)
    return { ok: false, error: message, exitCode: -1 }
  }
}

export function extractHuntEnvelopeData<T>(payload: unknown): T | undefined {
  if (payload == null) return undefined
  if (Array.isArray(payload)) return payload as T
  if (typeof payload !== "object") return payload as T

  const envelope = payload as HuntJsonEnvelope<T>
  if ("data" in envelope) {
    return envelope.data
  }

  return payload as T
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
  let proc: Bun.Subprocess<"ignore", "pipe", "pipe">
  const invalidStdoutLines: string[] = []

  try {
    proc = Bun.spawn(buildHuntCommand(args, opts), {
      cwd: opts?.cwd,
      env: opts?.env ? { ...process.env, ...opts.env } : undefined,
      stdout: "pipe",
      stderr: "pipe",
    }) as Bun.Subprocess<"ignore", "pipe", "pipe">
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    onError(message)
    return { kill() {} }
  }

  let killed = false
  const stderrText = new Response(proc.stderr).text()

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
            invalidStdoutLines.push(trimmed)
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
          invalidStdoutLines.push(remaining)
        }
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      onError(`Stream read error: ${message}`)
    }
  }

  const stdoutDone = readLines()

  const watchExit = async () => {
    const [exitCode, stderr] = await Promise.all([proc.exited, stderrText])
    await stdoutDone
    if (killed) return

    if (exitCode === 0) {
      if (invalidStdoutLines.length > 0) {
        const message = extractStructuredStreamError(invalidStdoutLines.join("\n"))
        if (message) onError(message)
      }
      return
    }

    const trimmed = stderr.trim()
    if (trimmed) {
      onError(trimmed)
      return
    }

    const stdoutMessage = extractStructuredStreamError(invalidStdoutLines.join("\n"))
    if (stdoutMessage) {
      onError(stdoutMessage)
      return
    }

    onError(`Process exited with code ${exitCode}`)
  }

  void watchExit()

  return {
    kill() {
      killed = true
      proc.kill()
    },
  }
}
