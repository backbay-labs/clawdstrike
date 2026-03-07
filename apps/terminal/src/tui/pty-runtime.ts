import { rm } from "node:fs/promises"
import { fileURLToPath } from "node:url"
import { Config } from "../config"
import { Workcell } from "../workcell"
import type { Toolchain } from "../types"
import type { RunRecord } from "./types"
import { buildEmbeddedInteractiveSessionCommand } from "./interactive-command"

export interface InteractivePtyRuntime {
  id: string
  write(input: string): void
  resize(cols: number, rows: number): void
  kill(): void
  onOutput(cb: (chunk: string) => void): void
  onExit(cb: (code: number | null, signal: string | null) => void): void
}

export interface EmbeddedInteractiveSessionPlan {
  sessionId: string
  workcell: Awaited<ReturnType<typeof Workcell.acquire>>
  routing: { toolchain: string; strategy: string; gates: string[] }
  runtime: InteractivePtyRuntime
  launchConsumesPrompt: boolean
  stagedTaskEditable: boolean
  cleanup: () => Promise<void>
}

function isInteractiveToolchain(toolchain: string): toolchain is Toolchain {
  return toolchain === "claude" || toolchain === "codex"
}

function makeSessionId(): string {
  return `pty_embedded_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`
}

const PTY_BRIDGE_PATH = fileURLToPath(new URL("./pty-runtime-helper.py", import.meta.url))

function shellEnvForRuntime(sessionId: string, worktreePath: string): Record<string, string> {
  return {
    ...process.env,
    TERM: process.env.TERM || "xterm-256color",
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    CLAWDSTRIKE_SANDBOX: "1",
    CLAWDSTRIKE_WORKCELL_ROOT: worktreePath,
    CLAWDSTRIKE_PTY_SESSION_ID: sessionId,
  }
}

function injectTerminalResponses(rawChunk: string, write: (input: string) => void): void {
  if (rawChunk.includes("\x1b[6n")) {
    write("\x1b[1;1R")
  }

  if (rawChunk.includes("\x1b[c") || rawChunk.includes("\x1b[>7u")) {
    write("\x1b[?1;2c")
  }
}

function createPtyRuntime(
  sessionId: string,
  command: string[],
  cwd: string,
  env: Record<string, string>,
): InteractivePtyRuntime {
  const python = Bun.which("python3") ?? "/usr/bin/python3"
  const proc = Bun.spawn([
    python,
    PTY_BRIDGE_PATH,
    "--cwd",
    cwd,
    "--cols",
    String(Math.max(process.stdout.columns ?? 120, 20)),
    "--rows",
    String(Math.max(process.stdout.rows ?? 40, 10)),
    "--",
    ...command,
  ], {
    cwd,
    env,
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  })
  const outputListeners = new Set<(chunk: string) => void>()
  const exitListeners = new Set<(code: number | null, signal: string | null) => void>()
  const encoder = new TextEncoder()
  const decoder = new TextDecoder()
  const ptyDecoder = new TextDecoder()
  let helperStdoutBuffer = ""
  let helperExit: { code: number | null; signal: string | null } | null = null

  const sendMessage = (message: Record<string, unknown>) => {
    try {
      proc.stdin.write(encoder.encode(`${JSON.stringify(message)}\n`))
    } catch {
      // Ignore writes after teardown.
    }
  }

  const write = (input: string) => {
    sendMessage({ type: "input", data: Buffer.from(input, "utf8").toString("base64") })
  }

  const emitOutput = (chunk: string) => {
    if (!chunk) {
      return
    }
    injectTerminalResponses(chunk, write)
    for (const listener of outputListeners) {
      listener(chunk)
    }
  }

  const flushHelperStdout = (chunk: string) => {
    helperStdoutBuffer += chunk
    for (;;) {
      const newline = helperStdoutBuffer.indexOf("\n")
      if (newline < 0) {
        break
      }
      const line = helperStdoutBuffer.slice(0, newline).trim()
      helperStdoutBuffer = helperStdoutBuffer.slice(newline + 1)
      if (!line) {
        continue
      }
      try {
        const message = JSON.parse(line) as
          | { type: "ready" }
          | { type: "output"; data: string }
          | { type: "exit"; code: number | null; signal?: string | null }
          | { type: "error"; error: string }
        if (message.type === "output") {
          const payload = Buffer.from(message.data, "base64")
          emitOutput(ptyDecoder.decode(payload, { stream: true }))
          continue
        }
        if (message.type === "exit") {
          emitOutput(ptyDecoder.decode())
          helperExit = {
            code: message.code ?? null,
            signal: message.signal ?? null,
          }
          continue
        }
        if (message.type === "error") {
          emitOutput(`${message.error}\n`)
        }
      } catch {
        emitOutput(`${line}\n`)
      }
    }
  }

  void (async () => {
    if (!proc.stdout) {
      return
    }
    const reader = proc.stdout.getReader()
    try {
      for (;;) {
        const { value, done } = await reader.read()
        if (done) {
          break
        }
        if (value) {
          flushHelperStdout(decoder.decode(value, { stream: true }))
        }
      }
      flushHelperStdout(decoder.decode())
    } finally {
      reader.releaseLock()
    }
  })()

  void (async () => {
    if (!proc.stderr) {
      return
    }
    const reader = proc.stderr.getReader()
    const stderrDecoder = new TextDecoder()
    try {
      for (;;) {
        const { value, done } = await reader.read()
        if (done) {
          break
        }
        if (value) {
          emitOutput(stderrDecoder.decode(value, { stream: true }))
        }
      }
      emitOutput(stderrDecoder.decode())
    } finally {
      reader.releaseLock()
    }
  })()

  void proc.exited.then((code) => {
    const exit = helperExit ?? { code, signal: null }
    for (const listener of exitListeners) {
      listener(exit.code, exit.signal)
    }
  })

  return {
    id: sessionId,
    write,
    resize(cols, rows) {
      sendMessage({ type: "resize", cols: Math.max(cols, 20), rows: Math.max(rows, 10) })
    },
    kill() {
      sendMessage({ type: "kill" })
      setTimeout(() => {
        try {
          proc.kill()
        } catch {
          // Ignore teardown races.
        }
      }, 250)
    },
    onOutput(cb) {
      outputListeners.add(cb)
    },
    onExit(cb) {
      exitListeners.add(cb)
    },
  }
}

export function sanitizeInteractiveOutput(rawChunk: string): string[] {
  const normalizedBackspaces = rawChunk.replace(/.\x08/g, "")
  const normalizedCarriage = normalizedBackspaces.replace(/\r\n/g, "\n").replace(/\r/g, "\n")
  const withCursorSpacing = normalizedCarriage
    .replace(/\x1b\[(\d*)C/g, (_, count: string) => " ".repeat(Math.min(Math.max(Number.parseInt(count || "1", 10), 1), 4)))
    .replace(/\u00a0/g, " ")
  const withoutOsc = withCursorSpacing.replace(/\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)/g, "")
  const withoutAnsi = withoutOsc.replace(/\x1b(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, "")
  const withoutControls = withoutAnsi.replace(/[\x00-\x08\x0B-\x1A\x1C-\x1F\x7F]/g, "")
  return withoutControls
    .split("\n")
    .map((line) => line.trimEnd())
    .filter((line) => line.length > 0)
}

export async function createEmbeddedInteractiveSession(
  run: RunRecord,
  options: { cwd: string; projectId: string },
): Promise<EmbeddedInteractiveSessionPlan> {
  if (!isInteractiveToolchain(run.agentId)) {
    throw new Error(`Interactive session is not available for ${run.agentLabel}`)
  }

  const config = await Config.load(options.cwd)
  const sandboxMode = config?.sandbox ?? "inplace"
  const workcell = await Workcell.acquire(options.projectId, run.agentId, {
    cwd: options.cwd,
    sandboxMode,
  })
  const commandPlan = buildEmbeddedInteractiveSessionCommand(run.agentId, workcell.directory, run.prompt)
  const sessionId = makeSessionId()
  const runtime = createPtyRuntime(
    sessionId,
    commandPlan.command,
    workcell.directory,
    shellEnvForRuntime(sessionId, workcell.directory),
  )

  return {
    sessionId: runtime.id,
    workcell,
    routing: {
      toolchain: run.agentId,
      strategy: "embedded interactive",
      gates: [],
    },
    runtime,
    launchConsumesPrompt: commandPlan.launchConsumesPrompt,
    stagedTaskEditable: commandPlan.stagedTaskEditable,
    cleanup: async () => {
      await Workcell.release(workcell.id, { reset: true })
      if (workcell.directory.includes(".clawdstrike/tmp/")) {
        await rm(workcell.directory, { recursive: true, force: true }).catch(() => {})
      }
    },
  }
}
