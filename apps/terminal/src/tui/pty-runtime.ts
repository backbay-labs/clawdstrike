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

type EscapeMode = "none" | "esc" | "csi" | "osc" | "osc_esc"

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value))
}

function trimRightText(value: string): string {
  return value.replace(/\s+$/u, "")
}

export class InteractiveTerminalBuffer {
  private lines: string[][] = [[]]
  private row = 0
  private col = 0
  private cols: number
  private rows: number
  private maxLines: number
  private escapeMode: EscapeMode = "none"
  private csiBuffer = ""
  private oscBuffer = ""
  private savedCursor: { row: number; col: number } | null = null
  private pendingCarriageReturn = false

  constructor(cols = 120, rows = 40, maxLines = 1200) {
    this.cols = Math.max(cols, 20)
    this.rows = Math.max(rows, 8)
    this.maxLines = Math.max(maxLines, this.rows * 4)
  }

  resize(cols: number, rows: number): void {
    this.cols = Math.max(cols, 20)
    this.rows = Math.max(rows, 8)
    this.maxLines = Math.max(this.maxLines, this.rows * 4)
  }

  feed(chunk: string): void {
    for (const ch of chunk) {
      if (this.pendingCarriageReturn && ch !== "\n") {
        this.ensureRow(this.row)
        this.lines[this.row] = []
        this.pendingCarriageReturn = false
      }

      if (this.escapeMode === "osc") {
        if (ch === "\x07") {
          this.escapeMode = "none"
          this.oscBuffer = ""
        } else if (ch === "\x1b") {
          this.escapeMode = "osc_esc"
        } else {
          this.oscBuffer += ch
        }
        continue
      }

      if (this.escapeMode === "osc_esc") {
        if (ch === "\\") {
          this.escapeMode = "none"
          this.oscBuffer = ""
        } else {
          this.escapeMode = "osc"
          this.oscBuffer += ch
        }
        continue
      }

      if (this.escapeMode === "csi") {
        this.csiBuffer += ch
        if (ch >= "@" && ch <= "~") {
          this.handleCsi(this.csiBuffer)
          this.csiBuffer = ""
          this.escapeMode = "none"
        }
        continue
      }

      if (this.escapeMode === "esc") {
        if (ch === "[") {
          this.escapeMode = "csi"
          this.csiBuffer = ""
        } else if (ch === "]") {
          this.escapeMode = "osc"
          this.oscBuffer = ""
        } else {
          this.handleEsc(ch)
          this.escapeMode = "none"
        }
        continue
      }

      if (ch === "\x1b") {
        this.escapeMode = "esc"
        continue
      }

      this.handleChar(ch)
    }
  }

  snapshot(limit = this.maxLines): string[] {
    const trimmedLines = this.lines
      .map((line) => trimRightText(line.join("").replace(/\u00a0/g, " ")))
      .filter((line) => line.length > 0)

    return trimmedLines.slice(Math.max(0, trimmedLines.length - limit))
  }

  private ensureRow(row: number): void {
    while (this.lines.length <= row) {
      this.lines.push([])
    }
  }

  private lineFeed(): void {
    this.row += 1
    this.col = 0
    this.ensureRow(this.row)
    if (this.lines.length > this.maxLines) {
      this.lines.shift()
      this.row = Math.max(0, this.row - 1)
      if (this.savedCursor) {
        this.savedCursor = {
          row: Math.max(0, this.savedCursor.row - 1),
          col: this.savedCursor.col,
        }
      }
    }
  }

  private carriageReturn(): void {
    this.col = 0
    this.pendingCarriageReturn = true
  }

  private writeChar(ch: string): void {
    if (this.col >= this.cols) {
      this.lineFeed()
    }
    this.ensureRow(this.row)
    const line = this.lines[this.row]!
    while (line.length < this.col) {
      line.push(" ")
    }
    line[this.col] = ch
    this.col += 1
  }

  private clearLine(mode: number): void {
    this.ensureRow(this.row)
    const line = this.lines[this.row]!
    if (mode === 1) {
      for (let i = 0; i <= this.col; i++) {
        line[i] = " "
      }
      return
    }
    if (mode === 2) {
      this.lines[this.row] = []
      this.col = 0
      return
    }
    line.length = Math.min(line.length, this.col)
  }

  private clearScreen(mode: number): void {
    if (mode === 2 || mode === 3) {
      this.lines = [[]]
      this.row = 0
      this.col = 0
      return
    }
    if (mode === 1) {
      for (let row = 0; row < this.row; row++) {
        this.lines[row] = []
      }
      this.clearLine(1)
      return
    }
    for (let row = this.row + 1; row < this.lines.length; row++) {
      this.lines[row] = []
    }
    this.clearLine(0)
  }

  private setCursor(row: number, col: number): void {
    this.row = clamp(row, 0, this.maxLines - 1)
    this.col = clamp(col, 0, this.cols - 1)
    this.ensureRow(this.row)
  }

  private moveCursor(rowDelta: number, colDelta: number): void {
    this.setCursor(this.row + rowDelta, this.col + colDelta)
  }

  private handleEsc(ch: string): void {
    if (ch === "7") {
      this.savedCursor = { row: this.row, col: this.col }
      return
    }
    if (ch === "8" && this.savedCursor) {
      this.setCursor(this.savedCursor.row, this.savedCursor.col)
    }
  }

  private handleCsi(sequence: string): void {
    const final = sequence.slice(-1)
    const rawParams = sequence.slice(0, -1)
    const normalized = rawParams.startsWith("?") ? rawParams.slice(1) : rawParams
    const params = normalized.length === 0
      ? []
      : normalized.split(";").map((value) => {
        const parsed = Number.parseInt(value, 10)
        return Number.isFinite(parsed) ? parsed : 0
      })

    switch (final) {
      case "A":
        this.moveCursor(-(params[0] || 1), 0)
        break
      case "B":
        this.moveCursor(params[0] || 1, 0)
        break
      case "C":
        this.moveCursor(0, params[0] || 1)
        break
      case "D":
        this.moveCursor(0, -(params[0] || 1))
        break
      case "E":
        this.setCursor(this.row + (params[0] || 1), 0)
        break
      case "F":
        this.setCursor(this.row - (params[0] || 1), 0)
        break
      case "G":
        this.setCursor(this.row, (params[0] || 1) - 1)
        break
      case "H":
      case "f":
        this.setCursor((params[0] || 1) - 1, (params[1] || 1) - 1)
        break
      case "J":
        this.clearScreen(params[0] || 0)
        break
      case "K":
        this.clearLine(params[0] || 0)
        break
      case "m":
        break
      case "s":
        this.savedCursor = { row: this.row, col: this.col }
        break
      case "u":
        if (this.savedCursor) {
          this.setCursor(this.savedCursor.row, this.savedCursor.col)
        }
        break
      default:
        break
    }
  }

  private handleChar(ch: string): void {
    if (ch === "\r") {
      this.carriageReturn()
      return
    }
    if (ch === "\n") {
      this.pendingCarriageReturn = false
      this.lineFeed()
      return
    }
    if (ch === "\b") {
      this.col = Math.max(0, this.col - 1)
      return
    }
    if (ch === "\t") {
      const remainder = this.col % 4
      const spaces = remainder === 0 ? 4 : 4 - remainder
      for (let i = 0; i < spaces; i++) {
        this.writeChar(" ")
      }
      return
    }
    if (ch < " " || ch === "\x7f") {
      return
    }
    this.writeChar(ch)
  }
}

export function sanitizeInteractiveOutput(rawChunk: string): string[] {
  const buffer = new InteractiveTerminalBuffer()
  buffer.feed(rawChunk)
  return buffer.snapshot()
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
  const commandPlan = buildEmbeddedInteractiveSessionCommand(run.agentId, workcell.directory, {
    sandboxMode,
  })
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
