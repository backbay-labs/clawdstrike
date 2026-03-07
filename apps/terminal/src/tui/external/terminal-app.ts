import type { ExternalRunSessionPlan, ExternalTerminalAdapter, ExternalTerminalLaunchResult } from "./types"

const TERMINAL_WINDOW_REF_PREFIX = "terminal-window:"

function appleScriptQuote(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`
}

async function runAppleScript(script: string): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["osascript", "-e", script], {
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  })
  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ])

  return { exitCode, stdout, stderr }
}

export function makeTerminalWindowRef(windowId: number): string {
  return `${TERMINAL_WINDOW_REF_PREFIX}${windowId}`
}

export function parseTerminalWindowRef(ref: string | null | undefined): number | null {
  if (!ref) {
    return null
  }

  const match = /^terminal-window:(\d+)$/.exec(ref.trim())
  if (!match) {
    return null
  }

  const windowId = Number(match[1])
  return Number.isInteger(windowId) ? windowId : null
}

export function buildTerminalAppLaunchCommand(plan: ExternalRunSessionPlan): string {
  return `cd -- ${shellQuote(plan.workcell.directory)}; exec /bin/zsh ${shellQuote(plan.scriptPath)}`
}

export const terminalAppAdapter: ExternalTerminalAdapter = {
  id: "terminal-app",
  label: "Terminal.app",
  description: "Open the interactive run in a new macOS Terminal.app window.",
  async isAvailable(): Promise<boolean> {
    return process.platform === "darwin" && Bun.which("osascript") !== null
  },
  async launch(plan: ExternalRunSessionPlan): Promise<ExternalTerminalLaunchResult> {
    const command = buildTerminalAppLaunchCommand(plan)
    const { exitCode, stdout, stderr } = await runAppleScript(
      [
        'tell application "Terminal"',
        "activate",
        `set launchedTab to do script "${appleScriptQuote(command)}"`,
        "delay 0.2",
        "return id of front window",
        "end tell",
      ].join("\n"),
    )
    if (exitCode !== 0) {
      throw new Error(stderr.trim() || `osascript exited with code ${exitCode}`)
    }

    const outputText = stdout.trim()
    const windowId = Number(outputText)
    if (!Number.isInteger(windowId)) {
      throw new Error(`Terminal.app did not return a window id: ${outputText || "empty output"}`)
    }

    return { ref: makeTerminalWindowRef(windowId) }
  },
  async focus(ref: string): Promise<void> {
    const windowId = parseTerminalWindowRef(ref)
    const script = windowId
      ? ['tell application "Terminal"', "activate", `set frontmost of window id ${windowId} to true`, "end tell"].join(
          "\n",
        )
      : 'tell application "Terminal" to activate'
    const { exitCode, stderr } = await runAppleScript(script)
    if (exitCode !== 0) {
      throw new Error(stderr.trim() || `osascript exited with code ${exitCode}`)
    }
  },
  async isAlive(ref: string): Promise<boolean> {
    const windowId = parseTerminalWindowRef(ref)
    if (!windowId) {
      return false
    }

    const { exitCode, stdout } = await runAppleScript(
      ['tell application "Terminal"', `return exists window id ${windowId}`, "end tell"].join("\n"),
    )
    return exitCode === 0 && stdout.trim() === "true"
  },
}
