import type { ExternalRunSessionPlan, ExternalTerminalAdapter, ExternalTerminalLaunchResult } from "./types"

function appleScriptQuote(value: string): string {
  return value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")
}

export const terminalAppAdapter: ExternalTerminalAdapter = {
  id: "terminal-app",
  label: "Terminal.app",
  description: "Open the interactive run in a new macOS Terminal.app window.",
  async isAvailable(): Promise<boolean> {
    return process.platform === "darwin" && Bun.which("osascript") !== null
  },
  async launch(plan: ExternalRunSessionPlan): Promise<ExternalTerminalLaunchResult> {
    const command = `cd ${JSON.stringify(plan.workcell.directory)}; /bin/zsh ${JSON.stringify(plan.scriptPath)}`
    const proc = Bun.spawn(
      [
        "osascript",
        "-e",
        `tell application "Terminal" to do script "${appleScriptQuote(command)}"`,
      ],
      {
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
      },
    )
    const exitCode = await proc.exited
    if (exitCode !== 0) {
      const errorText = await new Response(proc.stderr).text()
      throw new Error(errorText.trim() || `osascript exited with code ${exitCode}`)
    }

    return { ref: "terminal-app" }
  },
}
