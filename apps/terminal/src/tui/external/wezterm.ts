import type { ExternalRunSessionPlan, ExternalTerminalAdapter, ExternalTerminalLaunchResult } from "./types"

export function resolveWezTermShell(): string {
  return process.env.SHELL?.trim() || "sh"
}

async function spawnDetached(command: string[]): Promise<ExternalTerminalLaunchResult> {
  const proc = Bun.spawn(command, {
    stdin: "ignore",
    stdout: "ignore",
    stderr: "pipe",
  })

  const launchResult = await Promise.race([
    proc.exited.then((code) => ({ done: true as const, code })),
    Bun.sleep(150).then(() => ({ done: false as const })),
  ])
  if (launchResult.done && launchResult.code !== 0) {
    const errorText = await new Response(proc.stderr).text()
    throw new Error(errorText.trim() || `wezterm exited with code ${launchResult.code}`)
  }

  return { ref: proc.pid ? `wezterm:${proc.pid}` : "wezterm" }
}

export const weztermAdapter: ExternalTerminalAdapter = {
  id: "wezterm",
  label: "WezTerm",
  description: "Launch the interactive run in a new WezTerm window.",
  async isAvailable(): Promise<boolean> {
    return Bun.which("wezterm") !== null
  },
  async launch(plan: ExternalRunSessionPlan): Promise<ExternalTerminalLaunchResult> {
    return spawnDetached([
      "wezterm",
      "start",
      "--cwd",
      plan.workcell.directory,
      resolveWezTermShell(),
      plan.scriptPath,
    ])
  },
}
