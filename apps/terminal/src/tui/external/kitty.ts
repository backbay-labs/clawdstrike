import type { ExternalRunSessionPlan, ExternalTerminalAdapter, ExternalTerminalLaunchResult } from "./types"

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
    throw new Error(errorText.trim() || `kitty exited with code ${launchResult.code}`)
  }

  return { ref: proc.pid ? `kitty:${proc.pid}` : "kitty" }
}

export const kittyAdapter: ExternalTerminalAdapter = {
  id: "kitty",
  label: "Kitty",
  description: "Launch the interactive run in a new Kitty window.",
  async isAvailable(): Promise<boolean> {
    return Bun.which("kitty") !== null
  },
  async launch(plan: ExternalRunSessionPlan): Promise<ExternalTerminalLaunchResult> {
    return spawnDetached([
      "kitty",
      "--directory",
      plan.workcell.directory,
      "/bin/zsh",
      plan.scriptPath,
    ])
  },
}
