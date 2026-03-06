import type { ExternalRunSessionPlan, ExternalTerminalAdapter, ExternalTerminalLaunchResult } from "./types"

export interface TmuxAvailability {
  available: boolean
  sessionId: string | null
  reason: string | null
}

export interface TmuxCommandRunner {
  (args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }>
}

function quoteShell(value: string): string {
  if (value.length === 0) {
    return "''"
  }

  return `'${value.replace(/'/g, `'\"'\"'`)}'`
}

async function runTmuxCommand(args: string[]): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const proc = Bun.spawn(["tmux", ...args], {
    env: process.env,
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

export function hasTmuxAdapter(
  env: NodeJS.ProcessEnv = process.env,
  whichFn: (cmd: string) => string | null = Bun.which,
): boolean {
  return Boolean(env.TMUX) && Boolean(whichFn("tmux"))
}

export async function detectTmuxAvailability(
  env: NodeJS.ProcessEnv = process.env,
  whichFn: (cmd: string) => string | null = Bun.which,
  runCommand: TmuxCommandRunner = runTmuxCommand,
): Promise<TmuxAvailability> {
  if (!env.TMUX) {
    return { available: false, sessionId: null, reason: "tmux adapters are only available inside an active tmux client." }
  }

  if (!whichFn("tmux")) {
    return { available: false, sessionId: null, reason: "The tmux binary is not installed on this system." }
  }

  const session = await runCommand(["display-message", "-p", "#{session_id}"])
  if (session.exitCode !== 0) {
    return {
      available: false,
      sessionId: null,
      reason: session.stderr.trim() || "Unable to query the active tmux session.",
    }
  }

  return {
    available: true,
    sessionId: session.stdout.trim() || null,
    reason: null,
  }
}

async function resolveTmuxContext(
  env: NodeJS.ProcessEnv = process.env,
  whichFn: (cmd: string) => string | null = Bun.which,
  runCommand: TmuxCommandRunner = runTmuxCommand,
): Promise<{ sessionId: string | null }> {
  const availability = await detectTmuxAvailability(env, whichFn, runCommand)
  if (!availability.available) {
    throw new Error(availability.reason ?? "tmux is unavailable.")
  }

  return { sessionId: availability.sessionId }
}

export function buildTmuxLaunchCommand(
  adapterId: "tmux-split" | "tmux-window",
  context: { sessionId: string | null },
  plan: ExternalRunSessionPlan,
): string[] {
  const commandText = ["/bin/zsh", plan.scriptPath].map(quoteShell).join(" ")
  if (adapterId === "tmux-split") {
    return [
      "split-window",
      "-P",
      "-F",
      "#{pane_id}",
      ...(context.sessionId ? ["-t", context.sessionId] : []),
      "-c",
      plan.workcell.directory,
      commandText,
    ]
  }

  return [
    "new-window",
    "-P",
    "-F",
    "#{window_id}",
    ...(context.sessionId ? ["-t", context.sessionId] : []),
    "-n",
    `clawdstrike-${plan.workcell.id.slice(0, 8)}`,
    "-c",
    plan.workcell.directory,
    commandText,
  ]
}

export async function launchInTmux(
  adapterId: "tmux-split" | "tmux-window",
  plan: ExternalRunSessionPlan,
  runCommand: TmuxCommandRunner = runTmuxCommand,
): Promise<ExternalTerminalLaunchResult> {
  const context = await resolveTmuxContext(process.env, Bun.which, runCommand)
  const result = await runCommand(buildTmuxLaunchCommand(adapterId, context, plan))
  if (result.exitCode !== 0) {
    throw new Error(result.stderr.trim() || "tmux failed to open an external run surface.")
  }

  return {
    ref: result.stdout.trim() || null,
  }
}

export async function focusTmuxSurface(
  kind: "tmux-split" | "tmux-window",
  ref: string,
  runCommand: TmuxCommandRunner = runTmuxCommand,
): Promise<void> {
  const args = kind === "tmux-split" ? ["select-pane", "-t", ref] : ["select-window", "-t", ref]
  const result = await runCommand(args)
  if (result.exitCode !== 0) {
    throw new Error(result.stderr.trim() || "tmux failed to reopen the external run surface.")
  }
}

export async function isTmuxSurfaceAlive(
  kind: "tmux-split" | "tmux-window",
  ref: string,
  runCommand: TmuxCommandRunner = runTmuxCommand,
): Promise<boolean> {
  const format = kind === "tmux-split" ? "#{pane_id}" : "#{window_id}"
  const result = await runCommand(["display-message", "-p", "-t", ref, format])
  return result.exitCode === 0 && result.stdout.trim().length > 0
}

export const tmuxSplitAdapter: ExternalTerminalAdapter = {
  id: "tmux-split",
  label: "tmux split",
  description: "Open the run in a new tmux split in the active session.",
  async isAvailable(): Promise<boolean> {
    try {
      await resolveTmuxContext()
      return true
    } catch {
      return false
    }
  },
  async launch(plan: ExternalRunSessionPlan): Promise<ExternalTerminalLaunchResult> {
    return launchInTmux("tmux-split", plan)
  },
  async focus(ref: string): Promise<void> {
    await focusTmuxSurface("tmux-split", ref)
  },
  async isAlive(ref: string): Promise<boolean> {
    return isTmuxSurfaceAlive("tmux-split", ref)
  },
}

export const tmuxWindowAdapter: ExternalTerminalAdapter = {
  id: "tmux-window",
  label: "tmux window",
  description: "Open the run in a new tmux window in the active session.",
  async isAvailable(): Promise<boolean> {
    try {
      await resolveTmuxContext()
      return true
    } catch {
      return false
    }
  },
  async launch(plan: ExternalRunSessionPlan): Promise<ExternalTerminalLaunchResult> {
    return launchInTmux("tmux-window", plan)
  },
  async focus(ref: string): Promise<void> {
    await focusTmuxSurface("tmux-window", ref)
  },
  async isAlive(ref: string): Promise<boolean> {
    return isTmuxSurfaceAlive("tmux-window", ref)
  },
}
