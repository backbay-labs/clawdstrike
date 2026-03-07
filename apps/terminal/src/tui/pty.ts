import { mkdir, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { Config } from "../config"
import { Workcell } from "../workcell"
import type { SandboxMode, Toolchain } from "../types"
import type { RunRecord } from "./types"
import { buildInteractiveSessionCommand } from "./interactive-command"

export interface AttachRunSession {
  ptySessionId: string
  workcell: Awaited<ReturnType<typeof Workcell.acquire>>
  routing: { toolchain: string; strategy: string; gates: string[] }
  start: () => { exited: Promise<number>; terminate: () => void }
  cleanup: () => Promise<void>
}

function isInteractiveToolchain(toolchain: string): toolchain is Toolchain {
  return toolchain === "claude" || toolchain === "codex"
}

function buildInteractiveCommand(
  toolchain: Toolchain,
  worktreePath: string,
  sandboxMode?: SandboxMode,
) {
  return buildInteractiveSessionCommand(toolchain, worktreePath, { sandboxMode })
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`
}

function attachInstruction(run: RunRecord): string {
  if (run.agentId === "claude") {
    return "Claude interactive sessions start at a blank prompt. Use the staged task below, then press Enter."
  }

  return "The agent is attached to this terminal. Continue the session here and press Ctrl+C to return to ClawdStrike."
}

export function buildAttachLauncherScript(
  run: RunRecord,
  worktreePath: string,
  command: string[],
  stagedTaskPath: string,
): string {
  const commandLine = command.map(shellQuote).join(" ")

  const bannerLines = [
    "ClawdStrike interactive attach",
    `Agent: ${run.agentLabel}`,
    `Mode: ${run.mode} -> attach`,
    `Worktree: ${worktreePath}`,
    "",
    attachInstruction(run),
    "Press Ctrl+C or exit the agent to return to ClawdStrike.",
  ]

  const printBannerLines = bannerLines.map((line) => `print -r -- ${shellQuote(line)}`)

  return [
    "#!/bin/zsh",
    "set +e",
    "printf '\\033[2J\\033[3J\\033[H'",
    ...printBannerLines,
    `staged_task_path=${shellQuote(stagedTaskPath)}`,
    "if [ -s \"$staged_task_path\" ]; then",
    "  print -r -- 'Staged task:'",
    "  while IFS= read -r line || [ -n \"$line\" ]; do",
    "    print -r -- \"  $line\"",
    "  done < \"$staged_task_path\"",
    "else",
    "  print -r -- 'Staged task:'",
    "  print -r -- '  (empty prompt)'",
    "fi",
    "print",
    `exec ${commandLine}`,
  ].join("\n")
}

export async function createAttachRunSession(
  run: RunRecord,
  options: { cwd: string; projectId: string },
): Promise<AttachRunSession> {
  if (!isInteractiveToolchain(run.agentId)) {
    throw new Error(`Interactive attach is not available for ${run.agentLabel}`)
  }

  const config = await Config.load(options.cwd)
  const sandboxMode = config?.sandbox ?? "inplace"
  const workcell = await Workcell.acquire(options.projectId, run.agentId, {
    cwd: options.cwd,
    sandboxMode,
  })
  const command = buildInteractiveCommand(run.agentId, workcell.directory, sandboxMode)
  const ptySessionId = `pty_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`
  const metaDir = join(workcell.directory, ".clawdstrike")
  const scriptPath = join(metaDir, "attach-launch.zsh")
  const stagedTaskPath = join(metaDir, "attach-prompt.txt")

  await mkdir(metaDir, { recursive: true })
  await writeFile(stagedTaskPath, run.prompt, { mode: 0o600 })
  await writeFile(
    scriptPath,
    buildAttachLauncherScript(run, workcell.directory, command, stagedTaskPath),
    { mode: 0o700 },
  )

  return {
    ptySessionId,
    workcell,
    routing: {
      toolchain: run.agentId,
      strategy: "interactive attach",
      gates: [],
    },
    start: () => {
      const proc = Bun.spawn(["/bin/zsh", scriptPath], {
        cwd: workcell.directory,
        env: {
          ...process.env,
          CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
          CLAWDSTRIKE_SANDBOX: "1",
          CLAWDSTRIKE_WORKCELL_ROOT: workcell.directory,
          CLAWDSTRIKE_WORKCELL_ID: workcell.id,
          CLAWDSTRIKE_PTY_SESSION_ID: ptySessionId,
        },
        stdin: "inherit",
        stdout: "inherit",
        stderr: "inherit",
      })

      return {
        exited: proc.exited,
        terminate: () => proc.kill(),
      }
    },
    cleanup: async () => {
      await Workcell.release(workcell.id, { reset: true })
      if (workcell.directory.includes(".clawdstrike/tmp/")) {
        await rm(workcell.directory, { recursive: true, force: true }).catch(() => {})
      }
    },
  }
}
