import { rm } from "node:fs/promises"
import { Config } from "../config"
import { Workcell } from "../workcell"
import type { Toolchain } from "../types"
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
  prompt: string,
) {
  return buildInteractiveSessionCommand(toolchain, worktreePath, prompt)
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
  const command = buildInteractiveCommand(run.agentId, workcell.directory, run.prompt)
  const ptySessionId = `pty_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`

  return {
    ptySessionId,
    workcell,
    routing: {
      toolchain: run.agentId,
      strategy: "interactive attach",
      gates: [],
    },
    start: () => {
      const proc = Bun.spawn(command, {
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
