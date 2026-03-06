import { mkdir, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { Config } from "../../config"
import { Workcell } from "../../workcell"
import type { Toolchain } from "../../types"
import type { RunRecord } from "../types"
import type { ExternalRunSessionPlan } from "./types"

const CLAUDE_ALLOWED_TOOLS = ["Read", "Glob", "Grep", "Edit", "Write", "Bash"]
const EXTERNAL_STARTUP_TIMEOUT_MS = 10_000

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`
}

function isInteractiveToolchain(toolchain: string): toolchain is Toolchain {
  return toolchain === "claude" || toolchain === "codex"
}

async function buildInteractiveCommand(
  toolchain: Toolchain,
  worktreePath: string,
  prompt: string,
): Promise<string[]> {
  if (toolchain === "codex") {
    const metaDir = join(worktreePath, ".clawdstrike")
    const promptPath = join(metaDir, "prompt.md")
    await mkdir(metaDir, { recursive: true })
    await writeFile(promptPath, prompt)
    return [
      "codex",
      "--approval-mode",
      "suggest",
      "--writable-root",
      worktreePath,
      "--prompt-file",
      promptPath,
    ]
  }

  if (toolchain === "claude") {
    return [
      "claude",
      "--allowedTools",
      CLAUDE_ALLOWED_TOOLS.join(","),
      prompt,
    ]
  }

  throw new Error(`External execution is not available for ${toolchain}`)
}

function buildLaunchScript(
  worktreePath: string,
  command: string[],
  env: Record<string, string>,
  statusPath: string,
): string {
  const envLines = Object.entries(env).map(([key, value]) => `export ${key}=${shellQuote(value)}`)
  const commandLine = command.map(shellQuote).join(" ")
  return [
    "#!/bin/zsh",
    "set +e",
    ...envLines,
    "mkdir -p \"$(dirname " + shellQuote(statusPath) + ")\"",
    `printf '{"state":"starting","startedAt":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > ${shellQuote(statusPath)}`,
    `cd ${shellQuote(worktreePath)} || exit 1`,
    `${commandLine}`,
    "exit_code=$?",
    `printf '{"state":"finished","exitCode":%s,"finishedAt":"%s"}\n' "$exit_code" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > ${shellQuote(statusPath)}`,
    "exit \"$exit_code\"",
  ].join("\n")
}

export async function createExternalRunSession(
  run: RunRecord,
  options: { cwd: string; projectId: string },
): Promise<ExternalRunSessionPlan> {
  if (!isInteractiveToolchain(run.agentId)) {
    throw new Error(`External execution is not available for ${run.agentLabel}`)
  }

  const config = await Config.load(options.cwd)
  const sandboxMode = config?.sandbox ?? "inplace"
  const workcell = await Workcell.acquire(options.projectId, run.agentId, {
    cwd: options.cwd,
    sandboxMode,
  })
  const command = await buildInteractiveCommand(run.agentId, workcell.directory, run.prompt)
  const ptySessionId = `pty_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`
  const metaDir = join(workcell.directory, ".clawdstrike")
  const scriptPath = join(metaDir, "external-launch.zsh")
  const statusPath = join(metaDir, "external-status.json")

  await mkdir(metaDir, { recursive: true })
  await writeFile(
    scriptPath,
    buildLaunchScript(
      workcell.directory,
      command,
      {
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
        CLAWDSTRIKE_SANDBOX: "1",
        CLAWDSTRIKE_WORKCELL_ROOT: workcell.directory,
        CLAWDSTRIKE_WORKCELL_ID: workcell.id,
        CLAWDSTRIKE_PTY_SESSION_ID: ptySessionId,
      },
      statusPath,
    ),
    { mode: 0o755 },
  )

  return {
    ptySessionId,
    workcell,
    routing: {
      toolchain: run.agentId,
      strategy: "external terminal",
      gates: [],
    },
    scriptPath,
    statusPath,
    startupTimeoutMs: EXTERNAL_STARTUP_TIMEOUT_MS,
    cleanup: async () => {
      await Workcell.release(workcell.id, { reset: true })
      if (workcell.directory.includes(".clawdstrike/tmp/")) {
        await rm(workcell.directory, { recursive: true, force: true }).catch(() => {})
      }
    },
  }
}
