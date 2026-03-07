import { mkdir, rm, writeFile } from "node:fs/promises"
import { join } from "node:path"
import { Config } from "../../config"
import { Workcell } from "../../workcell"
import type { SandboxMode, Toolchain } from "../../types"
import type { RunRecord } from "../types"
import { buildInteractiveSessionCommand } from "../interactive-command"
import type { ExternalRunSessionPlan } from "./types"
const EXTERNAL_STARTUP_TIMEOUT_MS = 10_000
const EXTERNAL_LIVENESS_TIMEOUT_MS = 15_000
const EXTERNAL_HEARTBEAT_INTERVAL_SECONDS = 2

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`
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

export function buildLaunchScript(
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
    `status_path=${shellQuote(statusPath)}`,
    "mkdir -p \"$(dirname \"$status_path\")\"",
    "started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "__clawdstrike_external_status_written=0",
    `printf '{"state":"starting","startedAt":"%s"}\n' "$started_at" > "$status_path"`,
    "__clawdstrike_external_write_finished() {",
    "  exit_code=$1",
    "  reason=$2",
    "  if [ \"$__clawdstrike_external_status_written\" -eq 0 ]; then",
    `    printf '{"state":"finished","exitCode":%s,"startedAt":"%s","finishedAt":"%s","reason":"%s"}\n' "$exit_code" "$started_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$reason" > "$status_path"`,
    "    __clawdstrike_external_status_written=1",
    "  fi",
    "}",
    `if ! cd ${shellQuote(worktreePath)}; then`,
    "  __clawdstrike_external_write_finished 1 setup",
    "  exit 1",
    "fi",
    "__clawdstrike_external_heartbeat() {",
    "  while true; do",
    `    printf '{"state":"running","startedAt":"%s","heartbeatAt":"%s"}\n' "$started_at" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$status_path"`,
    `    sleep ${EXTERNAL_HEARTBEAT_INTERVAL_SECONDS}`,
    "  done",
    "}",
    "__clawdstrike_external_heartbeat &",
    "heartbeat_pid=$!",
    "__clawdstrike_external_cleanup() {",
    "  if [ -n \"$heartbeat_pid\" ]; then",
    "    kill \"$heartbeat_pid\" 2>/dev/null || true",
    "    wait \"$heartbeat_pid\" 2>/dev/null || true",
    "  fi",
    "}",
    "TRAPEXIT() {",
    "  exit_code=$?",
    "  __clawdstrike_external_cleanup",
    "  __clawdstrike_external_write_finished \"$exit_code\" exit",
    "}",
    "TRAPHUP() {",
    "  __clawdstrike_external_cleanup",
    "  __clawdstrike_external_write_finished 129 hangup",
    "  return 129",
    "}",
    "TRAPINT() {",
    "  __clawdstrike_external_cleanup",
    "  __clawdstrike_external_write_finished 130 interrupted",
    "  return 130",
    "}",
    "TRAPTERM() {",
    "  __clawdstrike_external_cleanup",
    "  __clawdstrike_external_write_finished 143 terminated",
    "  return 143",
    "}",
    `${commandLine}`,
    "exit_code=$?",
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
  const command = buildInteractiveCommand(run.agentId, workcell.directory, sandboxMode)
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
    { mode: 0o700 },
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
    livenessTimeoutMs: EXTERNAL_LIVENESS_TIMEOUT_MS,
    cleanup: async () => {
      await Workcell.release(workcell.id, { reset: true })
      if (workcell.directory.includes(".clawdstrike/tmp/")) {
        await rm(workcell.directory, { recursive: true, force: true }).catch(() => {})
      }
    },
  }
}
