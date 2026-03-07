/**
 * Codex Adapter - OpenAI Codex CLI integration
 *
 * Dispatches tasks to the Codex CLI using OAuth subscription auth.
 * Preserves ChatGPT Plus/Team/Enterprise subscription authentication.
 */

import { join } from "path"
import { stat } from "fs/promises"
import type { Adapter, AdapterResult } from "../index"
import type { WorkcellInfo, TaskInput } from "../../types"
import { commandExists, homeDirFromEnv } from "../../system"

/**
 * Codex CLI configuration
 */
export interface CodexConfig {
  approvalMode?: "suggest" | "auto-edit" | "full-auto"
  model?: string
  timeout?: number
}

const DEFAULT_CONFIG: CodexConfig = {
  approvalMode: "suggest",
  timeout: 300000, // 5 minutes
}

let config: CodexConfig = { ...DEFAULT_CONFIG }
const CODEX_AUTH_STATUS_TIMEOUT_MS = 1500

function buildCodexExecArgs(workcellDir: string): string[] {
  const args = ["-a", "never", "-s", "workspace-write", "exec", "--json", "-C", workcellDir]

  if (config.model) {
    args.push("--model", config.model)
  }

  args.push("-")
  return args
}

function extractCodexOutput(output: string): string {
  const lines = output.split("\n")
  let lastAgentMessage: string | undefined

  for (const line of lines) {
    if (!line.trim().startsWith("{")) {
      continue
    }

    try {
      const data = JSON.parse(line) as {
        type?: string
        item?: {
          type?: string
          text?: string
        }
      }

      if (data.type === "item.completed" && data.item?.type === "agent_message" && data.item.text) {
        lastAgentMessage = data.item.text
      }
    } catch {
      // Ignore malformed event lines.
    }
  }

  return lastAgentMessage ?? output
}

/**
 * Configure Codex adapter
 */
export function configure(newConfig: Partial<CodexConfig>): void {
  config = { ...config, ...newConfig }
}

async function checkCodexAuthStatus(): Promise<boolean> {
  try {
    const proc = Bun.spawn(["codex", "login", "status"], {
      stdout: "ignore",
      stderr: "ignore",
    })

    let timedOut = false
    const timeout = setTimeout(() => {
      timedOut = true
      proc.kill()
    }, CODEX_AUTH_STATUS_TIMEOUT_MS)

    const exitCode = await proc.exited
    clearTimeout(timeout)
    return !timedOut && exitCode === 0
  } catch {
    return false
  }
}

/**
 * Codex CLI adapter implementation
 */
export const CodexAdapter: Adapter = {
  info: {
    id: "codex",
    name: "Codex CLI",
    description: "OpenAI Codex CLI with ChatGPT Plus/Team/Enterprise subscription",
    authType: "oauth",
    requiresInstall: true,
  },

  async isAvailable(): Promise<boolean> {
    if (!commandExists("codex")) {
      return false
    }

    const homeDir = homeDirFromEnv()
    if (!homeDir) {
      return checkCodexAuthStatus()
    }

    const authPath = join(homeDir, ".codex", "auth.json")
    try {
      await stat(authPath)
      return true
    } catch {
      return checkCodexAuthStatus()
    }
  },

  async execute(
    workcell: WorkcellInfo,
    task: TaskInput,
    signal: AbortSignal
  ): Promise<AdapterResult> {
    const startTime = Date.now()
    const args = buildCodexExecArgs(workcell.directory)

    try {
      // Execute codex CLI
      const proc = Bun.spawn(["codex", ...args], {
        cwd: workcell.directory,
        env: {
          ...process.env,
          // Codex reads OAuth from ~/.codex/auth.json
          // No API key needed when using subscription
          CLAWDSTRIKE_SANDBOX: "1",
          CLAWDSTRIKE_WORKCELL_ROOT: workcell.directory,
          CLAWDSTRIKE_WORKCELL_ID: workcell.id,
        },
        stdin: "pipe",
        stdout: "pipe",
        stderr: "pipe",
      })

      proc.stdin.write(task.prompt)
      proc.stdin.end()

      // Handle abort signal
      const abortHandler = () => {
        proc.kill()
      }
      signal.addEventListener("abort", abortHandler)

      // Read output
      const [stdout, stderr] = await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ])
      const exitCode = await proc.exited

      signal.removeEventListener("abort", abortHandler)

      if (signal.aborted) {
        return {
          success: false,
          output: extractCodexOutput(stdout),
          error: "Execution cancelled",
        }
      }

      if (exitCode !== 0) {
        return {
          success: false,
          output: extractCodexOutput(stdout),
          error: stderr || `Codex exited with code ${exitCode}`,
        }
      }

      // Parse JSON output
      const telemetry = this.parseTelemetry(stdout)

      return {
        success: true,
        output: extractCodexOutput(stdout),
        telemetry: {
          ...telemetry,
          startedAt: startTime,
          completedAt: Date.now(),
        },
      }
    } catch (error) {
      return {
        success: false,
        output: "",
        error: error instanceof Error ? error.message : String(error),
      }
    }
  },

  parseTelemetry(output: string): Partial<AdapterResult["telemetry"]> {
    try {
      const lines = output.split("\n")
      for (const line of lines) {
        if (!line.startsWith("{")) {
          continue
        }

        try {
          const data = JSON.parse(line) as {
            model?: string
            cost?: number
            usage?: {
              input_tokens?: number
              prompt_tokens?: number
              output_tokens?: number
              completion_tokens?: number
            }
          }
          if (data.usage || data.model) {
            return {
              model: data.model,
              tokens: data.usage
                ? {
                    input: data.usage.input_tokens || data.usage.prompt_tokens || 0,
                    output: data.usage.output_tokens || data.usage.completion_tokens || 0,
                  }
                : undefined,
              cost: data.cost,
            }
          }
        } catch {
          // Not valid JSON, continue
        }
      }
    } catch {
      // Ignore parse errors
    }
    return {}
  },
}

export default CodexAdapter
