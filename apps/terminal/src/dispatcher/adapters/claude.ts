/**
 * Claude Adapter - Anthropic Claude Code CLI integration
 *
 * Dispatches tasks to Claude Code using OAuth subscription auth.
 * Preserves Claude Pro/Team subscription authentication.
 */

import { join } from "path"
import { stat } from "fs/promises"
import type { Adapter, AdapterResult } from "../index"
import type { WorkcellInfo, TaskInput } from "../../types"
import { commandExists, homeDirFromEnv } from "../../system"

/**
 * Claude Code configuration
 */
export interface ClaudeConfig {
  model?: string
  allowedTools?: string[]
  timeout?: number
  maxTurns?: number
}

const DEFAULT_CONFIG: ClaudeConfig = {
  allowedTools: ["Read", "Glob", "Grep", "Edit", "Write", "Bash"],
  timeout: 300000, // 5 minutes
  maxTurns: 50,
}

let config: ClaudeConfig = { ...DEFAULT_CONFIG }

const CLAUDE_AUTH_STATUS_TIMEOUT_MS = 3500

function shouldBypassClaudePermissions(workcell: WorkcellInfo): boolean {
  return workcell.name !== "inplace"
}

function buildClaudeExecArgs(workcell: WorkcellInfo, prompt: string): string[] {
  const args: string[] = [
    "--print",
    "--output-format", "json",
  ]

  if (shouldBypassClaudePermissions(workcell)) {
    args.push("--permission-mode", "bypassPermissions")
  }

  if (config.allowedTools && config.allowedTools.length > 0) {
    args.push("--allowedTools", config.allowedTools.join(","))
  }

  if (config.model) {
    args.push("--model", config.model)
  }

  if (config.maxTurns) {
    args.push("--max-turns", String(config.maxTurns))
  }

  args.push(prompt)
  return args
}

function extractClaudeOutput(output: string): string {
  try {
    const data = JSON.parse(output) as { result?: string }
    if (typeof data.result === "string" && data.result.trim()) {
      return data.result
    }
  } catch {
    // Fall back to the raw CLI output when Claude does not return JSON.
  }

  return output
}

/**
 * Configure Claude adapter
 */
export function configure(newConfig: Partial<ClaudeConfig>): void {
  config = { ...config, ...newConfig }
}

async function checkClaudeAuthStatus(): Promise<boolean> {
  try {
    const proc = Bun.spawn(["claude", "auth", "status"], {
      env: {
        ...process.env,
        CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      },
      stdout: "ignore",
      stderr: "ignore",
    })

    let timedOut = false
    const timeout = setTimeout(() => {
      timedOut = true
      proc.kill()
    }, CLAUDE_AUTH_STATUS_TIMEOUT_MS)

    const exitCode = await proc.exited
    clearTimeout(timeout)
    return !timedOut && exitCode === 0
  } catch {
    return false
  }
}

/**
 * Claude Code adapter implementation
 */
export const ClaudeAdapter: Adapter = {
  info: {
    id: "claude",
    name: "Claude Code",
    description: "Anthropic Claude Code with Pro/Team subscription",
    authType: "oauth",
    requiresInstall: true,
  },

  async isAvailable(): Promise<boolean> {
    if (!commandExists("claude")) {
      return false
    }

    const homeDir = homeDirFromEnv()
    if (!homeDir) {
      return checkClaudeAuthStatus()
    }

    const configPath = join(homeDir, ".claude", "config.json")
    try {
      await stat(configPath)
      return true
    } catch {
      return checkClaudeAuthStatus()
    }
  },

  async execute(
    workcell: WorkcellInfo,
    task: TaskInput,
    signal: AbortSignal
  ): Promise<AdapterResult> {
    const startTime = Date.now()
    const args = buildClaudeExecArgs(workcell, task.prompt)

    try {
      // Execute claude CLI
      const proc = Bun.spawn(["claude", ...args], {
        cwd: workcell.directory,
        env: {
          ...process.env,
          // Claude Code reads OAuth from ~/.claude/
          CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
          // Sandbox markers
          CLAWDSTRIKE_SANDBOX: "1",
          CLAWDSTRIKE_WORKCELL_ROOT: workcell.directory,
          CLAWDSTRIKE_WORKCELL_ID: workcell.id,
        },
        stdout: "pipe",
        stderr: "pipe",
      })

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
          output: extractClaudeOutput(stdout),
          error: "Execution cancelled",
        }
      }

      if (exitCode !== 0) {
        return {
          success: false,
          output: extractClaudeOutput(stdout),
          error: stderr || `Claude exited with code ${exitCode}`,
        }
      }

      // Parse telemetry from output
      const telemetry = this.parseTelemetry(stdout)

      return {
        success: true,
        output: extractClaudeOutput(stdout),
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
      // Claude Code outputs JSON with usage info
      const lines = output.split("\n")
      for (const line of lines) {
        if (line.startsWith("{") && line.includes("usage")) {
          try {
            const data = JSON.parse(line) as {
              model?: string
              cost?: number
              total_cost_usd?: number
              usage?: {
                input_tokens?: number
                output_tokens?: number
              }
              modelUsage?: Record<string, unknown>
            }
            const inferredModel = data.model ?? Object.keys(data.modelUsage ?? {})[0]
            if (data.usage) {
              return {
                model: inferredModel,
                tokens: {
                  input: data.usage.input_tokens || 0,
                  output: data.usage.output_tokens || 0,
                },
                cost: data.total_cost_usd ?? data.cost,
              }
            }
          } catch {
            // Not valid JSON, continue
          }
        }
      }

      // Try parsing the entire output as JSON
      try {
        const data = JSON.parse(output) as {
          model?: string
          cost?: number
          total_cost_usd?: number
          usage?: {
            input_tokens?: number
            output_tokens?: number
          }
          modelUsage?: Record<string, unknown>
        }
        const inferredModel = data.model ?? Object.keys(data.modelUsage ?? {})[0]
        if (data.usage) {
          return {
            model: inferredModel,
            tokens: {
              input: data.usage.input_tokens || 0,
              output: data.usage.output_tokens || 0,
            },
            cost: data.total_cost_usd ?? data.cost,
          }
        }
      } catch {
        // Not JSON
      }
    } catch {
      // Ignore parse errors
    }
    return {}
  },
}

export default ClaudeAdapter
