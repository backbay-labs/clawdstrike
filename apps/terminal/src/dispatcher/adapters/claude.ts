/**
 * Claude Adapter - Anthropic Claude Code CLI integration
 *
 * Dispatches tasks to Claude Code using OAuth subscription auth.
 * Preserves Claude Pro/Team subscription authentication.
 */

import { $ } from "bun"
import { join } from "path"
import { stat } from "fs/promises"
import { homedir } from "os"
import type { Adapter, AdapterResult } from "../index"
import type { WorkcellInfo, TaskInput } from "../../types"

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

/**
 * Configure Claude adapter
 */
export function configure(newConfig: Partial<ClaudeConfig>): void {
  config = { ...config, ...newConfig }
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
    // Check if `claude` CLI exists
    const which = await $`which claude`.quiet().nothrow()
    if (which.exitCode !== 0) {
      return false
    }

    // Check if auth is configured
    // Claude Code stores OAuth in ~/.claude/
    const configPath = join(homedir(), ".claude", "config.json")
    try {
      await stat(configPath)
      return true
    } catch {
      // Config doesn't exist, check if logged in via other means
      const authCheck = await $`claude auth status`.quiet().nothrow()
      return authCheck.exitCode === 0
    }
  },

  async execute(
    workcell: WorkcellInfo,
    task: TaskInput,
    signal: AbortSignal
  ): Promise<AdapterResult> {
    const startTime = Date.now()

    // Build command arguments
    // Claude Code uses --print for non-interactive single-prompt mode
    const args: string[] = [
      "--print",
      "--output-format", "json",
    ]

    // Add allowed tools whitelist
    if (config.allowedTools && config.allowedTools.length > 0) {
      args.push("--allowedTools", config.allowedTools.join(","))
    }

    // Add model if specified
    if (config.model) {
      args.push("--model", config.model)
    }

    // Add max turns if specified
    if (config.maxTurns) {
      args.push("--max-turns", String(config.maxTurns))
    }

    // Add the prompt as the last argument
    args.push(task.prompt)

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
          output: stdout,
          error: "Execution cancelled",
        }
      }

      if (exitCode !== 0) {
        return {
          success: false,
          output: stdout,
          error: stderr || `Claude exited with code ${exitCode}`,
        }
      }

      // Parse telemetry from output
      const telemetry = this.parseTelemetry(stdout)

      return {
        success: true,
        output: stdout,
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
            const data = JSON.parse(line)
            if (data.usage) {
              return {
                model: data.model,
                tokens: {
                  input: data.usage.input_tokens || 0,
                  output: data.usage.output_tokens || 0,
                },
                cost: data.cost,
              }
            }
          } catch {
            // Not valid JSON, continue
          }
        }
      }

      // Try parsing the entire output as JSON
      try {
        const data = JSON.parse(output)
        if (data.usage) {
          return {
            model: data.model,
            tokens: {
              input: data.usage.input_tokens || 0,
              output: data.usage.output_tokens || 0,
            },
            cost: data.cost,
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
