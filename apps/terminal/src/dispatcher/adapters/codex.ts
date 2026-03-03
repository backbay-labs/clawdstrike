/**
 * Codex Adapter - OpenAI Codex CLI integration
 *
 * Dispatches tasks to the Codex CLI using OAuth subscription auth.
 * Preserves ChatGPT Plus/Team/Enterprise subscription authentication.
 */

import { $ } from "bun"
import { join } from "path"
import { mkdir, writeFile } from "fs/promises"
import { homedir } from "os"
import type { Adapter, AdapterResult } from "../index"
import type { WorkcellInfo, TaskInput } from "../../types"

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

/**
 * Configure Codex adapter
 */
export function configure(newConfig: Partial<CodexConfig>): void {
  config = { ...config, ...newConfig }
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
    // Check if `codex` CLI exists
    const which = await $`which codex`.quiet().nothrow()
    if (which.exitCode !== 0) {
      return false
    }

    // Check if auth is configured
    // Codex stores OAuth tokens in ~/.codex/
    const authPath = join(homedir(), ".codex", "auth.json")
    try {
      const authCheck = await $`test -f ${authPath}`.quiet().nothrow()
      if (authCheck.exitCode !== 0) {
        // Try checking via codex auth status
        const statusCheck = await $`codex auth status`.quiet().nothrow()
        return statusCheck.exitCode === 0
      }
      return true
    } catch {
      return false
    }
  },

  async execute(
    workcell: WorkcellInfo,
    task: TaskInput,
    signal: AbortSignal
  ): Promise<AdapterResult> {
    const startTime = Date.now()

    // Write prompt to file (codex prefers file input for long prompts)
    const metaDir = join(workcell.directory, ".clawdstrike")
    const promptPath = join(metaDir, "prompt.md")
    await mkdir(metaDir, { recursive: true })
    await writeFile(promptPath, task.prompt)

    // Build command arguments
    const args: string[] = [
      "run",
      "--format", "json",
      "--approval-mode", config.approvalMode || "suggest",
    ]

    // Add sandbox options if available
    args.push("--writable-root", workcell.directory)

    // Add prompt file
    args.push("--prompt-file", promptPath)

    // Add model if specified
    if (config.model) {
      args.push("--model", config.model)
    }

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
          error: stderr || `Codex exited with code ${exitCode}`,
        }
      }

      // Parse JSON output
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
      // Try to parse JSON output
      const lines = output.split("\n")
      for (const line of lines) {
        if (line.startsWith("{")) {
          try {
            const data = JSON.parse(line)
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
      }
    } catch {
      // Ignore parse errors
    }
    return {}
  },
}

export default CodexAdapter
