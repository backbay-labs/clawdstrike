/**
 * OpenCode Adapter - Local OpenCode execution
 *
 * Executes tasks using the local OpenCode runtime or direct API calls.
 * Uses API key authentication (not subscription-based).
 */

import { join } from "path"
import { mkdir, writeFile } from "fs/promises"
import type { Adapter, AdapterResult } from "../index"
import type { WorkcellInfo, TaskInput } from "../../types"
import { callAnthropicApi, callOpenAiApi } from "./llm-api"
import { commandExists } from "../../system"

/**
 * OpenCode configuration
 */
export interface OpenCodeConfig {
  model?: string
  provider?: "anthropic" | "openai" | "google"
  timeout?: number
  apiKeyEnvVar?: string
}

const DEFAULT_CONFIG: OpenCodeConfig = {
  provider: "anthropic",
  model: "claude-sonnet-4-20250514",
  timeout: 300000, // 5 minutes
}

let config: OpenCodeConfig = { ...DEFAULT_CONFIG }

/**
 * Configure OpenCode adapter
 */
export function configure(newConfig: Partial<OpenCodeConfig>): void {
  config = { ...config, ...newConfig }
}

/**
 * Check if required API key is set
 */
function hasApiKey(): boolean {
  const provider = config.provider || "anthropic"
  const envVars: Record<string, string> = {
    anthropic: "ANTHROPIC_API_KEY",
    openai: "OPENAI_API_KEY",
    google: "GOOGLE_API_KEY",
  }

  const envVar = config.apiKeyEnvVar || envVars[provider]
  return !!process.env[envVar]
}

/**
 * OpenCode adapter implementation (local execution)
 */
export const OpenCodeAdapter: Adapter = {
  info: {
    id: "opencode",
    name: "OpenCode (Local)",
    description: "Local OpenCode execution with API key auth",
    authType: "api_key",
    requiresInstall: false, // Can run directly via API
  },

  async isAvailable(): Promise<boolean> {
    if (hasApiKey()) {
      return true
    }

    return commandExists("opencode")
  },

  async execute(
    workcell: WorkcellInfo,
    task: TaskInput,
    signal: AbortSignal
  ): Promise<AdapterResult> {
    const startTime = Date.now()

    // Try CLI first if available
    const cliAvailable = commandExists("opencode")

    if (cliAvailable) {
      return executeViaCli(workcell, task, signal, startTime)
    }

    // Fall back to direct API execution
    if (hasApiKey()) {
      return executeViaApi(workcell, task, signal, startTime)
    }

    return {
      success: false,
      output: "",
      error: "No API key configured and opencode CLI not found",
    }
  },

  parseTelemetry(output: string): Partial<AdapterResult["telemetry"]> {
    try {
      const data = JSON.parse(output)
      if (data.usage) {
        return {
          model: data.model,
          tokens: {
            input: data.usage.input_tokens || data.usage.prompt_tokens || 0,
            output: data.usage.output_tokens || data.usage.completion_tokens || 0,
          },
          cost: data.cost,
        }
      }
    } catch {
      // Try line-by-line parsing
      const lines = output.split("\n")
      for (const line of lines) {
        if (line.startsWith("{")) {
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
            // Continue
          }
        }
      }
    }
    return {}
  },
}

/**
 * Execute via opencode CLI
 */
async function executeViaCli(
  workcell: WorkcellInfo,
  task: TaskInput,
  signal: AbortSignal,
  startTime: number
): Promise<AdapterResult> {
  // Write prompt to file
  const metaDir = join(workcell.directory, ".clawdstrike")
  const promptPath = join(metaDir, "prompt.md")
  await mkdir(metaDir, { recursive: true })
  await writeFile(promptPath, task.prompt)

  const args: string[] = [
    "run",
    "--cwd", workcell.directory,
    "--prompt-file", promptPath,
    "--output", "json",
  ]

  if (config.model) {
    args.push("--model", config.model)
  }

  try {
    const proc = Bun.spawn(["opencode", ...args], {
      cwd: workcell.directory,
      env: {
        ...process.env,
        CLAWDSTRIKE_SANDBOX: "1",
        CLAWDSTRIKE_WORKCELL_ROOT: workcell.directory,
        CLAWDSTRIKE_WORKCELL_ID: workcell.id,
      },
      stdout: "pipe",
      stderr: "pipe",
    })

    const abortHandler = () => proc.kill()
    signal.addEventListener("abort", abortHandler)

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
        error: stderr || `OpenCode exited with code ${exitCode}`,
      }
    }

    return {
      success: true,
      output: stdout,
      telemetry: {
        ...OpenCodeAdapter.parseTelemetry(stdout),
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
}

/**
 * Execute via direct API call (simplified version)
 */
async function executeViaApi(
  workcell: WorkcellInfo,
  task: TaskInput,
  signal: AbortSignal,
  startTime: number
): Promise<AdapterResult> {
  const provider = config.provider || "anthropic"

  try {
    if (provider === "anthropic") {
      return await executeAnthropicApi(workcell, task, signal, startTime)
    } else if (provider === "openai") {
      return await executeOpenAiApi(workcell, task, signal, startTime)
    } else {
      return {
        success: false,
        output: "",
        error: `Unsupported provider: ${provider}`,
      }
    }
  } catch (error) {
    return {
      success: false,
      output: "",
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

/**
 * Execute via Anthropic API
 */
function buildSystemPrompt(workcell: WorkcellInfo, task: TaskInput): string {
  return `You are an AI coding assistant working in directory: ${workcell.directory}
Project: ${task.context.projectId}
Branch: ${workcell.branch}

Execute the following task and provide your response.`
}

async function executeAnthropicApi(
  workcell: WorkcellInfo,
  task: TaskInput,
  signal: AbortSignal,
  startTime: number
): Promise<AdapterResult> {
  const apiKey = process.env.ANTHROPIC_API_KEY
  if (!apiKey) {
    return { success: false, output: "", error: "ANTHROPIC_API_KEY not set" }
  }

  return callAnthropicApi({
    apiKey,
    model: config.model || "claude-sonnet-4-20250514",
    systemPrompt: buildSystemPrompt(workcell, task),
    userContent: task.prompt,
    signal,
    startTime,
    includeErrorBody: true,
  })
}

/**
 * Execute via OpenAI API
 */
async function executeOpenAiApi(
  workcell: WorkcellInfo,
  task: TaskInput,
  signal: AbortSignal,
  startTime: number
): Promise<AdapterResult> {
  const apiKey = process.env.OPENAI_API_KEY
  if (!apiKey) {
    return { success: false, output: "", error: "OPENAI_API_KEY not set" }
  }

  return callOpenAiApi({
    apiKey,
    model: config.model || "gpt-4o",
    systemPrompt: buildSystemPrompt(workcell, task),
    userContent: task.prompt,
    signal,
    startTime,
    includeErrorBody: true,
  })
}

export default OpenCodeAdapter
