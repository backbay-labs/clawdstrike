/**
 * Crush Adapter - Multi-provider fallback execution
 *
 * Provides retry and fallback across multiple providers.
 * Used for unreliable networks or batch jobs.
 */

import { $ } from "bun"
import { join } from "path"
import { mkdir, writeFile } from "fs/promises"
import type { Adapter, AdapterResult } from "../index"
import type { WorkcellInfo, TaskInput } from "../../types"
import { callAnthropicApi, callOpenAiApi } from "./llm-api"

/**
 * Crush configuration
 */
export interface CrushConfig {
  providers?: string[]
  retries?: number
  timeout?: number
  backoffMs?: number
}

const DEFAULT_CONFIG: CrushConfig = {
  providers: ["anthropic", "openai", "google"],
  retries: 3,
  timeout: 300000, // 5 minutes
  backoffMs: 1000,
}

let config: CrushConfig = { ...DEFAULT_CONFIG }

/**
 * Configure Crush adapter
 */
export function configure(newConfig: Partial<CrushConfig>): void {
  config = { ...config, ...newConfig }
}

/**
 * Sleep utility
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Crush adapter implementation (multi-provider fallback)
 */
export const CrushAdapter: Adapter = {
  info: {
    id: "crush",
    name: "Crush (Multi-provider Fallback)",
    description: "Retries across multiple providers with exponential backoff",
    authType: "api_key",
    requiresInstall: true,
  },

  async isAvailable(): Promise<boolean> {
    // Check if `crush` CLI exists
    const which = await $`which crush`.quiet().nothrow()
    if (which.exitCode === 0) {
      return true
    }

    // Crush is also available if we have any API keys for fallback
    const hasAnyKey =
      !!process.env.ANTHROPIC_API_KEY ||
      !!process.env.OPENAI_API_KEY ||
      !!process.env.GOOGLE_API_KEY

    return hasAnyKey
  },

  async execute(
    workcell: WorkcellInfo,
    task: TaskInput,
    signal: AbortSignal
  ): Promise<AdapterResult> {
    const startTime = Date.now()

    // Try CLI first if available
    const cliAvailable = (await $`which crush`.quiet().nothrow()).exitCode === 0

    if (cliAvailable) {
      return executeViaCli(workcell, task, signal, startTime)
    }

    // Fall back to manual retry logic
    return executeWithRetry(workcell, task, signal, startTime)
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
      // Ignore
    }
    return {}
  },
}

/**
 * Execute via crush CLI
 */
async function executeViaCli(
  workcell: WorkcellInfo,
  task: TaskInput,
  signal: AbortSignal,
  startTime: number
): Promise<AdapterResult> {
  const metaDir = join(workcell.directory, ".clawdstrike")
  const promptPath = join(metaDir, "prompt.md")
  await mkdir(metaDir, { recursive: true })
  await writeFile(promptPath, task.prompt)

  const providers = config.providers?.join(",") || "anthropic,openai,google"

  const args: string[] = [
    "--prompt-file", promptPath,
    "--providers", providers,
    "--retries", String(config.retries || 3),
    "--timeout", String((config.timeout || 300000) / 1000),
    "--output", "json",
  ]

  try {
    const proc = Bun.spawn(["crush", ...args], {
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
        error: stderr || `Crush exited with code ${exitCode}`,
      }
    }

    return {
      success: true,
      output: stdout,
      telemetry: {
        ...CrushAdapter.parseTelemetry(stdout),
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
 * Execute with manual retry across providers
 */
async function executeWithRetry(
  workcell: WorkcellInfo,
  task: TaskInput,
  signal: AbortSignal,
  startTime: number
): Promise<AdapterResult> {
  const providers = getAvailableProviders()
  const maxRetries = config.retries || 3
  const backoffMs = config.backoffMs || 1000

  const errors: string[] = []

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    for (const provider of providers) {
      if (signal.aborted) {
        return {
          success: false,
          output: "",
          error: "Execution cancelled",
        }
      }

      try {
        const result = await executeWithProvider(
          provider,
          workcell,
          task,
          signal,
          startTime
        )

        if (result.success) {
          return result
        }

        errors.push(`${provider}: ${result.error}`)
      } catch (error) {
        errors.push(
          `${provider}: ${error instanceof Error ? error.message : String(error)}`
        )
      }
    }

    // Exponential backoff before next retry round
    if (attempt < maxRetries - 1) {
      await sleep(backoffMs * Math.pow(2, attempt))
    }
  }

  return {
    success: false,
    output: "",
    error: `All providers failed after ${maxRetries} attempts:\n${errors.join("\n")}`,
  }
}

/**
 * Get available providers based on configured API keys
 */
function getAvailableProviders(): string[] {
  const available: string[] = []

  if (process.env.ANTHROPIC_API_KEY) {
    available.push("anthropic")
  }
  if (process.env.OPENAI_API_KEY) {
    available.push("openai")
  }
  if (process.env.GOOGLE_API_KEY) {
    available.push("google")
  }

  // Filter by configured providers if set
  if (config.providers && config.providers.length > 0) {
    return config.providers.filter((p) => available.includes(p))
  }

  return available
}

/**
 * Execute with a specific provider
 */
async function executeWithProvider(
  provider: string,
  workcell: WorkcellInfo,
  task: TaskInput,
  signal: AbortSignal,
  startTime: number
): Promise<AdapterResult> {
  switch (provider) {
    case "anthropic":
      return executeAnthropicApi(workcell, task, signal, startTime)
    case "openai":
      return executeOpenAiApi(workcell, task, signal, startTime)
    case "google":
      return executeGoogleApi(workcell, task, signal, startTime)
    default:
      return {
        success: false,
        output: "",
        error: `Unknown provider: ${provider}`,
      }
  }
}

/**
 * Execute via Anthropic API
 */
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
    model: "claude-sonnet-4-20250514",
    systemPrompt: `Working in: ${workcell.directory}`,
    userContent: task.prompt,
    signal,
    startTime,
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
    model: "gpt-4o",
    systemPrompt: `Working in: ${workcell.directory}`,
    userContent: task.prompt,
    signal,
    startTime,
  })
}

/**
 * Execute via Google AI API
 */
async function executeGoogleApi(
  workcell: WorkcellInfo,
  task: TaskInput,
  signal: AbortSignal,
  startTime: number
): Promise<AdapterResult> {
  const apiKey = process.env.GOOGLE_API_KEY
  if (!apiKey) {
    return { success: false, output: "", error: "GOOGLE_API_KEY not set" }
  }

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key=${apiKey}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        contents: [
          {
            role: "user",
            parts: [{ text: `Working in: ${workcell.directory}\n\n${task.prompt}` }],
          },
        ],
        generationConfig: {
          maxOutputTokens: 8192,
        },
      }),
      signal,
    }
  )

  if (!response.ok) {
    return {
      success: false,
      output: "",
      error: `Google API error: ${response.status}`,
    }
  }

  const data = (await response.json()) as {
    candidates?: { content?: { parts?: { text?: string }[] } }[]
    usageMetadata?: { promptTokenCount?: number; candidatesTokenCount?: number }
  }
  const output = data.candidates?.[0]?.content?.parts?.[0]?.text || ""

  return {
    success: true,
    output,
    telemetry: {
      model: "gemini-1.5-pro",
      tokens: data.usageMetadata
        ? {
            input: data.usageMetadata.promptTokenCount || 0,
            output: data.usageMetadata.candidatesTokenCount || 0,
          }
        : undefined,
      startedAt: startTime,
      completedAt: Date.now(),
    },
  }
}

export default CrushAdapter
