/**
 * Dispatcher - Workcell execution orchestrator
 *
 * Executes tasks in isolated workcells using native CLI adapters.
 * Handles single execution and retry logic.
 */

import type {
  TaskInput,
  ExecutionResult,
  WorkcellInfo,
  Toolchain,
} from "../types"
import * as adaptersModule from "./adapters"
import { git } from "../workcell"

export interface ExecutionRequest {
  task: TaskInput
  workcell: WorkcellInfo
  toolchain: Toolchain
  timeout?: number
}

export interface AdapterResult {
  success: boolean
  output: string
  error?: string
  telemetry?: {
    model?: string
    tokens?: { input: number; output: number }
    cost?: number
    startedAt?: number
    completedAt?: number
  }
}

export interface Adapter {
  info: {
    id: string
    name: string
    description: string
    authType: "oauth" | "api_key" | "none"
    requiresInstall: boolean
  }
  isAvailable(): Promise<boolean>
  execute(
    workcell: WorkcellInfo,
    task: TaskInput,
    signal: AbortSignal
  ): Promise<AdapterResult>
  parseTelemetry(output: string): Partial<AdapterResult["telemetry"]>
}

/**
 * Default execution timeout (5 minutes)
 */
const DEFAULT_TIMEOUT = 300000

/**
 * Sleep utility for retry backoff
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Dispatcher namespace - Task execution operations
 */
export namespace Dispatcher {
  /**
   * Execute task in workcell using specified toolchain
   */
  export async function execute(
    request: ExecutionRequest
  ): Promise<ExecutionResult> {
    const { task, workcell, toolchain, timeout = DEFAULT_TIMEOUT } = request
    const taskId = task.id || crypto.randomUUID()
    const startTime = Date.now()

    // Get adapter for toolchain
    const adapter = adaptersModule.getAdapter(toolchain)
    if (!adapter) {
      return {
        taskId,
        workcellId: workcell.id,
        toolchain,
        success: false,
        output: "",
        error: `No adapter found for toolchain: ${toolchain}`,
        telemetry: {
          startedAt: startTime,
          completedAt: Date.now(),
        },
      }
    }

    // Check if adapter is available
    const available = await adapter.isAvailable()
    if (!available) {
      return {
        taskId,
        workcellId: workcell.id,
        toolchain,
        success: false,
        output: "",
        error: `Adapter ${toolchain} is not available (missing auth or CLI)`,
        telemetry: {
          startedAt: startTime,
          completedAt: Date.now(),
        },
      }
    }

    // Create abort controller with timeout
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), timeout)

    try {
      // Execute via adapter
      const result = await adapter.execute(workcell, task, controller.signal)

      clearTimeout(timeoutId)

      // Get patch (diff) if execution succeeded (skip for inplace workcells)
      let patch: string | undefined
      if (result.success && workcell.name !== "inplace") {
        try {
          patch = await git.getWorktreeDiff(workcell.directory)
        } catch {
          // Ignore diff errors
        }
      }

      return {
        taskId,
        workcellId: workcell.id,
        toolchain,
        success: result.success,
        patch,
        output: result.output,
        error: result.error,
        telemetry: {
          startedAt: result.telemetry?.startedAt || startTime,
          completedAt: result.telemetry?.completedAt || Date.now(),
          model: result.telemetry?.model,
          tokens: result.telemetry?.tokens,
          cost: result.telemetry?.cost,
        },
      }
    } catch (error) {
      clearTimeout(timeoutId)

      const errorMessage =
        error instanceof Error
          ? error.name === "AbortError"
            ? `Execution timed out after ${timeout}ms`
            : error.message
          : String(error)

      return {
        taskId,
        workcellId: workcell.id,
        toolchain,
        success: false,
        output: "",
        error: errorMessage,
        telemetry: {
          startedAt: startTime,
          completedAt: Date.now(),
        },
      }
    }
  }

  /**
   * Execute with automatic retry on transient failures
   */
  export async function executeWithRetry(
    request: ExecutionRequest,
    maxRetries: number = 3
  ): Promise<ExecutionResult> {
    const backoffMs = 1000 // Starting backoff

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      const result = await execute(request)

      if (result.success) {
        return result
      }

      // Check if error is transient (network issues, rate limits)
      const isTransient = isTransientError(result.error)
      if (!isTransient || attempt === maxRetries - 1) {
        return result
      }

      // Exponential backoff before retry
      await sleep(backoffMs * Math.pow(2, attempt))
    }

    // Should not reach here, but satisfy TypeScript
    return execute(request)
  }

  /**
   * Get available adapters (those that pass isAvailable check)
   */
  export async function getAvailableAdapters(): Promise<Adapter[]> {
    return adaptersModule.getAvailableAdapters()
  }

  /**
   * Get adapter by toolchain ID
   */
  export function getAdapter(toolchain: Toolchain): Adapter | undefined {
    return adaptersModule.getAdapter(toolchain)
  }

  /**
   * Get all registered adapters
   */
  export function getAllAdapters(): Adapter[] {
    return adaptersModule.getAllAdapters()
  }
}

/**
 * Check if an error is transient (worth retrying)
 */
function isTransientError(error?: string): boolean {
  if (!error) return false

  const transientPatterns = [
    /timeout/i,
    /rate.?limit/i,
    /too.?many.?requests/i,
    /429/,
    /503/,
    /502/,
    /network/i,
    /connection/i,
    /ECONNRESET/,
    /ETIMEDOUT/,
    /temporarily/i,
  ]

  return transientPatterns.some((pattern) => pattern.test(error))
}

export default Dispatcher
