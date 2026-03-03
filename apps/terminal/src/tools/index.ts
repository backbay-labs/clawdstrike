/**
 * Tools - Agent tool definitions for ClawdStrike operations
 *
 * Exposes dispatch, speculate, and gate tools for use by OpenCode agents.
 * These tools allow agents to orchestrate other agents and run quality checks.
 */

import type {
  RoutingDecision,
  ExecutionResult,
  GateResults,
  SpeculationResult,
  Toolchain,
  VoteStrategy,
  TaskInput,
  WorkcellInfo,
} from "../types"
import { Router } from "../router"
import { Dispatcher } from "../dispatcher"
import { Verifier } from "../verifier"
import { Speculate } from "../speculate"
import { Workcell } from "../workcell"
import { Telemetry } from "../telemetry"

/**
 * Tool definition interface (compatible with OpenCode/MCP)
 */
export interface ToolDefinition {
  name: string
  description: string
  parameters: {
    type: "object"
    properties: Record<string, unknown>
    required: string[]
  }
  handler: (params: unknown, context?: ToolContext) => Promise<unknown>
}

/**
 * Context passed to tool handlers
 */
export interface ToolContext {
  cwd: string
  projectId: string
  taskId?: string
}

// =============================================================================
// DISPATCH TOOL
// =============================================================================

export interface DispatchParams {
  prompt: string
  toolchain?: Toolchain
  gates?: string[]
  timeout?: number
}

export interface DispatchResult {
  success: boolean
  taskId: string
  routing: RoutingDecision
  result?: ExecutionResult
  verification?: GateResults
  error?: string
}

/**
 * Dispatch tool - Submit task for execution
 */
export const dispatchTool: ToolDefinition = {
  name: "dispatch",
  description: `Submit a coding task for execution by a specialized agent.

Available toolchains:
- codex: OpenAI Codex CLI (GPT-5.2) - best for complex reasoning
- claude: Anthropic Claude Code (Opus) - fast, reliable general purpose
- opencode: Local OpenCode - quick, no network dependency
- crush: Multi-provider fallback - retries across providers

The task runs in an isolated workcell with quality gates.`,
  parameters: {
    type: "object",
    properties: {
      prompt: {
        type: "string",
        description: "The task prompt to execute",
      },
      toolchain: {
        type: "string",
        enum: ["codex", "claude", "opencode", "crush"],
        description:
          "Specific toolchain to use (optional, auto-routed if not specified)",
      },
      gates: {
        type: "array",
        items: { type: "string" },
        description: "Quality gates to run (default: pytest, mypy, ruff)",
      },
      timeout: {
        type: "number",
        description: "Timeout in milliseconds (default: 300000)",
      },
    },
    required: ["prompt"],
  },
  handler: async (
    params: unknown,
    context?: ToolContext
  ): Promise<DispatchResult> => {
    const p = params as DispatchParams
    const ctx = context ?? { cwd: process.cwd(), projectId: "default" }
    const taskId = ctx.taskId ?? crypto.randomUUID()

    // Start telemetry
    const rollout = Telemetry.startRollout(taskId)
    Telemetry.updateStatus(rollout.id, "routing")

    try {
      // Create task input
      const task: TaskInput = {
        id: taskId,
        prompt: p.prompt,
        context: {
          cwd: ctx.cwd,
          projectId: ctx.projectId,
        },
        hint: p.toolchain,
        gates: p.gates,
        timeout: p.timeout,
      }

      // Optional pre-dispatch security check (fail-open)
      try {
        const { Hushd } = await import("../hushd")
        const hushdClient = Hushd.getClient()
        const hushdAvailable = await hushdClient.probe(500)
        if (hushdAvailable) {
          const preCheck = await hushdClient.check({
            action_type: "shell",
            target: p.prompt.slice(0, 200),
            metadata: { source: "dispatch", toolchain: p.toolchain ?? "auto" },
          })
          if (preCheck?.decision === "deny") {
            Telemetry.updateStatus(rollout.id, "failed")
            await Telemetry.completeRollout(rollout.id)
            return {
              success: false,
              taskId,
              routing: { taskId, toolchain: p.toolchain ?? "codex", strategy: "single", gates: [], retries: 0, priority: 50 } as RoutingDecision,
              error: `Security policy denied: ${preCheck.guards.map(g => g.reason ?? g.guard).join(", ")}`,
            }
          }
        }
      } catch {
        // Fail-open: skip security check if hushd unavailable
      }

      // Route the task
      const routing = await Router.route(task)
      Telemetry.setRouting(rollout.id, routing)
      Telemetry.updateStatus(rollout.id, "executing")

      // Load config for sandbox mode
      const { Config } = await import("../config")
      const projectConfig = await Config.load(ctx.cwd)
      const sandboxMode = projectConfig?.sandbox ?? "inplace"

      // Acquire workcell
      let workcell: WorkcellInfo
      try {
        workcell = await Workcell.acquire(ctx.projectId, routing.toolchain, {
          cwd: ctx.cwd,
          sandboxMode,
        })
      } catch (err) {
        const error = err instanceof Error ? err.message : String(err)
        Telemetry.updateStatus(rollout.id, "failed")
        await Telemetry.completeRollout(rollout.id)
        return {
          success: false,
          taskId,
          routing,
          error: error.includes("Not a git repository")
            ? "Not a git repository. Run 'clawdstrike init' or launch the TUI for guided setup."
            : `Failed to acquire workcell: ${error}`,
        }
      }

      // Execute the task
      const result = await Dispatcher.execute({
        task,
        workcell,
        toolchain: routing.toolchain,
        timeout: p.timeout ?? 300000,
      })
      Telemetry.setExecution(rollout.id, result)

      // Run gates if execution succeeded
      let verification: GateResults | undefined
      if (result.success) {
        Telemetry.updateStatus(rollout.id, "verifying")
        verification = await Verifier.run(workcell, {
          gates: routing.gates,
          failFast: true,
        })
        Telemetry.setVerification(rollout.id, verification)
      }

      // Release workcell
      await Workcell.release(workcell.id, { reset: true })

      // Clean up tmpdir workcells
      if (workcell.directory.includes(".clawdstrike/tmp/")) {
        const { rm } = await import("fs/promises")
        await rm(workcell.directory, { recursive: true, force: true }).catch(
          () => {}
        )
      }

      // Complete telemetry
      Telemetry.updateStatus(
        rollout.id,
        result.success && verification?.allPassed ? "completed" : "failed"
      )
      await Telemetry.completeRollout(rollout.id)

      return {
        success: result.success && (verification?.allPassed ?? true),
        taskId,
        routing,
        result,
        verification,
      }
    } catch (err) {
      Telemetry.updateStatus(rollout.id, "failed")
      await Telemetry.completeRollout(rollout.id)
      throw err
    }
  },
}

// =============================================================================
// SPECULATE TOOL
// =============================================================================

export interface SpeculateParams {
  prompt: string
  toolchains?: Toolchain[]
  voteStrategy?: VoteStrategy
  gates?: string[]
  timeout?: number
}

export interface SpeculateToolResult {
  success: boolean
  winner?: {
    toolchain: Toolchain
    score: number
  }
  allResults: Array<{
    toolchain: Toolchain
    passed: boolean
    score: number
    error?: string
  }>
  result?: SpeculationResult
}

/**
 * Speculate tool - Run task with multiple agents in parallel
 */
export const speculateTool: ToolDefinition = {
  name: "speculate",
  description: `Run a task with multiple agents in parallel and select the best result.

Vote strategies:
- first_pass: First result that passes all gates wins (fastest)
- best_score: Highest gate score wins (best quality)
- consensus: Most similar patch wins (most deterministic)

Use for high-risk tasks where reliability is critical.`,
  parameters: {
    type: "object",
    properties: {
      prompt: {
        type: "string",
        description: "The task prompt to execute",
      },
      toolchains: {
        type: "array",
        items: { type: "string", enum: ["codex", "claude", "opencode"] },
        description: "Toolchains to use (default: codex, claude, opencode)",
      },
      voteStrategy: {
        type: "string",
        enum: ["first_pass", "best_score", "consensus"],
        description: "How to select the winner (default: first_pass)",
      },
      gates: {
        type: "array",
        items: { type: "string" },
        description: "Quality gates to run (default: pytest, mypy, ruff)",
      },
      timeout: {
        type: "number",
        description: "Timeout in milliseconds (default: 300000)",
      },
    },
    required: ["prompt"],
  },
  handler: async (
    params: unknown,
    context?: ToolContext
  ): Promise<SpeculateToolResult> => {
    const p = params as SpeculateParams
    const ctx = context ?? { cwd: process.cwd(), projectId: "default" }
    const taskId = ctx.taskId ?? crypto.randomUUID()

    const toolchains: Toolchain[] = p.toolchains ?? ["codex", "claude", "opencode"]
    const voteStrategy: VoteStrategy = p.voteStrategy ?? "first_pass"
    const gates = p.gates ?? ["pytest", "mypy", "ruff"]
    const timeout = p.timeout ?? 300000

    // Create task input
    const task: TaskInput = {
      id: taskId,
      prompt: p.prompt,
      context: {
        cwd: ctx.cwd,
        projectId: ctx.projectId,
      },
      gates,
      timeout,
    }

    // Run speculation
    const result = await Speculate.run({
      task,
      config: {
        count: toolchains.length,
        toolchains,
        voteStrategy,
        timeout,
      },
      gates,
    })

    // Format results
    const allResults = result.allResults.map((r) => ({
      toolchain: r.toolchain,
      passed: r.result?.success ?? false,
      score: r.gateResults?.score ?? 0,
      error: r.error,
    }))

    return {
      success: result.winner !== undefined,
      winner: result.winner
        ? {
            toolchain: result.winner.toolchain,
            score: result.winner.gateResults.score,
          }
        : undefined,
      allResults,
      result,
    }
  },
}

// =============================================================================
// GATE TOOL
// =============================================================================

export interface GateParams {
  gates?: string[]
  failFast?: boolean
  directory?: string
}

export interface GateToolResult {
  success: boolean
  allPassed: boolean
  score: number
  summary: string
  results: Array<{
    gate: string
    passed: boolean
    critical: boolean
    errorCount: number
    warningCount: number
  }>
}

/**
 * Gate tool - Run quality gates on current workspace
 */
export const gateTool: ToolDefinition = {
  name: "gate",
  description: `Run quality gates on the current workspace.

Available gates:
- pytest: Run Python tests
- mypy: Type check Python code
- ruff: Lint and format Python code

Use before committing or after making changes to verify quality.`,
  parameters: {
    type: "object",
    properties: {
      gates: {
        type: "array",
        items: { type: "string" },
        description: "Specific gates to run (default: pytest, mypy, ruff)",
      },
      failFast: {
        type: "boolean",
        description: "Stop on first critical failure (default: true)",
      },
      directory: {
        type: "string",
        description: "Directory to run gates in (default: current directory)",
      },
    },
    required: [],
  },
  handler: async (
    params: unknown,
    context?: ToolContext
  ): Promise<GateToolResult> => {
    const p = params as GateParams
    const ctx = context ?? { cwd: process.cwd(), projectId: "default" }

    const gates = p.gates ?? ["pytest", "mypy", "ruff"]
    const failFast = p.failFast ?? true
    const directory = p.directory ?? ctx.cwd

    // Create a mock workcell for the directory
    const workcell: WorkcellInfo = {
      id: crypto.randomUUID(),
      name: "gate-check",
      directory,
      branch: "main",
      status: "in_use",
      projectId: ctx.projectId,
      createdAt: Date.now(),
      useCount: 0,
    }

    // Run gates
    const results = await Verifier.run(workcell, {
      gates,
      failFast,
    })

    // Format results
    const formattedResults = results.results.map((r) => ({
      gate: r.gate,
      passed: r.passed,
      critical: r.critical,
      errorCount: r.diagnostics?.filter((d) => d.severity === "error").length ?? 0,
      warningCount:
        r.diagnostics?.filter((d) => d.severity === "warning").length ?? 0,
    }))

    return {
      success: results.allPassed,
      allPassed: results.allPassed,
      score: results.score,
      summary: results.summary,
      results: formattedResults,
    }
  },
}

// =============================================================================
// TOOL REGISTRY
// =============================================================================

/**
 * All ClawdStrike tools
 */
export const tools: ToolDefinition[] = [dispatchTool, speculateTool, gateTool]

/**
 * Get tool by name
 */
export function getTool(name: string): ToolDefinition | undefined {
  return tools.find((t) => t.name === name)
}

/**
 * Register tools with an agent system
 */
export function registerTools(register: (tool: ToolDefinition) => void): void {
  for (const tool of tools) {
    register(tool)
  }
}

/**
 * Execute a tool by name
 */
export async function executeTool(
  name: string,
  params: unknown,
  context?: ToolContext
): Promise<unknown> {
  const tool = getTool(name)
  if (!tool) {
    throw new Error(`Unknown tool: ${name}`)
  }
  return tool.handler(params, context)
}

export default tools
