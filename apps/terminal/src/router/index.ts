/**
 * Router - Task routing engine
 *
 * Determines how tasks are executed based on configurable rules.
 * Routes tasks to appropriate toolchains with strategies (single/speculate).
 */

import type { TaskInput, RoutingDecision, ExecutionResult, Toolchain } from "../types"
import * as rules from "./rules"

// Re-export rules for external use
export { rules }
export { DEFAULT_RULES } from "./rules"

export interface RouterConfig {
  rules: RoutingRule[]
  defaults: {
    toolchain: Toolchain
    gates: string[]
    retries: number
  }
}

export interface RoutingRule {
  name: string
  priority: number
  match: {
    labels?: string[]
    hint?: string
    filePatterns?: string[]
    promptPatterns?: string[]
    contextSize?: { min?: number; max?: number }
  }
  action: {
    toolchain?: string
    strategy?: "single" | "speculate"
    speculation?: {
      count: number
      toolchains: string[]
      voteStrategy: "first_pass" | "best_score" | "consensus"
    }
    gates?: string[]
    gatesAdd?: string[]
    gatesRemove?: string[]
    retries?: number
  }
}

/**
 * Default router configuration
 */
export const DEFAULT_CONFIG: RouterConfig = {
  rules: rules.DEFAULT_RULES,
  defaults: {
    toolchain: "claude",
    gates: ["pytest", "mypy", "ruff"],
    retries: 2,
  },
}

/**
 * Router namespace - Task routing operations
 */
export namespace Router {
  /**
   * Route a task to determine execution strategy
   */
  export async function route(
    task: TaskInput,
    config: RouterConfig = DEFAULT_CONFIG
  ): Promise<RoutingDecision> {
    // Combine default rules with config rules (config rules take precedence via priority)
    const allRules = [...rules.DEFAULT_RULES, ...config.rules]

    // Evaluate rules to get merged action
    const action = rules.evaluateRules(task, allRules)

    // Determine toolchain (use hint, rule result, or default)
    let toolchain: Toolchain = config.defaults.toolchain
    if (action.toolchain && rules.isValidToolchain(action.toolchain)) {
      toolchain = action.toolchain
    }

    // Determine strategy
    const strategy = action.strategy || "single"

    // Determine gates (use rule result or default)
    const gates = action.gates || config.defaults.gates

    // Determine retries
    const retries = action.retries ?? config.defaults.retries

    // Generate task ID if not provided
    const taskId = task.id || crypto.randomUUID()

    // Build routing decision
    const decision: RoutingDecision = {
      taskId,
      toolchain,
      strategy,
      gates,
      retries,
      priority: 50, // Default priority
    }

    // Add speculation config if strategy is speculate
    if (strategy === "speculate" && action.speculation) {
      decision.speculation = {
        count: action.speculation.count,
        toolchains: action.speculation.toolchains.filter(
          rules.isValidToolchain
        ) as Toolchain[],
        voteStrategy: action.speculation.voteStrategy,
        timeout: 300000, // 5 minute default
      }
    }

    return decision
  }

  /**
   * Re-route after failure with adjusted parameters
   *
   * Uses escalation strategy:
   * 1. Try different toolchain
   * 2. Reduce gate strictness
   * 3. Eventually return null (give up)
   */
  export async function reroute(
    task: TaskInput,
    previousResult: ExecutionResult,
    config: RouterConfig = DEFAULT_CONFIG
  ): Promise<RoutingDecision | null> {
    // Get the original routing decision
    const originalDecision = await route(task, config)

    // Determine what went wrong
    const wasToolchainError =
      previousResult.error?.includes("not available") ||
      previousResult.error?.includes("timeout")
    const wasGateFailure = !previousResult.success && !wasToolchainError

    // Toolchain fallback order
    const toolchainFallback: Toolchain[] = ["codex", "claude", "opencode", "crush"]
    const currentIndex = toolchainFallback.indexOf(previousResult.toolchain)

    if (wasToolchainError && currentIndex < toolchainFallback.length - 1) {
      // Try next toolchain in fallback order
      return {
        ...originalDecision,
        toolchain: toolchainFallback[currentIndex + 1],
        retries: 1, // Reduce retries on fallback
      }
    }

    if (wasGateFailure) {
      // If gates failed, try with reduced gates
      // Remove non-critical gates on first reroute
      const criticalGates = originalDecision.gates.filter(
        (g) => g === "pytest" // Only pytest is always critical
      )

      if (criticalGates.length < originalDecision.gates.length) {
        return {
          ...originalDecision,
          gates: criticalGates,
          retries: 1,
        }
      }
    }

    // Give up - no more rerouting options
    return null
  }

  /**
   * Evaluate rules against task, return merged action
   */
  export function evaluateRules(
    task: TaskInput,
    rulesList: RoutingRule[]
  ): Partial<RoutingRule["action"]> {
    return rules.evaluateRules(task, rulesList)
  }

  /**
   * Check if a rule matches a task
   */
  export function matchesRule(task: TaskInput, rule: RoutingRule): boolean {
    return rules.matchesRule(task, rule)
  }

  /**
   * Get default configuration
   */
  export function getDefaultConfig(): RouterConfig {
    return { ...DEFAULT_CONFIG }
  }
}

export default Router
