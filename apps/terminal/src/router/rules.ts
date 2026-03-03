/**
 * Router Rules Engine
 *
 * Evaluates routing rules against tasks and merges actions.
 */

import type { TaskInput, Toolchain } from "../types"
import type { RoutingRule } from "./index"

/**
 * Built-in default rules
 */
export const DEFAULT_RULES: RoutingRule[] = [
  {
    name: "hint-override",
    priority: 1000, // Highest priority - hints always win
    match: { hint: "*" },
    action: {
      // toolchain set dynamically from hint
    },
  },
  {
    name: "high-risk-speculate",
    priority: 100,
    match: { labels: ["dk_risk:high"] },
    action: {
      toolchain: "codex",
      strategy: "speculate",
      speculation: {
        count: 3,
        toolchains: ["codex", "claude", "opencode"],
        voteStrategy: "first_pass",
      },
      gates: ["pytest", "mypy", "ruff"],
      retries: 2,
    },
  },
  {
    name: "medium-risk",
    priority: 80,
    match: { labels: ["dk_risk:medium"] },
    action: {
      toolchain: "claude",
      strategy: "single",
      gates: ["pytest", "mypy"],
      retries: 2,
    },
  },
  {
    name: "small-fast-path",
    priority: 90,
    match: { labels: ["dk_size:xs"] },
    action: {
      toolchain: "opencode",
      strategy: "single",
      gates: ["ruff"],
      retries: 1,
    },
  },
  {
    name: "python-files",
    priority: 50,
    match: { filePatterns: ["**/*.py"] },
    action: {
      gatesAdd: ["mypy", "pytest"],
    },
  },
  {
    name: "typescript-files",
    priority: 50,
    match: { filePatterns: ["**/*.ts", "**/*.tsx"] },
    action: {
      gatesAdd: ["tsc"],
    },
  },
]

/**
 * Check if a rule matches the given task
 */
export function matchesRule(task: TaskInput, rule: RoutingRule): boolean {
  const { match } = rule

  // Check hint match (special case: "*" matches any hint)
  if (match.hint !== undefined) {
    if (match.hint === "*") {
      if (!task.hint) return false
    } else if (task.hint !== match.hint) {
      return false
    }
  }

  // Check label matches (all specified labels must be present)
  if (match.labels && match.labels.length > 0) {
    const taskLabels = task.labels || []
    const hasAllLabels = match.labels.every((label) =>
      taskLabels.includes(label)
    )
    if (!hasAllLabels) return false
  }

  // Check file pattern matches (any pattern match = true)
  if (match.filePatterns && match.filePatterns.length > 0) {
    const files = task.context.files || []
    if (files.length === 0) return false

    const hasMatch = files.some((file) =>
      match.filePatterns!.some((pattern) => matchGlob(file, pattern))
    )
    if (!hasMatch) return false
  }

  // Check prompt pattern matches (any pattern match = true)
  if (match.promptPatterns && match.promptPatterns.length > 0) {
    const hasMatch = match.promptPatterns.some((pattern) => {
      try {
        const regex = new RegExp(pattern, "i")
        return regex.test(task.prompt)
      } catch {
        return task.prompt.includes(pattern)
      }
    })
    if (!hasMatch) return false
  }

  // Check context size
  if (match.contextSize) {
    const promptLength = task.prompt.length
    if (match.contextSize.min !== undefined && promptLength < match.contextSize.min) {
      return false
    }
    if (match.contextSize.max !== undefined && promptLength > match.contextSize.max) {
      return false
    }
  }

  return true
}

/**
 * Simple glob matching (supports * and ** patterns)
 */
function matchGlob(file: string, pattern: string): boolean {
  // Convert glob to regex using placeholders to avoid interference
  let regexPattern = pattern
    .replace(/\./g, "\\.") // Escape dots

  // Use placeholders for complex replacements
  const ANYDIR_OPT = "\x00ANYDIR_OPT\x00" // (?:.*\/)?
  const ANYDIR_MID = "\x00ANYDIR_MID\x00" // (?:\/.*\/|\/)
  const ANYCHAR = "\x00ANYCHAR\x00" // .*

  // Handle **/ at the start specially - it can match zero or more directories
  regexPattern = regexPattern.replace(/^\*\*\//, ANYDIR_OPT)

  // Handle /**/ in the middle - matches any directories
  regexPattern = regexPattern.replace(/\/\*\*\//g, ANYDIR_MID)

  // Handle remaining ** (matches anything)
  regexPattern = regexPattern.replace(/\*\*/g, ANYCHAR)

  // Handle * (matches anything except /)
  regexPattern = regexPattern.replace(/\*/g, "[^/]*")

  // Replace placeholders with actual regex patterns
  regexPattern = regexPattern
    .replace(new RegExp(ANYDIR_OPT.replace(/\x00/g, "\\x00"), "g"), "(?:.*\\/)?")
    .replace(new RegExp(ANYDIR_MID.replace(/\x00/g, "\\x00"), "g"), "(?:\\/.*\\/|\\/)")
    .replace(new RegExp(ANYCHAR.replace(/\x00/g, "\\x00"), "g"), ".*")

  try {
    const regex = new RegExp(`^${regexPattern}$`)
    return regex.test(file)
  } catch {
    return false
  }
}

/**
 * Merge actions from multiple rules, respecting priority order
 */
export function mergeActions(
  actions: Array<{ priority: number; action: RoutingRule["action"] }>
): RoutingRule["action"] {
  // Sort by priority (highest first)
  const sorted = [...actions].sort((a, b) => b.priority - a.priority)

  const merged: RoutingRule["action"] = {}
  const allGates = new Set<string>()
  const gatesToAdd = new Set<string>()
  const gatesToRemove = new Set<string>()

  for (const { action } of sorted) {
    // Lower priority values only fill in missing fields
    if (action.toolchain !== undefined && merged.toolchain === undefined) {
      merged.toolchain = action.toolchain
    }
    if (action.strategy !== undefined && merged.strategy === undefined) {
      merged.strategy = action.strategy
    }
    if (action.speculation !== undefined && merged.speculation === undefined) {
      merged.speculation = action.speculation
    }
    if (action.retries !== undefined && merged.retries === undefined) {
      merged.retries = action.retries
    }

    // Gates accumulate
    if (action.gates) {
      for (const gate of action.gates) {
        allGates.add(gate)
      }
    }
    if (action.gatesAdd) {
      for (const gate of action.gatesAdd) {
        gatesToAdd.add(gate)
      }
    }
    if (action.gatesRemove) {
      for (const gate of action.gatesRemove) {
        gatesToRemove.add(gate)
      }
    }
  }

  // Compute final gates: (explicit gates OR accumulated adds) - removes
  const finalGates = new Set<string>()
  for (const gate of allGates) {
    finalGates.add(gate)
  }
  for (const gate of gatesToAdd) {
    finalGates.add(gate)
  }
  for (const gate of gatesToRemove) {
    finalGates.delete(gate)
  }

  if (finalGates.size > 0) {
    merged.gates = Array.from(finalGates)
  }

  return merged
}

/**
 * Evaluate all rules against a task and return merged action
 */
export function evaluateRules(
  task: TaskInput,
  rules: RoutingRule[]
): RoutingRule["action"] {
  const matchingActions: Array<{ priority: number; action: RoutingRule["action"] }> = []

  for (const rule of rules) {
    if (matchesRule(task, rule)) {
      // Handle hint-override rule specially
      if (rule.name === "hint-override" && task.hint) {
        matchingActions.push({
          priority: rule.priority,
          action: { ...rule.action, toolchain: task.hint },
        })
      } else {
        matchingActions.push({
          priority: rule.priority,
          action: rule.action,
        })
      }
    }
  }

  return mergeActions(matchingActions)
}

/**
 * Validate a toolchain value
 */
export function isValidToolchain(value: string): value is Toolchain {
  return ["codex", "claude", "opencode", "crush"].includes(value)
}
