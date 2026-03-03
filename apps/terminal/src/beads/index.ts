/**
 * Beads - Work graph integration
 *
 * Manages integration with the Beads work graph (issues.jsonl).
 * Handles issue queries, status updates, and dependency tracking.
 */

import type { Bead, BeadId, BeadStatus, BeadPriority } from "../types"
import { JSONL } from "./jsonl"

export { JSONL } from "./jsonl"

export interface BeadsConfig {
  path: string // Path to .beads directory
  autoSync?: boolean
}

export interface QueryOptions {
  status?: BeadStatus | BeadStatus[]
  priority?: BeadPriority | BeadPriority[]
  labels?: string[]
  assignee?: string
  limit?: number
  offset?: number
}

export interface ReadyIssue extends Bead {
  reasoning: string
  suggestedToolchain?: string
}

// Module state
let config: BeadsConfig | null = null

/**
 * Beads namespace - Work graph operations
 */
export namespace Beads {
  /**
   * Initialize Beads connection
   */
  export async function init(cfg: BeadsConfig): Promise<void> {
    config = cfg
    await JSONL.init(cfg.path)
  }

  /**
   * Get current config (throws if not initialized)
   */
  function getConfig(): BeadsConfig {
    if (!config) {
      throw new Error("Beads not initialized. Call Beads.init() first.")
    }
    return config
  }

  /**
   * Query issues from work graph
   */
  export async function query(options?: QueryOptions): Promise<Bead[]> {
    const cfg = getConfig()
    let issues = await JSONL.read(cfg.path)

    // Apply filters
    if (options?.status) {
      const statuses = Array.isArray(options.status)
        ? options.status
        : [options.status]
      issues = issues.filter((i) => statuses.includes(i.status))
    }

    if (options?.priority) {
      const priorities = Array.isArray(options.priority)
        ? options.priority
        : [options.priority]
      issues = issues.filter((i) => i.priority && priorities.includes(i.priority))
    }

    if (options?.labels && options.labels.length > 0) {
      issues = issues.filter((i) =>
        options.labels!.some((label) => i.labels?.includes(label))
      )
    }

    if (options?.assignee) {
      issues = issues.filter((i) => i.assignee === options.assignee)
    }

    // Apply pagination
    if (options?.offset) {
      issues = issues.slice(options.offset)
    }

    if (options?.limit) {
      issues = issues.slice(0, options.limit)
    }

    return issues
  }

  /**
   * Get issues ready for execution (status: "open", no blocking deps)
   */
  export async function getReady(): Promise<ReadyIssue[]> {
    const cfg = getConfig()
    const issues = await JSONL.read(cfg.path)

    // Get all open issues
    const openIssues = issues.filter((i) => i.status === "open")

    // For now, all open issues are considered ready
    // In a full implementation, we'd check dependencies in deps.jsonl
    return openIssues.map((issue) => ({
      ...issue,
      reasoning: `Issue ${issue.id} is open and has no blocking dependencies`,
      suggestedToolchain: inferToolchain(issue),
    }))
  }

  /**
   * Get single issue by ID
   */
  export async function get(id: BeadId): Promise<Bead | undefined> {
    const cfg = getConfig()
    const issues = await JSONL.read(cfg.path)
    return issues.find((i) => i.id === id)
  }

  /**
   * Create new issue
   */
  export async function create(
    issue: Omit<Bead, "id" | "createdAt" | "updatedAt">
  ): Promise<Bead> {
    const cfg = getConfig()
    const issues = await JSONL.read(cfg.path)

    // Generate new ID (find max number and increment)
    const prefix = extractPrefix(issues)
    const maxNum = issues.reduce((max, i) => {
      const num = parseInt(i.id.split("-")[1], 10)
      return num > max ? num : max
    }, 0)

    const newBead: Bead = {
      ...issue,
      id: `${prefix}-${maxNum + 1}` as BeadId,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    }

    await JSONL.append(cfg.path, newBead)
    return newBead
  }

  /**
   * Update issue status
   */
  export async function updateStatus(
    id: BeadId,
    status: BeadStatus
  ): Promise<Bead> {
    const cfg = getConfig()

    return JSONL.update(cfg.path, id, (issue) => ({
      ...issue,
      status,
      closedAt: status === "completed" || status === "cancelled" ? Date.now() : issue.closedAt,
    }))
  }

  /**
   * Update issue
   */
  export async function update(
    id: BeadId,
    updates: Partial<Bead>
  ): Promise<Bead> {
    const cfg = getConfig()

    return JSONL.update(cfg.path, id, (issue) => ({
      ...issue,
      ...updates,
      id: issue.id, // Prevent ID changes
      createdAt: issue.createdAt, // Prevent createdAt changes
    }))
  }

  /**
   * Get dependencies for an issue
   * Note: In a full implementation, this would read from deps.jsonl
   */
  export async function getDependencies(_id: BeadId): Promise<Bead[]> {
    // STUB: Would read from .beads/deps.jsonl
    return []
  }

  /**
   * Get dependents (issues that depend on this one)
   * Note: In a full implementation, this would read from deps.jsonl
   */
  export async function getDependents(_id: BeadId): Promise<Bead[]> {
    // STUB: Would read from .beads/deps.jsonl
    return []
  }

  /**
   * Sync with external source (if configured)
   * Note: This is a placeholder for GitHub/Linear sync
   */
  export async function sync(): Promise<void> {
    const cfg = getConfig()
    if (cfg.autoSync) {
      // STUB: Would sync with external provider
      console.log("Beads sync not implemented")
    }
  }

  /**
   * Check if Beads is initialized
   */
  export function isInitialized(): boolean {
    return config !== null
  }

  /**
   * Reset Beads state (mainly for testing)
   */
  export function reset(): void {
    config = null
  }
}

/**
 * Extract project prefix from existing issues
 */
function extractPrefix(issues: Bead[]): string {
  if (issues.length === 0) {
    return "PROJ"
  }
  return issues[0].id.split("-")[0]
}

/**
 * Infer suggested toolchain from issue labels/content
 */
function inferToolchain(issue: Bead): string | undefined {
  const labels = issue.labels || []

  // Check for explicit hints
  const hintLabel = labels.find((l) => l.startsWith("dk_tool_hint:"))
  if (hintLabel) {
    return hintLabel.split(":")[1]
  }

  // Check for risk level
  if (labels.includes("dk_risk:high")) {
    return "codex"
  }

  // Check for size
  if (labels.includes("dk_size:xs") || labels.includes("dk_size:s")) {
    return "opencode"
  }

  return undefined
}

export default Beads
