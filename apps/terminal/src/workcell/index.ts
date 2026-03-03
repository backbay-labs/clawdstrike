/**
 * Workcell - Isolated execution environment manager
 *
 * Manages git worktree-based isolation for task execution.
 * Handles pool lifecycle: create, acquire, release, destroy.
 */

import { z } from "zod"
import { join } from "path"
import { mkdir } from "fs/promises"
import type { WorkcellInfo, Toolchain, SandboxMode } from "../types"
import * as pool from "./pool"
import * as lifecycle from "./lifecycle"
import * as git from "./git"

// Re-export git utilities for external use
export { git }

/**
 * Pool configuration schema
 */
export const PoolConfig = z.object({
  minSize: z.number().int().min(0).max(10).default(2),
  maxSize: z.number().int().min(1).max(50).default(10),
  ttl: z.number().int().positive().default(3600000), // 1 hour
  preWarm: z.boolean().default(true),
  cleanupInterval: z.number().int().positive().default(300000), // 5 min
})

export type PoolConfig = z.infer<typeof PoolConfig>

export interface PoolStatus {
  projectId: string
  total: number
  warm: number
  inUse: number
  config: PoolConfig
}

export interface GCResult {
  destroyed: number
  remaining: number
  duration: number
}

/**
 * Default pool configuration
 */
const DEFAULT_CONFIG: PoolConfig = {
  minSize: 2,
  maxSize: 10,
  ttl: 3600000,
  preWarm: true,
  cleanupInterval: 300000,
}

/**
 * Cached git root per project
 */
const gitRoots: Map<string, string> = new Map()

/**
 * Get git root for a project (with caching)
 */
async function getGitRoot(projectId: string, cwd?: string): Promise<string> {
  let gitRoot = gitRoots.get(projectId)
  if (gitRoot) return gitRoot

  // Use provided cwd or current directory
  const directory = cwd || process.cwd()
  gitRoot = await git.getGitRoot(directory)
  gitRoots.set(projectId, gitRoot)
  return gitRoot
}

/**
 * Workcell namespace - Workcell lifecycle operations
 */
export namespace Workcell {
  /**
   * Initialize a project's workcell pool
   */
  export async function init(
    projectId: string,
    options?: {
      cwd?: string
      config?: Partial<PoolConfig>
    }
  ): Promise<void> {
    const gitRoot = await getGitRoot(projectId, options?.cwd)
    const config = PoolConfig.parse({ ...DEFAULT_CONFIG, ...options?.config })

    pool.initPool(projectId, gitRoot, config)

    // Restore any existing workcells
    await lifecycle.restoreWorkcells(projectId, gitRoot, config)

    // Pre-warm if configured
    if (config.preWarm) {
      await lifecycle.preWarmPool(projectId, gitRoot, config)
    }
  }

  /**
   * Acquire a workcell from the pool (or create new)
   */
  export async function acquire(
    projectId: string,
    toolchain?: Toolchain,
    options?: { cwd?: string; sandboxMode?: SandboxMode }
  ): Promise<WorkcellInfo> {
    const sandboxMode = options?.sandboxMode ?? "worktree"
    const cwd = options?.cwd ?? process.cwd()

    // Inplace mode: return synthetic workcell pointing at cwd
    if (sandboxMode === "inplace") {
      return {
        id: crypto.randomUUID(),
        name: "inplace",
        directory: cwd,
        branch: "HEAD",
        status: "in_use",
        toolchain,
        projectId,
        createdAt: Date.now(),
        useCount: 1,
      }
    }

    // Tmpdir mode: create a temp directory under .clawdstrike/tmp/
    if (sandboxMode === "tmpdir") {
      const id = crypto.randomUUID()
      const shortId = id.slice(0, 8)
      const tmpDir = join(cwd, ".clawdstrike", "tmp", `wc-${shortId}`)
      await mkdir(tmpDir, { recursive: true })
      return {
        id,
        name: `wc-${shortId}`,
        directory: tmpDir,
        branch: "HEAD",
        status: "in_use",
        toolchain,
        projectId,
        createdAt: Date.now(),
        useCount: 1,
      }
    }

    // Worktree mode: existing behavior
    const gitRoot = await getGitRoot(projectId, cwd)
    const config = pool.getPoolConfig(projectId)

    // Ensure pool is initialized
    if (!pool.getPool(projectId)) {
      pool.initPool(projectId, gitRoot, config)
    }

    return lifecycle.acquireWorkcell(projectId, gitRoot, config, toolchain)
  }

  /**
   * Release workcell back to pool (or destroy)
   * No-op for inplace/tmpdir workcells that aren't pooled.
   */
  export async function release(
    workcellId: string,
    options?: { keep?: boolean; reset?: boolean }
  ): Promise<void> {
    const workcell = pool.getWorkcell(workcellId)
    if (!workcell) {
      // Not pooled (inplace/tmpdir) — no-op
      return
    }

    const gitRoot = await getGitRoot(workcell.projectId)
    await lifecycle.releaseWorkcell(workcellId, gitRoot, options)
  }

  /**
   * Get current pool status
   */
  export function status(projectId: string): PoolStatus {
    const poolState = pool.getPool(projectId)
    const counts = pool.countByStatus(projectId)

    return {
      projectId,
      total: counts.total,
      warm: counts.warm,
      inUse: counts.inUse,
      config: poolState?.config || DEFAULT_CONFIG,
    }
  }

  /**
   * Run garbage collection
   */
  export async function gc(projectId?: string): Promise<GCResult> {
    if (projectId) {
      const gitRoot = await getGitRoot(projectId)
      return lifecycle.gcWorkcells(projectId, gitRoot)
    }

    // GC all pools
    let totalDestroyed = 0
    let totalRemaining = 0
    const startTime = Date.now()

    for (const id of pool.getPoolIds()) {
      const gitRoot = await getGitRoot(id)
      const result = await lifecycle.gcWorkcells(id, gitRoot)
      totalDestroyed += result.destroyed
      totalRemaining += result.remaining
    }

    return {
      destroyed: totalDestroyed,
      remaining: totalRemaining,
      duration: Date.now() - startTime,
    }
  }

  /**
   * Destroy all workcells (for shutdown)
   */
  export async function destroyAll(projectId?: string): Promise<void> {
    if (projectId) {
      const gitRoot = await getGitRoot(projectId)
      await lifecycle.destroyAllWorkcells(projectId, gitRoot)
      gitRoots.delete(projectId)
      return
    }

    // Destroy all pools
    for (const id of pool.getPoolIds()) {
      const gitRoot = await getGitRoot(id)
      await lifecycle.destroyAllWorkcells(id, gitRoot)
    }

    gitRoots.clear()
    pool.clearAllPools()
  }

  /**
   * List all workcells
   */
  export function list(projectId?: string): WorkcellInfo[] {
    if (projectId) {
      return pool.getProjectWorkcells(projectId)
    }
    return pool.getAllWorkcells()
  }

  /**
   * Get workcell by ID
   */
  export function get(workcellId: string): WorkcellInfo | undefined {
    return pool.getWorkcell(workcellId)
  }

  /**
   * Configure pool settings
   */
  export function configure(
    projectId: string,
    config: Partial<PoolConfig>
  ): void {
    pool.updatePoolConfig(projectId, config)
  }

  /**
   * Check if workcell has uncommitted changes
   */
  export async function hasChanges(workcellId: string): Promise<boolean> {
    const workcell = pool.getWorkcell(workcellId)
    if (!workcell) {
      throw new Error(`Workcell not found: ${workcellId}`)
    }
    return git.hasChanges(workcell.directory)
  }

  /**
   * Get diff of changes in workcell
   */
  export async function getDiff(workcellId: string): Promise<string> {
    const workcell = pool.getWorkcell(workcellId)
    if (!workcell) {
      throw new Error(`Workcell not found: ${workcellId}`)
    }
    return git.getWorktreeDiff(workcell.directory)
  }

  /**
   * Get list of changed files in workcell
   */
  export async function getChangedFiles(workcellId: string): Promise<string[]> {
    const workcell = pool.getWorkcell(workcellId)
    if (!workcell) {
      throw new Error(`Workcell not found: ${workcellId}`)
    }
    return git.getChangedFiles(workcell.directory)
  }

  /**
   * Reset workcell to clean state
   */
  export async function reset(workcellId: string): Promise<void> {
    const workcell = pool.getWorkcell(workcellId)
    if (!workcell) {
      throw new Error(`Workcell not found: ${workcellId}`)
    }
    await git.resetWorktree(workcell.directory)
  }
}

export default Workcell
