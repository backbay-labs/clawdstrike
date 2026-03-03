/**
 * Workcell Lifecycle Management
 *
 * Handles creation, cleanup, and state transitions for workcells.
 */

import { randomUUID } from "crypto"
import { join } from "path"
import { mkdir, rm, writeFile, readFile } from "fs/promises"
import type { WorkcellInfo, Toolchain, WorkcellStatus } from "../types"
import type { PoolConfig } from "./index"
import * as git from "./git"
import * as pool from "./pool"

/**
 * Workcell metadata file name
 */
const METADATA_FILE = ".clawdstrike-workcell.json"

/**
 * Generate a unique workcell name
 */
function generateWorkcellName(index: number): string {
  const timestamp = Date.now().toString(36)
  return `wc-${timestamp}-${index}`
}

/**
 * Create a new workcell
 */
export async function createWorkcell(
  projectId: string,
  gitRoot: string,
  options: {
    toolchain?: Toolchain
    branch?: string
  } = {}
): Promise<WorkcellInfo> {
  const workcellId = randomUUID()
  const workcellsDir = git.getWorkcellsDir(gitRoot)
  const index = pool.countByStatus(projectId).total + 1
  const name = generateWorkcellName(index)
  const workcellPath = join(workcellsDir, name)

  // Get base branch
  const baseBranch = options.branch || (await git.getCurrentBranch(gitRoot))

  // Create workcell info (status: creating)
  const workcell: WorkcellInfo = {
    id: workcellId,
    name,
    directory: workcellPath,
    branch: baseBranch,
    status: "creating",
    toolchain: options.toolchain,
    projectId,
    createdAt: Date.now(),
    useCount: 0,
  }

  // Add to pool immediately to track creation
  pool.addToPool(workcell)

  try {
    // Create worktree with detached HEAD at current commit
    const commit = await git.getCurrentCommit(gitRoot)
    await git.createWorktree(gitRoot, workcellPath, {
      commit,
      detach: true,
    })

    // Create .clawdstrike directory in workcell
    const metaDir = join(workcellPath, ".clawdstrike")
    await mkdir(metaDir, { recursive: true })

    // Write metadata
    await writeMetadata(workcellPath, workcell)

    // Update status to warm
    workcell.status = "warm"
    pool.updateWorkcell(workcell)

    return workcell
  } catch (error) {
    // Remove from pool on failure
    pool.removeFromPool(workcellId)

    // Try to clean up the partially created worktree
    try {
      await git.removeWorktree(gitRoot, workcellPath, { force: true })
    } catch {
      // Ignore cleanup errors
    }

    throw error
  }
}

/**
 * Write workcell metadata
 */
async function writeMetadata(
  workcellPath: string,
  workcell: WorkcellInfo
): Promise<void> {
  const metadataPath = join(workcellPath, ".clawdstrike", METADATA_FILE)
  await writeFile(metadataPath, JSON.stringify(workcell, null, 2))
}

/**
 * Read workcell metadata
 */
export async function readMetadata(
  workcellPath: string
): Promise<WorkcellInfo | null> {
  const metadataPath = join(workcellPath, ".clawdstrike", METADATA_FILE)
  try {
    const content = await readFile(metadataPath, "utf-8")
    return JSON.parse(content) as WorkcellInfo
  } catch {
    return null
  }
}

/**
 * Acquire a workcell (get from pool or create new)
 */
export async function acquireWorkcell(
  projectId: string,
  gitRoot: string,
  config: PoolConfig,
  toolchain?: Toolchain
): Promise<WorkcellInfo> {
  // Ensure pool is initialized
  pool.initPool(projectId, gitRoot, config)

  // Try to find a warm workcell
  let workcell = pool.findWarmWorkcell(projectId, toolchain)

  // If no warm workcell, create new one if allowed
  if (!workcell) {
    if (!pool.canCreateMore(projectId)) {
      throw new Error(
        `Pool limit reached for project ${projectId}. Max: ${config.maxSize}`
      )
    }
    workcell = await createWorkcell(projectId, gitRoot, { toolchain })
  }

  // Mark as in_use
  workcell = {
    ...workcell,
    status: "in_use" as WorkcellStatus,
    toolchain: toolchain || workcell.toolchain,
    lastUsedAt: Date.now(),
    useCount: workcell.useCount + 1,
  }

  pool.updateWorkcell(workcell)
  await writeMetadata(workcell.directory, workcell)

  return workcell
}

/**
 * Release a workcell back to pool
 */
export async function releaseWorkcell(
  workcellId: string,
  gitRoot: string,
  options: { keep?: boolean; reset?: boolean } = {}
): Promise<void> {
  const workcell = pool.getWorkcell(workcellId)
  if (!workcell) {
    throw new Error(`Workcell not found: ${workcellId}`)
  }

  const poolState = pool.getPool(workcell.projectId)
  if (!poolState) {
    throw new Error(`Pool not found for project: ${workcell.projectId}`)
  }

  // Check if we should destroy or return to pool
  const counts = pool.countByStatus(workcell.projectId)
  const shouldDestroy =
    !options.keep &&
    counts.warm >= poolState.config.minSize &&
    counts.total > poolState.config.minSize

  if (shouldDestroy) {
    await destroyWorkcell(workcellId, gitRoot)
    return
  }

  // Reset the workcell if requested (default: true)
  if (options.reset !== false) {
    workcell.status = "cleaning"
    pool.updateWorkcell(workcell)

    try {
      await git.resetWorktree(workcell.directory)
    } catch (error) {
      // If reset fails, destroy the workcell
      await destroyWorkcell(workcellId, gitRoot)
      throw error
    }
  }

  // Return to pool as warm
  const updatedWorkcell: WorkcellInfo = {
    ...workcell,
    status: "warm",
    lastUsedAt: Date.now(),
  }

  pool.updateWorkcell(updatedWorkcell)
  await writeMetadata(workcell.directory, updatedWorkcell)
}

/**
 * Destroy a workcell
 */
export async function destroyWorkcell(
  workcellId: string,
  gitRoot: string
): Promise<void> {
  const workcell = pool.getWorkcell(workcellId)
  if (!workcell) {
    return // Already destroyed or doesn't exist
  }

  // Update status
  workcell.status = "destroyed"
  pool.updateWorkcell(workcell)

  try {
    // Remove git worktree
    await git.removeWorktree(gitRoot, workcell.directory, { force: true })
  } catch {
    // Try direct removal if git worktree remove fails
    try {
      await rm(workcell.directory, { recursive: true, force: true })
    } catch {
      // Ignore
    }
  }

  // Remove from pool
  pool.removeFromPool(workcellId)
}

/**
 * Destroy all workcells for a project
 */
export async function destroyAllWorkcells(
  projectId: string,
  gitRoot: string
): Promise<void> {
  const workcells = pool.getProjectWorkcells(projectId)

  await Promise.all(
    workcells.map((wc) => destroyWorkcell(wc.id, gitRoot).catch(() => {}))
  )

  pool.deletePool(projectId)
}

/**
 * Garbage collect expired workcells
 */
export async function gcWorkcells(
  projectId: string,
  gitRoot: string
): Promise<{ destroyed: number; remaining: number; duration: number }> {
  const startTime = Date.now()
  const expired = pool.getExpiredWorkcells(projectId)

  let destroyed = 0
  for (const workcell of expired) {
    try {
      await destroyWorkcell(workcell.id, gitRoot)
      destroyed++
    } catch {
      // Continue with next
    }
  }

  const remaining = pool.countByStatus(projectId).total

  return {
    destroyed,
    remaining,
    duration: Date.now() - startTime,
  }
}

/**
 * Pre-warm pool to minimum size
 */
export async function preWarmPool(
  projectId: string,
  gitRoot: string,
  config: PoolConfig
): Promise<void> {
  pool.initPool(projectId, gitRoot, config)

  const counts = pool.countByStatus(projectId)
  const needed = config.minSize - counts.warm

  if (needed <= 0) return

  // Create workcells in parallel
  const promises: Promise<WorkcellInfo>[] = []
  for (let i = 0; i < needed; i++) {
    promises.push(createWorkcell(projectId, gitRoot))
  }

  await Promise.all(promises)
}

/**
 * Restore existing workcells from disk
 */
export async function restoreWorkcells(
  projectId: string,
  gitRoot: string,
  config: PoolConfig
): Promise<void> {
  // Initialize pool (ignore return value)
  pool.initPool(projectId, gitRoot, config)

  // List existing worktrees
  const worktrees = await git.listWorktrees(gitRoot)
  const workcellsDir = git.getWorkcellsDir(gitRoot)

  for (const worktree of worktrees) {
    // Check if this is a clawdstrike workcell
    if (!worktree.path.startsWith(workcellsDir)) {
      continue
    }

    // Try to read metadata
    const metadata = await readMetadata(worktree.path)
    if (metadata && metadata.projectId === projectId) {
      // Restore to pool as warm (reset it first)
      try {
        await git.resetWorktree(worktree.path)
        metadata.status = "warm"
        metadata.lastUsedAt = Date.now()
        pool.addToPool(metadata)
      } catch {
        // If reset fails, try to remove
        try {
          await git.removeWorktree(gitRoot, worktree.path, { force: true })
        } catch {
          // Ignore
        }
      }
    }
  }
}
