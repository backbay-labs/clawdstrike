/**
 * Workcell Pool Management
 *
 * Manages pools of warm workcells per project for fast acquisition.
 */

import type { WorkcellInfo, Toolchain } from "../types"
import type { PoolConfig } from "./index"

/**
 * Internal pool state for a project
 */
export interface PoolState {
  projectId: string
  gitRoot: string
  config: PoolConfig
  workcells: Map<string, WorkcellInfo>
  cleanupTimer?: ReturnType<typeof setInterval>
}

/**
 * Global pool registry keyed by projectId
 */
const pools: Map<string, PoolState> = new Map()

/**
 * Get or create pool for a project
 */
export function getPool(projectId: string): PoolState | undefined {
  return pools.get(projectId)
}

/**
 * Initialize a pool for a project
 */
export function initPool(
  projectId: string,
  gitRoot: string,
  config: PoolConfig
): PoolState {
  // Check if pool already exists
  let pool = pools.get(projectId)
  if (pool) {
    // Update config if provided
    pool.config = { ...pool.config, ...config }
    return pool
  }

  // Create new pool
  pool = {
    projectId,
    gitRoot,
    config,
    workcells: new Map(),
  }

  pools.set(projectId, pool)
  return pool
}

/**
 * Get pool config with defaults
 */
export function getPoolConfig(projectId: string): PoolConfig {
  const pool = pools.get(projectId)
  if (pool) {
    return pool.config
  }

  // Return defaults
  return {
    minSize: 2,
    maxSize: 10,
    ttl: 3600000,
    preWarm: true,
    cleanupInterval: 300000,
  }
}

/**
 * Update pool config
 */
export function updatePoolConfig(
  projectId: string,
  config: Partial<PoolConfig>
): void {
  const pool = pools.get(projectId)
  if (pool) {
    pool.config = { ...pool.config, ...config }
  }
}

/**
 * Add workcell to pool
 */
export function addToPool(workcell: WorkcellInfo): void {
  const pool = pools.get(workcell.projectId)
  if (pool) {
    pool.workcells.set(workcell.id, workcell)
  }
}

/**
 * Remove workcell from pool
 */
export function removeFromPool(workcellId: string): WorkcellInfo | undefined {
  for (const pool of pools.values()) {
    const workcell = pool.workcells.get(workcellId)
    if (workcell) {
      pool.workcells.delete(workcellId)
      return workcell
    }
  }
  return undefined
}

/**
 * Get workcell by ID from any pool
 */
export function getWorkcell(workcellId: string): WorkcellInfo | undefined {
  for (const pool of pools.values()) {
    const workcell = pool.workcells.get(workcellId)
    if (workcell) {
      return workcell
    }
  }
  return undefined
}

/**
 * Update workcell in pool
 */
export function updateWorkcell(workcell: WorkcellInfo): void {
  const pool = pools.get(workcell.projectId)
  if (pool && pool.workcells.has(workcell.id)) {
    pool.workcells.set(workcell.id, workcell)
  }
}

/**
 * Find an available warm workcell in pool
 */
export function findWarmWorkcell(
  projectId: string,
  toolchain?: Toolchain
): WorkcellInfo | undefined {
  const pool = pools.get(projectId)
  if (!pool) return undefined

  for (const workcell of pool.workcells.values()) {
    if (workcell.status === "warm") {
      // If toolchain specified, prefer matching workcells
      if (toolchain && workcell.toolchain === toolchain) {
        return workcell
      }
      // If no toolchain or no match, return any warm workcell
      if (!toolchain) {
        return workcell
      }
    }
  }

  // Second pass: return any warm workcell if toolchain didn't match
  if (toolchain) {
    for (const workcell of pool.workcells.values()) {
      if (workcell.status === "warm") {
        return workcell
      }
    }
  }

  return undefined
}

/**
 * Count workcells in pool by status
 */
export function countByStatus(
  projectId: string
): { total: number; warm: number; inUse: number; creating: number } {
  const pool = pools.get(projectId)
  if (!pool) {
    return { total: 0, warm: 0, inUse: 0, creating: 0 }
  }

  let warm = 0
  let inUse = 0
  let creating = 0

  for (const workcell of pool.workcells.values()) {
    switch (workcell.status) {
      case "warm":
        warm++
        break
      case "in_use":
        inUse++
        break
      case "creating":
        creating++
        break
    }
  }

  return {
    total: pool.workcells.size,
    warm,
    inUse,
    creating,
  }
}

/**
 * Check if pool can create more workcells
 */
export function canCreateMore(projectId: string): boolean {
  const pool = pools.get(projectId)
  if (!pool) return true

  const counts = countByStatus(projectId)
  return counts.total < pool.config.maxSize
}

/**
 * Get expired workcells (past TTL and warm)
 */
export function getExpiredWorkcells(projectId: string): WorkcellInfo[] {
  const pool = pools.get(projectId)
  if (!pool) return []

  const now = Date.now()
  const expired: WorkcellInfo[] = []

  for (const workcell of pool.workcells.values()) {
    if (workcell.status === "warm") {
      const lastUsed = workcell.lastUsedAt || workcell.createdAt
      if (now - lastUsed > pool.config.ttl) {
        // Don't expire if we're at minSize
        const counts = countByStatus(projectId)
        if (counts.warm > pool.config.minSize) {
          expired.push(workcell)
        }
      }
    }
  }

  return expired
}

/**
 * Get all workcells across all pools
 */
export function getAllWorkcells(): WorkcellInfo[] {
  const all: WorkcellInfo[] = []
  for (const pool of pools.values()) {
    for (const workcell of pool.workcells.values()) {
      all.push(workcell)
    }
  }
  return all
}

/**
 * Get all workcells for a project
 */
export function getProjectWorkcells(projectId: string): WorkcellInfo[] {
  const pool = pools.get(projectId)
  if (!pool) return []
  return Array.from(pool.workcells.values())
}

/**
 * Clear all pools (for shutdown)
 */
export function clearAllPools(): void {
  for (const pool of pools.values()) {
    if (pool.cleanupTimer) {
      clearInterval(pool.cleanupTimer)
    }
    pool.workcells.clear()
  }
  pools.clear()
}

/**
 * Get all pool IDs
 */
export function getPoolIds(): string[] {
  return Array.from(pools.keys())
}

/**
 * Delete a pool
 */
export function deletePool(projectId: string): void {
  const pool = pools.get(projectId)
  if (pool) {
    if (pool.cleanupTimer) {
      clearInterval(pool.cleanupTimer)
    }
    pool.workcells.clear()
    pools.delete(projectId)
  }
}
