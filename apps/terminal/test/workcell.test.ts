/**
 * Workcell unit tests
 *
 * Tests for git worktree operations, pool management, and lifecycle.
 */

import { describe, test, expect, beforeEach } from "bun:test"
import * as pool from "../src/workcell/pool"
import * as git from "../src/workcell/git"
import type { WorkcellInfo } from "../src/types"

describe("Git utilities", () => {
  test("getWorkcellsDir returns correct path", () => {
    expect(git.getWorkcellsDir("/project")).toBe("/project/.clawdstrike/workcells")
    expect(git.getWorkcellsDir("/home/user/repo")).toBe(
      "/home/user/repo/.clawdstrike/workcells"
    )
  })

  test("generateWorktreeBranch generates correct format", () => {
    const branch = git.generateWorktreeBranch("wc", "abc12345")
    expect(branch).toBe("clawdstrike/wc/abc12345")
  })
})

describe("Pool state management", () => {
  const projectId = "test-project"
  const gitRoot = "/test/repo"

  beforeEach(() => {
    // Clear all pools before each test
    pool.clearAllPools()
  })

  test("initPool creates pool with default config", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    const state = pool.initPool(projectId, gitRoot, config)

    expect(state).toBeDefined()
    expect(state.projectId).toBe(projectId)
    expect(state.gitRoot).toBe(gitRoot)
    expect(state.config).toEqual(config)
    expect(state.workcells.size).toBe(0)
  })

  test("getPool returns undefined for non-existent pool", () => {
    expect(pool.getPool("nonexistent")).toBeUndefined()
  })

  test("getPool returns existing pool", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool(projectId, gitRoot, config)

    const state = pool.getPool(projectId)
    expect(state).toBeDefined()
    expect(state?.projectId).toBe(projectId)
  })

  test("addWorkcell adds to pool", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool(projectId, gitRoot, config)

    const workcell: WorkcellInfo = {
      id: "123e4567-e89b-12d3-a456-426614174000",
      name: "wc-test",
      directory: "/test/repo/.clawdstrike/workcells/wc-test",
      branch: "wc-test",
      status: "warm",
      projectId,
      createdAt: Date.now(),
      useCount: 0,
    }

    pool.addToPool(workcell)
    const counts = pool.countByStatus(projectId)

    expect(counts.total).toBe(1)
    expect(counts.warm).toBe(1)
    expect(counts.inUse).toBe(0)
  })

  test("findWarmWorkcell returns warm workcell", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool(projectId, gitRoot, config)

    const workcell: WorkcellInfo = {
      id: "123e4567-e89b-12d3-a456-426614174000",
      name: "wc-test",
      directory: "/test/repo/.clawdstrike/workcells/wc-test",
      branch: "wc-test",
      status: "warm",
      projectId,
      createdAt: Date.now(),
      useCount: 0,
    }

    pool.addToPool(workcell)
    const found = pool.findWarmWorkcell(projectId)

    expect(found).toBeDefined()
    expect(found?.id).toBe(workcell.id)
  })

  test("findWarmWorkcell returns undefined when none warm", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool(projectId, gitRoot, config)

    const workcell: WorkcellInfo = {
      id: "123e4567-e89b-12d3-a456-426614174000",
      name: "wc-test",
      directory: "/test/repo/.clawdstrike/workcells/wc-test",
      branch: "wc-test",
      status: "in_use", // Not warm
      projectId,
      createdAt: Date.now(),
      useCount: 1,
    }

    pool.addToPool(workcell)
    const found = pool.findWarmWorkcell(projectId)

    expect(found).toBeUndefined()
  })

  test("updateWorkcellStatus updates status correctly", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool(projectId, gitRoot, config)

    const workcell: WorkcellInfo = {
      id: "123e4567-e89b-12d3-a456-426614174000",
      name: "wc-test",
      directory: "/test/repo/.clawdstrike/workcells/wc-test",
      branch: "wc-test",
      status: "warm",
      projectId,
      createdAt: Date.now(),
      useCount: 0,
    }

    pool.addToPool(workcell)
    pool.updateWorkcell({ ...workcell, status: "in_use" })

    const updated = pool.getWorkcell(workcell.id)
    expect(updated?.status).toBe("in_use")
  })

  test("removeWorkcell removes from pool", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool(projectId, gitRoot, config)

    const workcell: WorkcellInfo = {
      id: "123e4567-e89b-12d3-a456-426614174000",
      name: "wc-test",
      directory: "/test/repo/.clawdstrike/workcells/wc-test",
      branch: "wc-test",
      status: "warm",
      projectId,
      createdAt: Date.now(),
      useCount: 0,
    }

    pool.addToPool(workcell)
    expect(pool.countByStatus(projectId).total).toBe(1)

    pool.removeFromPool(workcell.id)
    expect(pool.countByStatus(projectId).total).toBe(0)
  })

  test("countByStatus returns correct counts", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool(projectId, gitRoot, config)

    const workcells: WorkcellInfo[] = [
      {
        id: "123e4567-e89b-12d3-a456-426614174001",
        name: "wc-warm1",
        directory: "/test/repo/.clawdstrike/workcells/wc-warm1",
        branch: "wc-warm1",
        status: "warm",
        projectId,
        createdAt: Date.now(),
        useCount: 0,
      },
      {
        id: "123e4567-e89b-12d3-a456-426614174002",
        name: "wc-warm2",
        directory: "/test/repo/.clawdstrike/workcells/wc-warm2",
        branch: "wc-warm2",
        status: "warm",
        projectId,
        createdAt: Date.now(),
        useCount: 0,
      },
      {
        id: "123e4567-e89b-12d3-a456-426614174003",
        name: "wc-inuse",
        directory: "/test/repo/.clawdstrike/workcells/wc-inuse",
        branch: "wc-inuse",
        status: "in_use",
        projectId,
        createdAt: Date.now(),
        useCount: 1,
      },
      {
        id: "123e4567-e89b-12d3-a456-426614174004",
        name: "wc-creating",
        directory: "/test/repo/.clawdstrike/workcells/wc-creating",
        branch: "wc-creating",
        status: "creating",
        projectId,
        createdAt: Date.now(),
        useCount: 0,
      },
    ]

    for (const wc of workcells) {
      pool.addToPool(wc)
    }

    const counts = pool.countByStatus(projectId)
    expect(counts.total).toBe(4)
    expect(counts.warm).toBe(2)
    expect(counts.inUse).toBe(1)
    expect(counts.creating).toBe(1)
  })

  test("getExpiredWorkcells returns old workcells", () => {
    const config = { minSize: 0, maxSize: 10, ttl: 1000, preWarm: false, cleanupInterval: 300000 } // 1 second TTL
    pool.initPool(projectId, gitRoot, config)

    const oldWorkcell: WorkcellInfo = {
      id: "123e4567-e89b-12d3-a456-426614174001",
      name: "wc-old",
      directory: "/test/repo/.clawdstrike/workcells/wc-old",
      branch: "wc-old",
      status: "warm",
      projectId,
      createdAt: Date.now() - 10000, // 10 seconds ago
      useCount: 0,
    }

    const newWorkcell: WorkcellInfo = {
      id: "123e4567-e89b-12d3-a456-426614174002",
      name: "wc-new",
      directory: "/test/repo/.clawdstrike/workcells/wc-new",
      branch: "wc-new",
      status: "warm",
      projectId,
      createdAt: Date.now(), // Just now
      useCount: 0,
    }

    pool.addToPool(oldWorkcell)
    pool.addToPool(newWorkcell)

    const expired = pool.getExpiredWorkcells(projectId)
    expect(expired.length).toBe(1)
    expect(expired[0].id).toBe(oldWorkcell.id)
  })

  test("getPoolIds returns all project IDs", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool("project1", "/repo1", config)
    pool.initPool("project2", "/repo2", config)
    pool.initPool("project3", "/repo3", config)

    const ids = pool.getPoolIds()
    expect(ids.length).toBe(3)
    expect(ids).toContain("project1")
    expect(ids).toContain("project2")
    expect(ids).toContain("project3")
  })

  test("clearAllPools removes all pools", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool("project1", "/repo1", config)
    pool.initPool("project2", "/repo2", config)

    expect(pool.getPoolIds().length).toBe(2)

    pool.clearAllPools()
    expect(pool.getPoolIds().length).toBe(0)
  })

  test("updatePoolConfig updates config", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool(projectId, gitRoot, config)

    pool.updatePoolConfig(projectId, { maxSize: 20, ttl: 7200000 })

    const state = pool.getPool(projectId)
    expect(state?.config.maxSize).toBe(20)
    expect(state?.config.ttl).toBe(7200000)
    expect(state?.config.minSize).toBe(2) // Unchanged
  })

  test("findWarmWorkcell filters by toolchain", () => {
    const config = { minSize: 2, maxSize: 10, ttl: 3600000, preWarm: true, cleanupInterval: 300000 }
    pool.initPool(projectId, gitRoot, config)

    const workcell1: WorkcellInfo = {
      id: "123e4567-e89b-12d3-a456-426614174001",
      name: "wc-codex",
      directory: "/test/repo/.clawdstrike/workcells/wc-codex",
      branch: "wc-codex",
      status: "warm",
      toolchain: "codex",
      projectId,
      createdAt: Date.now(),
      useCount: 0,
    }

    const workcell2: WorkcellInfo = {
      id: "123e4567-e89b-12d3-a456-426614174002",
      name: "wc-claude",
      directory: "/test/repo/.clawdstrike/workcells/wc-claude",
      branch: "wc-claude",
      status: "warm",
      toolchain: "claude",
      projectId,
      createdAt: Date.now(),
      useCount: 0,
    }

    pool.addToPool(workcell1)
    pool.addToPool(workcell2)

    const foundCodex = pool.findWarmWorkcell(projectId, "codex")
    expect(foundCodex?.id).toBe(workcell1.id)

    const foundClaude = pool.findWarmWorkcell(projectId, "claude")
    expect(foundClaude?.id).toBe(workcell2.id)

    // Should find any when no toolchain specified
    const foundAny = pool.findWarmWorkcell(projectId)
    expect(foundAny).toBeDefined()
  })
})
