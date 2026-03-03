/**
 * Git operations for workcell management
 *
 * Handles git worktree creation, cleanup, and branch management.
 */

import { $ } from "bun"
import { join, dirname } from "path"
import { mkdir, rm, stat } from "fs/promises"

export interface WorktreeInfo {
  path: string
  branch: string
  commit: string
}

/**
 * Get the git root directory for the current working directory
 */
export async function getGitRoot(cwd: string): Promise<string> {
  const result = await $`git -C ${cwd} rev-parse --show-toplevel`.quiet().nothrow()
  if (result.exitCode !== 0) {
    throw new Error(`Not a git repository: ${cwd}`)
  }
  return result.text().trim()
}

/**
 * Get the current branch name
 */
export async function getCurrentBranch(cwd: string): Promise<string> {
  const result = await $`git -C ${cwd} rev-parse --abbrev-ref HEAD`.quiet().nothrow()
  if (result.exitCode !== 0) {
    throw new Error(`Failed to get current branch: ${result.stderr.toString()}`)
  }
  return result.text().trim()
}

/**
 * Get the current commit hash
 */
export async function getCurrentCommit(cwd: string): Promise<string> {
  const result = await $`git -C ${cwd} rev-parse HEAD`.quiet().nothrow()
  if (result.exitCode !== 0) {
    throw new Error(`Failed to get current commit: ${result.stderr.toString()}`)
  }
  return result.text().trim()
}

/**
 * List existing worktrees
 */
export async function listWorktrees(gitRoot: string): Promise<WorktreeInfo[]> {
  const result = await $`git -C ${gitRoot} worktree list --porcelain`.quiet().nothrow()
  if (result.exitCode !== 0) {
    return []
  }

  const output = result.text()
  const worktrees: WorktreeInfo[] = []
  let current: Partial<WorktreeInfo> = {}

  for (const line of output.split("\n")) {
    if (line.startsWith("worktree ")) {
      if (current.path) {
        worktrees.push(current as WorktreeInfo)
      }
      current = { path: line.substring(9) }
    } else if (line.startsWith("HEAD ")) {
      current.commit = line.substring(5)
    } else if (line.startsWith("branch ")) {
      // Format: refs/heads/branch-name
      current.branch = line.substring(7).replace("refs/heads/", "")
    } else if (line === "detached") {
      current.branch = "HEAD"
    }
  }

  if (current.path) {
    worktrees.push(current as WorktreeInfo)
  }

  return worktrees
}

/**
 * Create a new worktree
 */
export async function createWorktree(
  gitRoot: string,
  worktreePath: string,
  options: {
    branch?: string
    newBranch?: string
    commit?: string
    detach?: boolean
  } = {}
): Promise<WorktreeInfo> {
  // Ensure parent directory exists
  await mkdir(dirname(worktreePath), { recursive: true })

  const args: string[] = ["worktree", "add"]

  if (options.detach) {
    args.push("--detach")
  }

  if (options.newBranch) {
    args.push("-b", options.newBranch)
  }

  args.push(worktreePath)

  if (options.commit) {
    args.push(options.commit)
  } else if (options.branch) {
    args.push(options.branch)
  }

  const result = await $`git -C ${gitRoot} ${args}`.quiet().nothrow()
  if (result.exitCode !== 0) {
    throw new Error(`Failed to create worktree: ${result.stderr.toString()}`)
  }

  // Get the actual branch/commit info
  const branch = options.newBranch || options.branch || await getCurrentBranch(worktreePath)
  const commit = await getCurrentCommit(worktreePath)

  return {
    path: worktreePath,
    branch,
    commit,
  }
}

/**
 * Remove a worktree
 */
export async function removeWorktree(
  gitRoot: string,
  worktreePath: string,
  options: { force?: boolean } = {}
): Promise<void> {
  const args = ["worktree", "remove"]
  if (options.force) {
    args.push("--force")
  }
  args.push(worktreePath)

  const result = await $`git -C ${gitRoot} ${args}`.quiet().nothrow()

  // If worktree remove failed, try to clean up manually
  if (result.exitCode !== 0) {
    // Check if directory exists
    try {
      await stat(worktreePath)
      // Directory exists, try force removal
      await rm(worktreePath, { recursive: true, force: true })
      // Also prune stale worktree references
      await $`git -C ${gitRoot} worktree prune`.quiet().nothrow()
    } catch {
      // Directory doesn't exist, just prune
      await $`git -C ${gitRoot} worktree prune`.quiet().nothrow()
    }
  }
}

/**
 * Reset a worktree to a clean state
 */
export async function resetWorktree(worktreePath: string): Promise<void> {
  // Hard reset to HEAD
  await $`git -C ${worktreePath} reset --hard HEAD`.quiet().nothrow()

  // Clean untracked files
  await $`git -C ${worktreePath} clean -fd`.quiet().nothrow()
}

/**
 * Check if a path is inside a worktree
 */
export async function isWorktree(path: string): Promise<boolean> {
  const result = await $`git -C ${path} rev-parse --is-inside-work-tree`.quiet().nothrow()
  return result.exitCode === 0 && result.text().trim() === "true"
}

/**
 * Get diff of changes in worktree
 */
export async function getWorktreeDiff(worktreePath: string): Promise<string> {
  // Include both staged and unstaged changes
  const result = await $`git -C ${worktreePath} diff HEAD`.quiet().nothrow()
  return result.text()
}

/**
 * Check if worktree has uncommitted changes
 */
export async function hasChanges(worktreePath: string): Promise<boolean> {
  const result = await $`git -C ${worktreePath} status --porcelain`.quiet().nothrow()
  return result.text().trim().length > 0
}

/**
 * Stage all changes in worktree
 */
export async function stageAll(worktreePath: string): Promise<void> {
  await $`git -C ${worktreePath} add -A`.quiet().nothrow()
}

/**
 * Create a commit in worktree
 */
export async function commit(
  worktreePath: string,
  message: string
): Promise<string> {
  await stageAll(worktreePath)

  const result = await $`git -C ${worktreePath} commit -m ${message}`.quiet().nothrow()
  if (result.exitCode !== 0) {
    throw new Error(`Failed to commit: ${result.stderr.toString()}`)
  }

  return getCurrentCommit(worktreePath)
}

/**
 * Get list of changed files in worktree
 */
export async function getChangedFiles(worktreePath: string): Promise<string[]> {
  const result = await $`git -C ${worktreePath} diff --name-only HEAD`.quiet().nothrow()
  const files = result.text().trim()
  if (!files) return []
  return files.split("\n").filter(Boolean)
}

/**
 * Generate unique worktree branch name
 */
export function generateWorktreeBranch(prefix: string, id: string): string {
  return `clawdstrike/${prefix}/${id}`
}

/**
 * Get clawdstrike workcells directory path
 */
export function getWorkcellsDir(gitRoot: string): string {
  return join(gitRoot, ".clawdstrike", "workcells")
}
