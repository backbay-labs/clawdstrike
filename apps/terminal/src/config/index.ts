/**
 * Config - Project configuration management
 *
 * Handles loading, saving, and detecting project configuration.
 * Stores config as JSON in .clawdstrike/config.json.
 */

import { z } from "zod"
import { join } from "path"
import { mkdir, readFile, writeFile, stat } from "fs/promises"
import type { Toolchain, SandboxMode } from "../types"

// =============================================================================
// SCHEMA
// =============================================================================

export const ProjectConfig = z.object({
  schema_version: z.literal("1.0.0"),
  sandbox: z.enum(["inplace", "worktree", "tmpdir"]).default("inplace"),
  toolchain: z.enum(["codex", "claude", "opencode", "crush"]).optional(),
  adapters: z
    .record(
      z.string(),
      z.object({
        available: z.boolean(),
        version: z.string().optional(),
      })
    )
    .default({}),
  git_available: z.boolean().default(false),
  project_id: z.string().default("default"),
})

export type ProjectConfig = z.infer<typeof ProjectConfig>

// =============================================================================
// DETECTION
// =============================================================================

export interface DetectionResult {
  adapters: Record<string, { available: boolean; version?: string }>
  git_available: boolean
  recommended_sandbox: SandboxMode
  recommended_toolchain?: Toolchain
}

// =============================================================================
// CONFIG NAMESPACE
// =============================================================================

const CONFIG_DIR = ".clawdstrike"
const CONFIG_FILE = "config.json"

function configPath(cwd: string): string {
  return join(cwd, CONFIG_DIR, CONFIG_FILE)
}

export namespace Config {
  /**
   * Check if config file exists
   */
  export async function exists(cwd: string): Promise<boolean> {
    try {
      await stat(configPath(cwd))
      return true
    } catch {
      return false
    }
  }

  /**
   * Load project config from .clawdstrike/config.json
   * Returns null if file doesn't exist
   */
  export async function load(cwd: string): Promise<ProjectConfig | null> {
    try {
      const raw = await readFile(configPath(cwd), "utf-8")
      const data = JSON.parse(raw)
      return ProjectConfig.parse(data)
    } catch {
      return null
    }
  }

  /**
   * Save project config to .clawdstrike/config.json
   */
  export async function save(
    cwd: string,
    config: ProjectConfig
  ): Promise<void> {
    const dir = join(cwd, CONFIG_DIR)
    await mkdir(dir, { recursive: true })
    const validated = ProjectConfig.parse(config)
    await writeFile(configPath(cwd), JSON.stringify(validated, null, 2) + "\n")
  }

  /**
   * Detect available toolchains, git status, and recommend configuration
   */
  export async function detect(cwd: string): Promise<DetectionResult> {
    const { getAllAdapters } = await import("../dispatcher/adapters")
    const allAdapters = getAllAdapters()

    // Run all adapter availability checks in parallel + git check
    const adapterChecks = allAdapters.map(async (adapter) => {
      const available = await adapter.isAvailable()
      return {
        id: adapter.info.id,
        available,
      }
    })

    const gitCheck = async (): Promise<boolean> => {
      try {
        const { getGitRoot } = await import("../workcell/git")
        await getGitRoot(cwd)
        return true
      } catch {
        return false
      }
    }

    const [adapterResults, gitAvailable] = await Promise.all([
      Promise.all(adapterChecks),
      gitCheck(),
    ])

    // Build adapters map
    const adapters: Record<string, { available: boolean; version?: string }> =
      {}
    for (const result of adapterResults) {
      adapters[result.id] = { available: result.available }
    }

    // Recommend sandbox: worktree if git available, otherwise inplace
    const recommended_sandbox: SandboxMode = gitAvailable
      ? "worktree"
      : "inplace"

    // Recommend first available toolchain (prefer claude > codex > opencode > crush)
    const priority: Toolchain[] = ["claude", "codex", "opencode", "crush"]
    const recommended_toolchain = priority.find((t) => adapters[t]?.available)

    return {
      adapters,
      git_available: gitAvailable,
      recommended_sandbox,
      recommended_toolchain,
    }
  }
}

export default Config
