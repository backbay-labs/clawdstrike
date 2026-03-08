/**
 * Config - Project configuration management
 *
 * Handles loading, saving, and detecting project configuration.
 * Stores config as JSON in .clawdstrike/config.json.
 */

import { z } from "zod"
import { dirname, join } from "path"
import { mkdir, readFile, writeFile, stat } from "fs/promises"
import type { Toolchain, SandboxMode } from "../types"
import { commandExists } from "../system"

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

async function pathExists(path: string): Promise<boolean> {
  try {
    await stat(path)
    return true
  } catch {
    return false
  }
}

async function detectGitAvailability(cwd: string): Promise<boolean> {
  if (!(await commandExists("git"))) {
    return false
  }

  let current = cwd

  while (true) {
    if (await pathExists(join(current, ".git"))) {
      return true
    }

    const parent = dirname(current)
    if (parent === current) {
      return false
    }

    current = parent
  }
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
   * Inspect local project state using filesystem checks only.
   */
  export async function inspectProject(
    cwd: string
  ): Promise<Pick<DetectionResult, "git_available" | "recommended_sandbox">> {
    const git_available = await detectGitAvailability(cwd)

    return {
      git_available,
      recommended_sandbox: git_available ? "worktree" : "inplace",
    }
  }

  /**
   * Detect available toolchains, git status, and recommend configuration
   */
  export async function detect(cwd: string): Promise<DetectionResult> {
    const { getAllAdapters } = await import("../dispatcher/adapters")
    const allAdapters = getAllAdapters()
    const project = await inspectProject(cwd)

    const adapterResults = await Promise.allSettled(
      allAdapters.map(async (adapter) => {
        const available = await adapter.isAvailable()
        return {
          id: adapter.info.id,
          available,
        }
      })
    )

    // Build adapters map
    const adapters: Record<string, { available: boolean; version?: string }> =
      {}

    for (const [index, result] of adapterResults.entries()) {
      const id = allAdapters[index]?.info.id
      if (!id) continue

      if (result.status === "fulfilled") {
        adapters[id] = { available: result.value.available }
      } else {
        adapters[id] = { available: false }
      }
    }

    // Recommend first available toolchain (prefer claude > codex > opencode > crush)
    const priority: Toolchain[] = ["claude", "codex", "opencode", "crush"]
    const recommended_toolchain = priority.find((t) => adapters[t]?.available)

    return {
      adapters,
      git_available: project.git_available,
      recommended_sandbox: project.recommended_sandbox,
      recommended_toolchain,
    }
  }
}

export default Config
