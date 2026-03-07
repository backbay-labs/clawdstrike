/**
 * Health - Integration healthcheck system for ClawdStrike
 *
 * Provides lightweight, parallel healthchecks for:
 * - Security: hushd, hush-cli
 * - AI Toolchains: Claude, Codex, OpenCode
 * - Infrastructure: Git, Python, Bun
 * - MCP Server: ClawdStrike's own MCP server status
 */

// =============================================================================
// TYPES
// =============================================================================

export interface HealthStatus {
  id: string
  name: string
  category: "security" | "ai" | "infra" | "mcp"
  available: boolean
  version?: string
  latency?: number
  error?: string
  checkedAt: number
}

export interface HealthCheckOptions {
  force?: boolean
  timeout?: number
}

export interface HealthSummary {
  security: HealthStatus[]
  ai: HealthStatus[]
  infra: HealthStatus[]
  mcp: HealthStatus[]
  checkedAt: number
}

// =============================================================================
// INTEGRATION DEFINITIONS
// =============================================================================

interface IntegrationDef {
  id: string
  name: string
  category: "security" | "ai" | "infra" | "mcp"
  command?: string
  args?: string[]
  versionParser?: (output: string) => string | undefined
  httpProbe?: string
}

function hushdHealthUrl(): string {
  const baseUrl = process.env.CLAWDSTRIKE_HUSHD_URL ?? "http://127.0.0.1:9876"
  return `${baseUrl.replace(/\/$/, "")}/health`
}

function getIntegrations(): IntegrationDef[] {
  return [
    // Security
    {
      id: "hushd",
      name: "hushd",
      category: "security",
      httpProbe: hushdHealthUrl(),
    },
    {
      id: "hush-cli",
      name: "hush-cli",
      category: "security",
      command: "clawdstrike",
      args: ["--version"],
      versionParser: (out) => out.match(/(\d+\.\d+(?:\.\d+)?)/)?.[1],
    },

    // AI Toolchains
    {
      id: "claude",
      name: "Claude",
      category: "ai",
      command: "claude",
      args: ["--version"],
      versionParser: (out) => out.match(/(\d+\.\d+(?:\.\d+)?)/)?.[1],
    },
    {
      id: "codex",
      name: "Codex",
      category: "ai",
      command: "codex",
      args: ["--version"],
      versionParser: (out) => out.match(/(\d+\.\d+(?:\.\d+)?)/)?.[1],
    },
    {
      id: "opencode",
      name: "OpenCode",
      category: "ai",
      command: "opencode",
      args: ["--version"],
      versionParser: (out) => out.match(/(\d+\.\d+(?:\.\d+)?)/)?.[1],
    },

    // Infrastructure
    {
      id: "git",
      name: "Git",
      category: "infra",
      command: "git",
      args: ["--version"],
      versionParser: (out) => out.match(/git version (\d+\.\d+(?:\.\d+)?)/)?.[1],
    },
    {
      id: "python",
      name: "Python",
      category: "infra",
      command: "python3",
      args: ["--version"],
      versionParser: (out) => out.match(/Python (\d+\.\d+(?:\.\d+)?)/)?.[1],
    },
    {
      id: "bun",
      name: "Bun",
      category: "infra",
      command: "bun",
      args: ["--version"],
      versionParser: (out) => out.match(/(\d+\.\d+(?:\.\d+)?)/)?.[1],
    },
  ]
}

// =============================================================================
// CACHE
// =============================================================================

const CACHE_TTL = 60_000 // 60 seconds
let healthCache: Map<string, HealthStatus> = new Map()
let lastFullCheck = 0

// MCP server state (set externally)
let mcpServerStatus: { running: boolean; port?: number } = { running: false }

// =============================================================================
// HEALTHCHECK FUNCTIONS
// =============================================================================

/**
 * Check a single integration using HTTP probe or Bun's subprocess
 */
async function checkIntegration(
  def: IntegrationDef,
  timeout: number
): Promise<HealthStatus> {
  const startTime = Date.now()
  const result: HealthStatus = {
    id: def.id,
    name: def.name,
    category: def.category,
    available: false,
    checkedAt: Date.now(),
  }

  // HTTP probe check
  if (def.httpProbe) {
    try {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeout)
      const response = await fetch(def.httpProbe, { signal: controller.signal })
      clearTimeout(timer)
      result.latency = Date.now() - startTime
      result.available = response.ok
      if (!response.ok) {
        result.error = `HTTP ${response.status}`
      }
    } catch (err) {
      result.latency = Date.now() - startTime
      result.available = false
      if (err instanceof Error) {
        result.error = err.name === "AbortError" ? "timeout" : err.message
      } else {
        result.error = String(err)
      }
    }
    return result
  }

  try {
    // Use Bun.spawn with proper timeout handling
    const proc = Bun.spawn([def.command!, ...(def.args ?? [])], {
      stdout: "pipe",
      stderr: "pipe",
    })

    // Race between process completion and timeout
    const timeoutPromise = new Promise<"timeout">((resolve) => {
      setTimeout(() => resolve("timeout"), timeout)
    })

    const processPromise = (async () => {
      const exitCode = await proc.exited
      const stdout = await new Response(proc.stdout).text()
      const stderr = await new Response(proc.stderr).text()
      return { exitCode, stdout, stderr }
    })()

    const raceResult = await Promise.race([processPromise, timeoutPromise])

    result.latency = Date.now() - startTime

    if (raceResult === "timeout") {
      proc.kill()
      result.available = false
      result.error = "timeout"
    } else {
      const { exitCode, stdout, stderr } = raceResult
      const output = stdout || stderr

      if (exitCode === 0 || output.length > 0) {
        const version = def.versionParser?.(output)
        result.available = true
        result.version = version
      } else {
        result.available = false
        result.error = `exit code ${exitCode}`
      }
    }
  } catch (err) {
    result.latency = Date.now() - startTime
    result.available = false

    if (err instanceof Error) {
      // Check for command not found
      if (err.message.includes("spawn") || err.message.includes("ENOENT") || err.message.includes("not found")) {
        result.error = "not found"
      } else {
        result.error = err.message
      }
    } else {
      result.error = String(err)
    }
  }

  return result
}

/**
 * Health namespace - Integration healthchecks
 */
export namespace Health {
  /**
   * Check all integrations in parallel
   */
  export async function checkAll(
    options: HealthCheckOptions = {}
  ): Promise<HealthSummary> {
    const { force = false, timeout = 3000 } = options
    const now = Date.now()

    // Return cached if fresh and not forced
    if (!force && now - lastFullCheck < CACHE_TTL && healthCache.size > 0) {
      return getSummary()
    }

    // Check all integrations in parallel
    const checks = getIntegrations().map((def) => checkIntegration(def, timeout))
    const results = await Promise.all(checks)

    // Update cache
    for (const result of results) {
      healthCache.set(result.id, result)
    }
    lastFullCheck = now

    return getSummary()
  }

  /**
   * Check a single integration
   */
  export async function check(
    id: string,
    options: HealthCheckOptions = {}
  ): Promise<HealthStatus | undefined> {
    const { force = false, timeout = 3000 } = options

    // Return cached if fresh and not forced
    const cached = healthCache.get(id)
    if (!force && cached && Date.now() - cached.checkedAt < CACHE_TTL) {
      return cached
    }

    // Find integration definition
    const def = getIntegrations().find((i) => i.id === id)
    if (!def) {
      return undefined
    }

    // Check and cache
    const result = await checkIntegration(def, timeout)
    healthCache.set(id, result)
    return result
  }

  /**
   * Get cached health summary (no new checks)
   */
  export function getSummary(): HealthSummary {
    const summary: HealthSummary = {
      security: [],
      ai: [],
      infra: [],
      mcp: [],
      checkedAt: lastFullCheck,
    }

    // Group by category
    for (const status of healthCache.values()) {
      if (status.category === "security") {
        summary.security.push(status)
      } else if (status.category === "ai") {
        summary.ai.push(status)
      } else if (status.category === "infra") {
        summary.infra.push(status)
      }
    }

    // Add MCP server status
    summary.mcp.push({
      id: "clawdstrike-mcp",
      name: "ClawdStrike MCP",
      category: "mcp",
      available: mcpServerStatus.running,
      version: mcpServerStatus.port ? `:${mcpServerStatus.port}` : undefined,
      checkedAt: Date.now(),
    })

    // Sort each category by id for consistent order
    summary.security.sort((a, b) => a.id.localeCompare(b.id))
    summary.ai.sort((a, b) => a.id.localeCompare(b.id))
    summary.infra.sort((a, b) => a.id.localeCompare(b.id))

    return summary
  }

  /**
   * Get status for a single integration from cache
   */
  export function getStatus(id: string): HealthStatus | undefined {
    if (id === "clawdstrike-mcp") {
      return {
        id: "clawdstrike-mcp",
        name: "ClawdStrike MCP",
        category: "mcp",
        available: mcpServerStatus.running,
        version: mcpServerStatus.port ? `:${mcpServerStatus.port}` : undefined,
        checkedAt: Date.now(),
      }
    }
    return healthCache.get(id)
  }

  /**
   * Set MCP server status (called by MCP module)
   */
  export function setMcpStatus(running: boolean, port?: number): void {
    mcpServerStatus = { running, port }
  }

  /**
   * Get MCP server status
   */
  export function getMcpStatus(): { running: boolean; port?: number } {
    return { ...mcpServerStatus }
  }

  /**
   * Clear the health cache
   */
  export function clearCache(): void {
    healthCache.clear()
    lastFullCheck = 0
  }

  /**
   * Get list of all integration IDs
   */
  export function getIntegrationIds(): string[] {
    return getIntegrations().map((i) => i.id)
  }

  /**
   * Check if cache is stale
   */
  export function isCacheStale(): boolean {
    return Date.now() - lastFullCheck > CACHE_TTL
  }
}

export default Health
