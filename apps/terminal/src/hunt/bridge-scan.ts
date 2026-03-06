// hunt/bridge-scan.ts - MCP scan bridge wrapper

import { extractHuntEnvelopeData, runHuntCommand } from "./bridge"
import type { ScanPathResult, ScanDiff } from "./types"

export interface ScanOptions {
  targets?: string[]
  policy?: string
  timeout?: number
}

interface RawTool {
  name: string
  description?: string
  inputSchema?: Record<string, unknown>
}

interface RawSignature {
  metadata?: {
    serverInfo?: {
      name?: string
      version?: string
    }
  }
  tools?: RawTool[]
  prompts?: Array<string | { name?: string }>
  resources?: Array<string | { name?: string; uri?: string }>
}

interface RawServerConfig {
  command?: string
  args?: string[]
  env?: Record<string, string>
}

interface RawServerScanResult {
  name: string
  server?: RawServerConfig
  signature?: RawSignature
  issues?: import("./types").Issue[]
  policy_violations?: import("./types").PolicyViolation[]
  error?: {
    message?: string
    exception?: string
    category?: string
  }
}

interface RawScanPathResult {
  client?: string | null
  path: string
  servers?: RawServerScanResult[] | null
  issues?: import("./types").Issue[]
  error?: {
    message?: string
    exception?: string
    category?: string
  } | null
}

interface HuntScanPayload {
  scan_results?: RawScanPathResult[]
  changes?: ScanDiff
}

function describeScanError(error: RawScanPathResult["error"] | RawServerScanResult["error"]): string {
  if (!error) return "Unknown scan error"
  return [error.category, error.exception, error.message].filter(Boolean).join(": ")
}

function normalizeSignature(signature: RawSignature | undefined) {
  if (!signature) return undefined

  return {
    name: signature.metadata?.serverInfo?.name ?? "unknown",
    version: signature.metadata?.serverInfo?.version,
    tools: (signature.tools ?? []).map((tool) => ({
      name: tool.name,
      description: tool.description,
      input_schema: tool.inputSchema,
    })),
    prompts: (signature.prompts ?? []).map((prompt) => typeof prompt === "string" ? prompt : (prompt.name ?? "prompt")),
    resources: (signature.resources ?? []).map((resource) => {
      if (typeof resource === "string") return resource
      return resource.name ?? resource.uri ?? "resource"
    }),
  }
}

export function normalizeScanResults(results: RawScanPathResult[]): ScanPathResult[] {
  return results.map((result) => ({
    client: result.client ?? "unknown",
    path: result.path,
    servers: (result.servers ?? []).map((server) => ({
      name: server.name,
      command: server.server?.command ?? "unknown",
      args: server.server?.args ?? [],
      env: server.server?.env,
      signature: normalizeSignature(server.signature),
      issues: server.issues ?? [],
      violations: server.policy_violations ?? [],
      error: server.error ? describeScanError(server.error) : undefined,
    })),
    issues: result.issues ?? [],
    errors: result.error
      ? [{ path: result.path, error: describeScanError(result.error) }]
      : [],
  }))
}

export async function runScan(opts?: ScanOptions): Promise<ScanPathResult[]> {
  const args = ["scan"]
  if (opts?.targets) args.push(...opts.targets)
  if (opts?.policy) args.push("--policy", opts.policy)
  const result = await runHuntCommand<HuntScanPayload>(args, {
    timeout: opts?.timeout,
  })
  const payload = extractHuntEnvelopeData<HuntScanPayload>(result.data)
  return normalizeScanResults(payload?.scan_results ?? [])
}

export interface DiffOptions {
  baseline: string
  current?: string
  timeout?: number
}

export async function runScanDiff(opts: DiffOptions): Promise<ScanDiff | undefined> {
  const args = ["scan", "diff", "--baseline", opts.baseline]
  if (opts.current) args.push("--current", opts.current)
  const result = await runHuntCommand<HuntScanPayload>(args, {
    timeout: opts.timeout,
  })
  return extractHuntEnvelopeData<HuntScanPayload>(result.data)?.changes
}
