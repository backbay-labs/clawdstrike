// hunt/bridge-scan.ts - MCP scan bridge wrapper

import { runHuntCommand } from "./bridge"
import type { ScanPathResult, ScanDiff } from "./types"

export interface ScanOptions {
  targets?: string[]
  policy?: string
  timeout?: number
}

export async function runScan(opts?: ScanOptions): Promise<ScanPathResult[]> {
  const args = ["scan"]
  if (opts?.targets) args.push(...opts.targets)
  if (opts?.policy) args.push("--policy", opts.policy)
  const result = await runHuntCommand<ScanPathResult[]>(args, {
    timeout: opts?.timeout,
  })
  return result.data ?? []
}

export interface DiffOptions {
  baseline: string
  current?: string
  timeout?: number
}

export async function runScanDiff(opts: DiffOptions): Promise<ScanDiff | undefined> {
  const args = ["scan", "diff", "--baseline", opts.baseline]
  if (opts.current) args.push("--current", opts.current)
  const result = await runHuntCommand<ScanDiff>(args, {
    timeout: opts.timeout,
  })
  return result.data
}
