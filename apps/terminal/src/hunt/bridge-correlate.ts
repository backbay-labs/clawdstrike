// hunt/bridge-correlate.ts - Correlation and watch mode bridge wrapper

import { runHuntCommand, spawnHuntStream, type HuntStreamHandle } from "./bridge"
import type { Alert, TimelineEvent, WatchJsonLine, WatchStats } from "./types"

export interface CorrelateOptions {
  rules: string[]
  since?: string
  until?: string
}

export async function runCorrelate(opts: CorrelateOptions): Promise<Alert[]> {
  const args = ["correlate"]
  for (const rule of opts.rules) args.push("--rules", rule)
  if (opts.since) args.push("--since", opts.since)
  if (opts.until) args.push("--until", opts.until)
  const result = await runHuntCommand<Alert[]>(args)
  return result.data ?? []
}

export function startWatch(
  rules: string[],
  onEvent: (event: TimelineEvent) => void,
  onAlert: (alert: Alert) => void,
  onStats?: (stats: WatchStats) => void,
): HuntStreamHandle {
  const args = ["watch"]
  for (const rule of rules) args.push("--rules", rule)
  return spawnHuntStream(
    args,
    (line: WatchJsonLine) => {
      if (line.type === "event") onEvent(line.data)
      else if (line.type === "alert") onAlert(line.data)
      else if (line.type === "stats" && onStats) onStats(line.data)
    },
    (error) => {
      console.error("Watch error:", error)
    },
  )
}
