// hunt/bridge-query.ts - Timeline query bridge wrapper

import { runHuntCommand } from "./bridge"
import type { TimelineEvent, EventSource, NormalizedVerdict } from "./types"

export interface QueryFilters {
  nl?: string
  source?: EventSource
  verdict?: NormalizedVerdict
  kind?: string
  since?: string
  until?: string
  limit?: number
}

export async function runQuery(filters: QueryFilters): Promise<TimelineEvent[]> {
  const args = ["query"]
  if (filters.nl) args.push(filters.nl)
  if (filters.source) args.push("--source", filters.source)
  if (filters.verdict) args.push("--verdict", filters.verdict)
  if (filters.kind) args.push("--kind", filters.kind)
  if (filters.since) args.push("--since", filters.since)
  if (filters.until) args.push("--until", filters.until)
  if (filters.limit) args.push("--limit", String(filters.limit))
  const result = await runHuntCommand<TimelineEvent[]>(args)
  return result.data ?? []
}

export async function runTimeline(filters: QueryFilters): Promise<TimelineEvent[]> {
  const args = ["timeline"]
  if (filters.source) args.push("--source", filters.source)
  if (filters.verdict) args.push("--verdict", filters.verdict)
  if (filters.since) args.push("--since", filters.since)
  if (filters.until) args.push("--until", filters.until)
  if (filters.limit) args.push("--limit", String(filters.limit))
  const result = await runHuntCommand<TimelineEvent[]>(args)
  return result.data ?? []
}
