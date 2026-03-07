// hunt/bridge-query.ts - Timeline query bridge wrapper

import { extractHuntEnvelopeData, runHuntCommand } from "./bridge"
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

interface HuntQueryPayload {
  events?: TimelineEvent[]
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
  const result = await runHuntCommand<HuntQueryPayload>(args)
  return extractHuntEnvelopeData<HuntQueryPayload>(result.data)?.events ?? []
}

export async function runTimeline(filters: QueryFilters): Promise<TimelineEvent[]> {
  const args = ["timeline"]
  if (filters.source) args.push("--source", filters.source)
  if (filters.verdict) args.push("--verdict", filters.verdict)
  if (filters.since) args.push("--since", filters.since)
  if (filters.until) args.push("--until", filters.until)
  if (filters.limit) args.push("--limit", String(filters.limit))
  const result = await runHuntCommand<HuntQueryPayload>(args)
  return extractHuntEnvelopeData<HuntQueryPayload>(result.data)?.events ?? []
}
