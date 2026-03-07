// hunt/bridge-correlate.ts - Correlation and watch mode bridge wrapper

import { extractHuntEnvelopeData, runHuntCommand, spawnHuntStream, type HuntStreamHandle } from "./bridge"
import type { Alert, TimelineEvent, WatchJsonLine, WatchStats } from "./types"

export interface CorrelateOptions {
  rules: string[]
  since?: string
  until?: string
}

export interface WatchOptions {
  cwd?: string
  natsUrl?: string
  natsCreds?: string
  natsToken?: string
  natsNkeySeed?: string
}

export interface WatchCallbacks {
  onEvent: (event: TimelineEvent) => void
  onAlert: (alert: Alert) => void
  onStats?: (stats: WatchStats) => void
  onError?: (error: string) => void
}

interface HuntCorrelatePayload {
  alerts?: Alert[]
}

export async function runCorrelate(opts: CorrelateOptions): Promise<Alert[]> {
  const args = ["correlate"]
  for (const rule of opts.rules) args.push("--rules", rule)
  if (opts.since) args.push("--since", opts.since)
  if (opts.until) args.push("--until", opts.until)
  const result = await runHuntCommand<HuntCorrelatePayload>(args)
  return extractHuntEnvelopeData<HuntCorrelatePayload>(result.data)?.alerts ?? []
}

export function startWatch(
  rules: string[],
  callbacks: WatchCallbacks,
  opts?: WatchOptions,
): HuntStreamHandle {
  const args = ["watch"]
  const env: Record<string, string> = {}
  for (const rule of rules) args.push("--rules", rule)
  if (opts?.natsUrl) args.push("--nats-url", opts.natsUrl)
  if (opts?.natsCreds) args.push("--nats-creds", opts.natsCreds)
  if (opts?.natsToken) env.CLAWDSTRIKE_HUNT_NATS_TOKEN = opts.natsToken
  if (opts?.natsNkeySeed) env.CLAWDSTRIKE_HUNT_NATS_NKEY_SEED = opts.natsNkeySeed
  return spawnHuntStream(
    args,
    (line: WatchJsonLine) => {
      if (line.type === "event") callbacks.onEvent(line.data)
      else if (line.type === "alert") callbacks.onAlert(line.data)
      else if (line.type === "stats" && callbacks.onStats) callbacks.onStats(line.data)
    },
    (error) => {
      callbacks.onError?.(error)
    },
    {
      cwd: opts?.cwd,
      env: Object.keys(env).length > 0 ? env : undefined,
    },
  )
}
