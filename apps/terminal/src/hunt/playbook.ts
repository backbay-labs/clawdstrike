// hunt/playbook.ts - Playbook builder and executor

import type { PlaybookStep, PlaybookResult, TimelineEvent, Alert } from "./types"
import { runTimeline } from "./bridge-query"
import { runCorrelate } from "./bridge-correlate"
import { runIoc } from "./bridge-ioc"

export interface PlaybookConfig {
  name: string
  description?: string
  timeRange?: string   // e.g., "24h"
  rules?: string[]     // Rule file paths
  iocFeeds?: string[]  // IOC feed paths
}

export function buildDefaultPlaybook(_config: PlaybookConfig): PlaybookStep[] {
  return [
    { name: "Query Events", description: "Fetch timeline events", command: "hunt", args: ["timeline"], status: "pending" },
    { name: "Filter & Analyze", description: "Filter events by severity", command: "hunt", args: ["query"], status: "pending" },
    { name: "Correlate", description: "Run correlation rules", command: "hunt", args: ["correlate"], status: "pending" },
    { name: "IOC Match", description: "Match against IOC feeds", command: "hunt", args: ["ioc"], status: "pending" },
    { name: "Generate Report", description: "Build evidence report", command: "report", args: [], status: "pending" },
  ]
}

export async function executePlaybook(
  config: PlaybookConfig,
  steps: PlaybookStep[],
  onStepUpdate: (index: number, step: PlaybookStep) => void,
): Promise<PlaybookResult> {
  const started_at = new Date().toISOString()
  let events: TimelineEvent[] = []
  let alerts: Alert[] = []
  let success = true

  for (let i = 0; i < steps.length; i++) {
    const step: PlaybookStep = { ...steps[i], status: "running" }
    onStepUpdate(i, step)

    const startTime = Date.now()
    try {
      switch (i) {
        case 0: { // Query timeline
          events = await runTimeline({ since: config.timeRange })
          step.output = { eventCount: events.length }
          break
        }
        case 1: { // Filter
          const denied = events.filter(e => e.verdict === "deny")
          step.output = { filtered: denied.length, total: events.length }
          events = denied.length > 0 ? denied : events
          break
        }
        case 2: { // Correlate
          if (config.rules && config.rules.length > 0) {
            alerts = await runCorrelate({ rules: config.rules })
          }
          step.output = { alertCount: alerts.length }
          break
        }
        case 3: { // IOC
          if (config.iocFeeds && config.iocFeeds.length > 0) {
            const matches = await runIoc({ feeds: config.iocFeeds })
            step.output = { matchCount: matches.length }
          } else {
            step.output = { matchCount: 0, skipped: true }
          }
          break
        }
        case 4: { // Report
          step.output = { events: events.length, alerts: alerts.length }
          break
        }
      }
      step.status = "passed"
      step.duration_ms = Date.now() - startTime
    } catch (err) {
      step.status = "failed"
      step.error = err instanceof Error ? err.message : String(err)
      step.duration_ms = Date.now() - startTime
      success = false
    }
    onStepUpdate(i, step)
  }

  return {
    name: config.name,
    steps,
    started_at,
    completed_at: new Date().toISOString(),
    success,
  }
}
