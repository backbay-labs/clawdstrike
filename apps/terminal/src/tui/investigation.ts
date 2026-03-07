import { createHash } from "node:crypto"
import type { Alert, HuntReport, RuleSeverity, TimelineEvent } from "../hunt/types"
import type { AppState, HuntInvestigationState } from "./types"

const INVESTIGATION_EVENT_LIMIT = 50
const INVESTIGATION_STALE_MS = 5 * 60_000

export interface InvestigationUpdate {
  origin: HuntInvestigationState["origin"]
  title: string
  summary?: string | null
  query?: string | null
  events?: TimelineEvent[]
  findings?: string[]
}

function clampEvents(events: TimelineEvent[]): TimelineEvent[] {
  if (events.length <= INVESTIGATION_EVENT_LIMIT) {
    return events
  }

  return events.slice(-INVESTIGATION_EVENT_LIMIT)
}

function deriveSeverity(investigation: HuntInvestigationState): RuleSeverity {
  const hasDenied = investigation.events.some((event) => event.verdict === "deny")
  if (hasDenied) {
    return investigation.events.length > 10 ? "critical" : "high"
  }

  if (investigation.findings.length > 0) {
    return "medium"
  }

  return investigation.events.length > 0 ? "low" : "medium"
}

function buildSyntheticAlert(
  investigation: HuntInvestigationState,
  severity: RuleSeverity,
): Alert {
  const matchedEvents = clampEvents(investigation.events)

  return {
    rule: investigation.origin ? `investigation:${investigation.origin}` : "investigation:manual",
    severity,
    timestamp: investigation.updatedAt ?? new Date().toISOString(),
    title: investigation.title || "Investigation Report",
    description: investigation.summary ?? undefined,
    matched_events: matchedEvents,
    evidence: {
      query: investigation.query ?? undefined,
      findings: investigation.findings,
    },
    mitre_attack: [],
  }
}

function hashParts(parts: string[]): string {
  const hash = createHash("sha256")
  for (const part of parts) {
    hash.update(part)
  }
  return hash.digest("hex")
}

export function updateInvestigation(state: AppState, update: InvestigationUpdate): void {
  const existing = state.hunt.investigation

  state.hunt.investigation = {
    origin: update.origin,
    title: update.title,
    summary: update.summary ?? existing.summary,
    query: update.query ?? existing.query,
    events: clampEvents(update.events ?? existing.events),
    findings: update.findings ?? existing.findings,
    updatedAt: new Date().toISOString(),
  }
}

export function appendInvestigationEvent(
  state: AppState,
  event: TimelineEvent,
  update: Omit<InvestigationUpdate, "events">,
): void {
  const existing = state.hunt.investigation
  const events = [...existing.events, event]

  updateInvestigation(state, {
    ...update,
    events,
  })
}

export function clearInvestigation(state: AppState): void {
  state.hunt.investigation = {
    origin: null,
    title: "",
    summary: null,
    query: null,
    events: [],
    findings: [],
    updatedAt: null,
  }
}

export function getInvestigationCounts(investigation: HuntInvestigationState): {
  events: number
  findings: number
} {
  return {
    events: investigation.events.length,
    findings: investigation.findings.length,
  }
}

export function isInvestigationStale(
  investigation: HuntInvestigationState,
  now = Date.now(),
): boolean {
  if (!investigation.updatedAt) {
    return false
  }

  const updatedAt = new Date(investigation.updatedAt).getTime()
  if (Number.isNaN(updatedAt)) {
    return false
  }

  return now - updatedAt > INVESTIGATION_STALE_MS
}

export function buildInvestigationReport(state: AppState): HuntReport | null {
  const investigation = state.hunt.investigation
  const counts = getInvestigationCounts(investigation)

  if (!investigation.title && counts.events === 0 && counts.findings === 0) {
    return null
  }

  const severity = deriveSeverity(investigation)
  const alert = buildSyntheticAlert(investigation, severity)
  const evidence = clampEvents(investigation.events).map((event, index) => ({
    index: index + 1,
    event,
    relevance:
      event.verdict === "deny"
        ? "blocked action"
        : event.verdict === "audit"
          ? "review required"
          : "supporting context",
    merkle_proof: [
      hashParts([event.timestamp, event.source, event.summary]),
    ],
  }))

  const title = investigation.title || "Investigation Report"
  const createdAt = investigation.updatedAt ?? new Date().toISOString()
  const merkleRoot = hashParts([
    title,
    createdAt,
    investigation.summary ?? "",
    ...investigation.findings,
    ...evidence.map((item) => item.merkle_proof?.[0] ?? item.event.summary),
  ])

  const recommendations = new Set<string>()
  if (investigation.findings.length > 0) {
    recommendations.add("Review flagged findings before applying agent changes.")
  }
  if (investigation.events.some((event) => event.verdict === "deny")) {
    recommendations.add("Inspect denied actions and tighten the relevant allowlists or policies.")
  }
  if (investigation.origin === "scan") {
    recommendations.add("Remove unused MCP tools and re-run the scan after policy changes.")
  }
  if (investigation.query) {
    recommendations.add(`Save the query "${investigation.query}" as a reusable starting filter.`)
  }

  return {
    id: `investigation-${merkleRoot.slice(0, 12)}`,
    title,
    severity,
    created_at: createdAt,
    alert,
    evidence,
    merkle_root: merkleRoot,
    summary:
      investigation.summary ??
      `${counts.events} event(s) and ${counts.findings} finding(s) collected from ${investigation.origin ?? "the current investigation"}.`,
    recommendations: [...recommendations],
  }
}
