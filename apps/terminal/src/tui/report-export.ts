import { mkdir, readFile, writeFile } from "node:fs/promises"
import { basename, isAbsolute, join } from "node:path"
import { randomUUID } from "node:crypto"
import type { EvidenceItem, EventSource, HuntReport, RuleSeverity } from "../hunt/types"
import type { AuditEvent } from "../hushd"
export interface ReportExportResult {
  directory: string
  fileStem: string
  jsonPath: string
  markdownPath: string
  historyEntry: ReportHistoryEntry
}

export interface ReportTraceMetadata {
  eventSources: EventSource[]
  receiptIds: string[]
  auditEventIds: string[]
  sessionIds: string[]
}

export interface ReportTraceability {
  exportAuditEventId: string
  auditStatus: "recorded" | "degraded" | "not_configured"
  auditRecordedAt?: string
  error?: string
}

export interface ReportHistoryEntry {
  version: 1
  reportId: string
  title: string
  severity: RuleSeverity
  summary: string
  reportCreatedAt: string
  exportedAt: string
  evidenceCount: number
  merkleRoot?: string
  investigationOrigin?: string | null
  jsonPath: string
  markdownPath: string
  trace: ReportTraceMetadata
  traceability: ReportTraceability
}

const REPORTS_DIR = ".clawdstrike/reports"
const REPORT_HISTORY_FILE = "index.jsonl"

function sanitizeFilePart(value: string, fallback: string): string {
  const sanitized = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")

  return sanitized || fallback
}

function formatTimestampStem(iso: string): string {
  const timestamp = new Date(iso)
  if (Number.isNaN(timestamp.getTime())) {
    return "report"
  }

  const year = String(timestamp.getUTCFullYear())
  const month = String(timestamp.getUTCMonth() + 1).padStart(2, "0")
  const day = String(timestamp.getUTCDate()).padStart(2, "0")
  const hours = String(timestamp.getUTCHours()).padStart(2, "0")
  const minutes = String(timestamp.getUTCMinutes()).padStart(2, "0")
  const seconds = String(timestamp.getUTCSeconds()).padStart(2, "0")
  return `${year}${month}${day}-${hours}${minutes}${seconds}z`
}

function buildFileStem(report: HuntReport): string {
  const timestamp = formatTimestampStem(report.created_at)
  const id = sanitizeFilePart(report.id, "report")
  return `${timestamp}-${id}`.slice(0, 80)
}

function firstString(details: Record<string, unknown>, keys: string[]): string | null {
  for (const key of keys) {
    const value = details[key]
    if (typeof value === "string" && value.length > 0) {
      return value
    }
  }

  return null
}

function getInvestigationOrigin(report: HuntReport): string | null {
  if (!report.alert.rule.startsWith("investigation:")) {
    return null
  }

  return report.alert.rule.slice("investigation:".length) || null
}

export function deriveTraceMetadata(report: HuntReport): ReportTraceMetadata {
  const sources = new Set<EventSource>()
  const receiptIds = new Set<string>()
  const auditEventIds = new Set<string>()
  const sessionIds = new Set<string>()

  for (const item of report.evidence) {
    sources.add(item.event.source)

    const receiptId = firstString(item.event.details, ["receipt_id", "receiptId"])
    if (receiptId) {
      receiptIds.add(receiptId)
    }

    const auditId = firstString(item.event.details, ["audit_id", "auditId", "event_id", "eventId"])
    if (auditId) {
      auditEventIds.add(auditId)
    }

    const sessionId = firstString(item.event.details, ["session_id", "sessionId", "run_id", "runId", "task_id", "taskId"])
    if (sessionId) {
      sessionIds.add(sessionId)
    }
  }

  return {
    eventSources: [...sources],
    receiptIds: [...receiptIds],
    auditEventIds: [...auditEventIds],
    sessionIds: [...sessionIds],
  }
}

function renderTraceMarkdown(
  trace: ReportTraceMetadata,
  traceability?: ReportTraceability,
): string[] {
  const lines: string[] = ["## Trace Metadata", ""]

  if (trace.eventSources.length > 0) {
    lines.push(`- Sources: ${trace.eventSources.join(", ")}`)
  }
  if (trace.receiptIds.length > 0) {
    lines.push(`- Receipt IDs: ${trace.receiptIds.join(", ")}`)
  }
  if (trace.auditEventIds.length > 0) {
    lines.push(`- Audit Event IDs: ${trace.auditEventIds.join(", ")}`)
  }
  if (trace.sessionIds.length > 0) {
    lines.push(`- Session IDs: ${trace.sessionIds.join(", ")}`)
  }
  if (traceability) {
    lines.push(`- Export Audit Event ID: ${traceability.exportAuditEventId}`)
    lines.push(`- Export Audit Status: ${traceability.auditStatus}`)
    if (traceability.auditRecordedAt) {
      lines.push(`- Export Audit Recorded At: ${traceability.auditRecordedAt}`)
    }
    if (traceability.error) {
      lines.push(`- Export Audit Error: ${traceability.error}`)
    }
  }
  if (lines.length === 2) {
    lines.push("- No receipt or audit metadata was captured in the exported evidence.")
  }
  lines.push("")
  return lines
}

function getReportsDirectory(cwd: string): string {
  return join(cwd, REPORTS_DIR)
}

function getHistoryIndexPath(cwd: string): string {
  return join(getReportsDirectory(cwd), REPORT_HISTORY_FILE)
}

function relativeReportPath(cwd: string, absolutePath: string): string {
  const reportsDir = getReportsDirectory(cwd)
  if (absolutePath.startsWith(reportsDir)) {
    return join(REPORTS_DIR, basename(absolutePath))
  }

  return absolutePath
}

function resolveHistoryPath(cwd: string, pathValue: string): string {
  return isAbsolute(pathValue) ? pathValue : join(cwd, pathValue)
}

function buildHistoryEntry(
  report: HuntReport,
  cwd: string,
  jsonPath: string,
  markdownPath: string,
): ReportHistoryEntry {
  return {
    version: 1,
    reportId: report.id,
    title: report.title,
    severity: report.severity,
    summary: report.summary,
    reportCreatedAt: report.created_at,
    exportedAt: new Date().toISOString(),
    evidenceCount: report.evidence.length,
    merkleRoot: report.merkle_root,
    investigationOrigin: getInvestigationOrigin(report),
    jsonPath: relativeReportPath(cwd, jsonPath),
    markdownPath: relativeReportPath(cwd, markdownPath),
    trace: deriveTraceMetadata(report),
    traceability: {
      exportAuditEventId: randomUUID(),
      auditStatus: "not_configured",
    },
  }
}

async function writeHistoryEntries(cwd: string, entries: ReportHistoryEntry[]): Promise<void> {
  const indexPath = getHistoryIndexPath(cwd)
  await writeFile(
    indexPath,
    entries.map((item) => JSON.stringify(item)).join("\n") + "\n",
    "utf8",
  )
}

async function appendHistoryEntry(cwd: string, entry: ReportHistoryEntry): Promise<void> {
  const history = await readReportHistory(cwd)
  history.unshift(entry)
  await writeHistoryEntries(cwd, history)
}

function markdownValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "null"
  }

  if (typeof value === "string") {
    return value
  }

  if (typeof value === "number" || typeof value === "boolean") {
    return String(value)
  }

  return JSON.stringify(value)
}

function renderEvidenceMarkdown(item: EvidenceItem): string[] {
  const lines = [
    `### Evidence #${item.index}`,
    `- Summary: ${item.event.summary}`,
    `- Verdict: ${item.event.verdict}`,
    `- Source: ${item.event.source}`,
    `- Kind: ${item.event.kind}`,
    `- Timestamp: ${item.event.timestamp}`,
    `- Relevance: ${item.relevance}`,
  ]

  const detailEntries = Object.entries(item.event.details)
  if (detailEntries.length > 0) {
    lines.push("- Details:")
    for (const [key, value] of detailEntries) {
      lines.push(`  - ${key}: ${markdownValue(value)}`)
    }
  }

  if (item.merkle_proof && item.merkle_proof.length > 0) {
    lines.push("- Merkle Proof:")
    for (const proof of item.merkle_proof) {
      lines.push(`  - ${proof}`)
    }
  }

  return lines
}

export function renderReportMarkdown(
  report: HuntReport,
  trace = deriveTraceMetadata(report),
  traceability?: ReportTraceability,
): string {
  const lines: string[] = [
    `# ${report.title}`,
    "",
    `- ID: ${report.id}`,
    `- Severity: ${report.severity}`,
    `- Created: ${report.created_at}`,
    `- Rule: ${report.alert.rule}`,
    `- Evidence Count: ${report.evidence.length}`,
    "",
    "## Summary",
    "",
    report.summary,
    "",
  ]

  if (report.recommendations && report.recommendations.length > 0) {
    lines.push("## Recommendations", "")
    for (const recommendation of report.recommendations) {
      lines.push(`- ${recommendation}`)
    }
    lines.push("")
  }

  lines.push("## Evidence", "")
  for (const item of report.evidence) {
    lines.push(...renderEvidenceMarkdown(item), "")
  }

  if (report.merkle_root) {
    lines.push("## Merkle Root", "", report.merkle_root, "")
  }

  lines.push(...renderTraceMarkdown(trace, traceability))

  return `${lines.join("\n").trimEnd()}\n`
}

export async function readReportHistory(cwd: string): Promise<ReportHistoryEntry[]> {
  try {
    const indexPath = getHistoryIndexPath(cwd)
    const content = await readFile(indexPath, "utf8")
    return content
      .split("\n")
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
      .map((line) => {
        try {
          return JSON.parse(line) as ReportHistoryEntry
        } catch {
          return null
        }
      })
      .filter((entry): entry is ReportHistoryEntry => entry !== null)
      .sort((a, b) => b.exportedAt.localeCompare(a.exportedAt))
  } catch {
    return []
  }
}

export async function loadExportedReport(cwd: string, entry: ReportHistoryEntry): Promise<HuntReport> {
  const raw = await readFile(resolveHistoryPath(cwd, entry.jsonPath), "utf8")
  return JSON.parse(raw) as HuntReport
}

function severityToAuditLevel(severity: RuleSeverity): AuditEvent["severity"] {
  switch (severity) {
    case "critical":
      return "critical"
    case "high":
      return "error"
    case "medium":
      return "warning"
    case "low":
    default:
      return "info"
  }
}

export function buildReportExportAuditEvent(
  report: HuntReport,
  entry: ReportHistoryEntry,
): AuditEvent {
  return {
    id: entry.traceability.exportAuditEventId,
    timestamp: entry.exportedAt,
    event_type: "report_export",
    action_type: "report_export",
    target: entry.reportId,
    decision: "allowed",
    severity: severityToAuditLevel(report.severity),
    message: `Investigation report exported: ${entry.title}`,
    session_id: entry.trace.sessionIds[0] ?? null,
    agent_id: null,
    metadata: {
      report_id: entry.reportId,
      title: entry.title,
      summary: entry.summary,
      severity: entry.severity,
      investigation_origin: entry.investigationOrigin ?? null,
      report_created_at: entry.reportCreatedAt,
      exported_at: entry.exportedAt,
      markdown_path: entry.markdownPath,
      json_path: entry.jsonPath,
      merkle_root: entry.merkleRoot ?? null,
      receipt_ids: entry.trace.receiptIds,
      audit_event_ids: entry.trace.auditEventIds,
      session_ids: entry.trace.sessionIds,
      event_sources: entry.trace.eventSources,
    },
  }
}

export async function updateReportHistoryTraceability(
  cwd: string,
  entry: ReportHistoryEntry,
  traceability: ReportTraceability,
): Promise<ReportHistoryEntry> {
  const history = await readReportHistory(cwd)
  const updated = history.map((item) => (
    item.reportId === entry.reportId && item.exportedAt === entry.exportedAt
      ? { ...item, traceability }
      : item
  ))
  await writeHistoryEntries(cwd, updated)
  return updated.find((item) => item.reportId === entry.reportId && item.exportedAt === entry.exportedAt)
    ?? { ...entry, traceability }
}

export async function syncExportedReportMarkdown(
  cwd: string,
  report: HuntReport,
  entry: ReportHistoryEntry,
): Promise<void> {
  await writeFile(
    resolveHistoryPath(cwd, entry.markdownPath),
    renderReportMarkdown(report, entry.trace, entry.traceability),
    "utf8",
  )
}

export async function exportReportBundle(
  report: HuntReport,
  cwd: string,
): Promise<ReportExportResult> {
  const directory = getReportsDirectory(cwd)
  const fileStem = buildFileStem(report)
  const jsonPath = join(directory, `${fileStem}.json`)
  const markdownPath = join(directory, `${fileStem}.md`)
  const historyEntry = buildHistoryEntry(report, cwd, jsonPath, markdownPath)

  await mkdir(directory, { recursive: true })
  await Promise.all([
    writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8"),
    writeFile(markdownPath, renderReportMarkdown(report, historyEntry.trace, historyEntry.traceability), "utf8"),
  ])
  await appendHistoryEntry(cwd, historyEntry)

  return {
    directory,
    fileStem,
    jsonPath,
    markdownPath,
    historyEntry,
  }
}
