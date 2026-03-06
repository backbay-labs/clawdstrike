/**
 * Hunt Report Screen - Evidence report viewer with expand/collapse and export.
 */

import { THEME } from "../theme"
import { relative } from "node:path"
import type { Screen, ScreenContext } from "../types"
import type { EvidenceItem, RuleSeverity } from "../../hunt/types"
import { Hushd } from "../../hushd"
import type { ListItem } from "../components/scrollable-list"
import { renderBox } from "../components/box"
import { fitString } from "../components/types"
import { buildInvestigationReport, updateInvestigation } from "../investigation"
import { renderSurfaceHeader } from "../components/surface-header"
import { scrollReportViewport, syncReportViewport, type ReportRowSpan } from "../report-view"
import {
  buildReportExportAuditEvent,
  exportReportBundle,
  syncExportedReportMarkdown,
  updateReportHistoryTraceability,
} from "../report-export"

const SEVERITY_COLORS: Record<RuleSeverity, string> = {
  low: THEME.muted,
  medium: THEME.warning,
  high: THEME.warning,
  critical: THEME.error,
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso)
    return d.toLocaleString()
  } catch {
    return iso
  }
}

function evidenceToListItem(item: EvidenceItem, expanded: boolean): ListItem {
  const expandIcon = expanded ? "\u25BC" : "\u25B6"
  const verdictColor = item.event.verdict === "deny" ? THEME.error
    : item.event.verdict === "allow" ? THEME.success
    : item.event.verdict === "audit" ? THEME.warning
    : THEME.dim
  const label =
    `${THEME.muted}${expandIcon}${THEME.reset} ` +
    `${THEME.secondary}#${item.index}${THEME.reset} ` +
    `${verdictColor}[${item.event.verdict}]${THEME.reset} ` +
    `${THEME.white}${item.event.summary}${THEME.reset} ` +
    `${THEME.dim}- ${item.relevance}${THEME.reset}`
  const plain = `${expandIcon} #${item.index} [${item.event.verdict}] ${item.event.summary} - ${item.relevance}`
  return { label, plainLength: plain.length }
}

function renderExpandedEvidence(item: EvidenceItem, width: number): string[] {
  const lines: string[] = []
  const indent = "     "
  lines.push(fitString(`${indent}${THEME.dim}Source:${THEME.reset} ${THEME.white}${item.event.source}${THEME.reset}`, width))
  lines.push(fitString(`${indent}${THEME.dim}Kind:${THEME.reset} ${THEME.white}${item.event.kind}${THEME.reset}`, width))
  lines.push(fitString(`${indent}${THEME.dim}Time:${THEME.reset} ${THEME.white}${formatTimestamp(item.event.timestamp)}${THEME.reset}`, width))

  // Show details
  const detailKeys = Object.keys(item.event.details)
  if (detailKeys.length > 0) {
    lines.push(fitString(`${indent}${THEME.dim}Details:${THEME.reset}`, width))
    for (const key of detailKeys.slice(0, 8)) {
      const val = String(item.event.details[key] ?? "")
      const truncVal = val.length > 50 ? val.slice(0, 47) + "..." : val
      lines.push(fitString(`${indent}  ${THEME.tertiary}${key}${THEME.reset}: ${THEME.white}${truncVal}${THEME.reset}`, width))
    }
    if (detailKeys.length > 8) {
      lines.push(fitString(`${indent}  ${THEME.dim}... +${detailKeys.length - 8} more fields${THEME.reset}`, width))
    }
  }

  // Merkle proof
  if (item.merkle_proof && item.merkle_proof.length > 0) {
    lines.push(fitString(`${indent}${THEME.dim}Merkle proof:${THEME.reset}`, width))
    for (const hash of item.merkle_proof.slice(0, 4)) {
      lines.push(fitString(`${indent}  ${THEME.tertiary}${hash}${THEME.reset}`, width))
    }
    if (item.merkle_proof.length > 4) {
      lines.push(fitString(`${indent}  ${THEME.dim}... +${item.merkle_proof.length - 4} more${THEME.reset}`, width))
    }
  }

  lines.push(" ".repeat(width))
  return lines
}

function estimateEvidenceHeight(
  report: NonNullable<ScreenContext["state"]["hunt"]["report"]["report"]>,
  height: number,
  hasError: boolean,
): number {
  const headerLines = (report.summary ? 4 : 3) + 2
  const prefixLines = 2 + (hasError ? 1 : 0) + headerLines
  const trailingReserve = 6
  return Math.max(3, height - prefixLines - trailingReserve)
}

function buildEvidenceLayout(
  report: NonNullable<ScreenContext["state"]["hunt"]["report"]["report"]>,
  selectedIndex: number,
  expandedIndex: number | null,
  innerWidth: number,
): { lines: string[]; rowSpans: ReportRowSpan[] } {
  const lines: string[] = []
  const rowSpans: ReportRowSpan[] = []

  for (let i = 0; i < report.evidence.length; i++) {
    const ev = report.evidence[i]
    const isSelected = i === selectedIndex
    const isExpanded = expandedIndex === i
    const item = evidenceToListItem(ev, isExpanded)
    const rowStart = lines.length

    if (isSelected) {
      const marker = `${THEME.accent}${THEME.bold} ▸ ${THEME.reset}`
      lines.push(fitString(`${marker}${item.label}`, innerWidth - 2))
    } else {
      lines.push(fitString(`   ${item.label}`, innerWidth - 2))
    }

    if (isExpanded) {
      for (const expLine of renderExpandedEvidence(ev, innerWidth - 4)) {
        lines.push(fitString(`   ${expLine}`, innerWidth - 2))
      }
    }

    rowSpans.push({
      start: rowStart,
      end: Math.max(rowStart, lines.length - 1),
    })
  }

  if (lines.length === 0) {
    lines.push(fitString(`${THEME.muted}  (no evidence items)${THEME.reset}`, innerWidth - 2))
  }

  return { lines, rowSpans }
}

function renderEvidenceViewport(
  lines: string[],
  offset: number,
  height: number,
  width: number,
): string[] {
  if (height <= 0) {
    return []
  }

  const hasMoreAbove = offset > 0
  const indicatorLines = hasMoreAbove ? 1 : 0
  const contentHeight = Math.max(1, height - indicatorLines)
  const hasMoreBelow = offset + contentHeight < lines.length
  const adjustedIndicatorLines = indicatorLines + (hasMoreBelow ? 1 : 0)
  const adjustedContentHeight = Math.max(1, height - adjustedIndicatorLines)
  const visible = lines.slice(offset, offset + adjustedContentHeight)
  const output: string[] = []

  if (hasMoreAbove) {
    output.push(fitString(`${THEME.dim}  ▲ more evidence above${THEME.reset}`, width))
  }
  output.push(...visible)
  if (hasMoreBelow) {
    output.push(fitString(`${THEME.dim}  ▼ more evidence below${THEME.reset}`, width))
  }
  while (output.length < height) {
    output.push(" ".repeat(width))
  }
  return output
}

async function exportCurrentReport(ctx: ScreenContext): Promise<void> {
  const current = ctx.state.hunt.report
  if (!current.report) {
    return
  }

  ctx.state.hunt.report = {
    ...current,
    error: null,
    statusMessage: `${THEME.secondary}Exporting report bundle...${THEME.reset}`,
  }
  ctx.app.render()

  try {
    const result = await exportReportBundle(current.report, ctx.app.getCwd())
    let historyEntry = result.historyEntry

    if (ctx.state.hushdConnected) {
      const auditResult = await Hushd.getClient().ingestAuditBatch([
        buildReportExportAuditEvent(current.report, historyEntry),
      ])
      const recorded =
        auditResult.ok &&
        Boolean(auditResult.data) &&
        (auditResult.data?.accepted ?? 0) > 0
      historyEntry = await updateReportHistoryTraceability(
        ctx.app.getCwd(),
        historyEntry,
        {
          ...historyEntry.traceability,
          auditStatus: recorded ? "recorded" : "degraded",
          auditRecordedAt: recorded ? new Date().toISOString() : undefined,
          error: recorded ? undefined : auditResult.error ?? "remote audit ingest failed",
        },
      )
      await syncExportedReportMarkdown(ctx.app.getCwd(), current.report, historyEntry)
    } else {
      const auditStatus = ctx.state.hushdStatus === "not_configured"
        ? "not_configured"
        : "degraded"
      const error = ctx.state.hushdStatus === "unauthorized"
        ? "hushd authorization required"
        : ctx.state.hushdStatus === "not_configured"
          ? "hushd not configured for remote audit export"
          : "hushd unavailable during export"
      historyEntry = await updateReportHistoryTraceability(
        ctx.app.getCwd(),
        historyEntry,
        {
          ...historyEntry.traceability,
          auditStatus,
          error,
        },
      )
      await syncExportedReportMarkdown(ctx.app.getCwd(), current.report, historyEntry)
    }

    ctx.state.hunt.reportHistory.entries = [
      historyEntry,
      ...ctx.state.hunt.reportHistory.entries.filter((entry) => (
        entry.reportId !== historyEntry.reportId || entry.exportedAt !== historyEntry.exportedAt
      )),
    ]

    const relativeMarkdown = relative(ctx.app.getCwd(), result.markdownPath) || result.markdownPath
    const relativeJson = relative(ctx.app.getCwd(), result.jsonPath) || result.jsonPath
    ctx.state.hunt.report = {
      ...ctx.state.hunt.report,
      error: null,
      statusMessage:
        `${THEME.success}Exported report bundle:${THEME.reset} ` +
        `${THEME.white}${relativeMarkdown}${THEME.reset} ${THEME.dim}+${THEME.reset} ` +
        `${THEME.white}${relativeJson}${THEME.reset} ` +
        `${THEME.dim}[audit:${historyEntry.traceability.auditStatus}]${THEME.reset}`,
    }
  } catch (err) {
    ctx.state.hunt.report = {
      ...ctx.state.hunt.report,
      error: err instanceof Error ? err.message : String(err),
      statusMessage: null,
    }
  }

  ctx.app.render()
}

export const huntReportScreen: Screen = {
  onEnter(ctx: ScreenContext): void {
    if (ctx.state.hunt.report.report) {
      return
    }

    const report = buildInvestigationReport(ctx.state)
    if (report) {
      ctx.state.hunt.report = {
        ...ctx.state.hunt.report,
        report,
        error: null,
        statusMessage: null,
      }
      updateInvestigation(ctx.state, {
        origin: "report",
        title: report.title,
        summary: report.summary,
        events: report.alert.matched_events,
        findings: ctx.state.hunt.investigation.findings,
        query: ctx.state.hunt.investigation.query,
      })
    }
  },

  render(ctx: ScreenContext): string {
    const { state, width, height } = ctx
    const rs = state.hunt.report
    const lines: string[] = []

    lines.push(...renderSurfaceHeader("hunt-report", "Evidence Report", width, THEME))

    if (rs.error) {
      lines.push(fitString(`${THEME.error} Error: ${rs.error}${THEME.reset}`, width))
    } else if (rs.statusMessage) {
      lines.push(fitString(` ${rs.statusMessage}`, width))
    }

    // Empty state
    if (!rs.report) {
      const msgY = Math.floor(height / 2) - 1
      for (let i = 2; i < msgY; i++) lines.push(" ".repeat(width))
      lines.push(fitString(`${THEME.muted}  No report loaded.${THEME.reset}`, width))
      lines.push(fitString(`${THEME.dim}  Build investigation context from watch, scan, timeline, or query first.${THEME.reset}`, width))
      for (let i = lines.length; i < height - 1; i++) lines.push(" ".repeat(width))
      lines.push(renderHelpBar(width))
      return lines.join("\n")
    }

    const report = rs.report
    const innerWidth = Math.min(78, width - 4)

    // -- Alert header box --
    const severityColor = SEVERITY_COLORS[report.severity] ?? THEME.muted
    const headerLines: string[] = [
      fitString(`${THEME.white}${THEME.bold}${report.title}${THEME.reset}`, innerWidth - 2),
      fitString(
        `${severityColor}${report.severity.toUpperCase()}${THEME.reset}` +
        `${THEME.dim}  |  ${THEME.reset}` +
        `${THEME.muted}${formatTimestamp(report.created_at)}${THEME.reset}` +
        `${THEME.dim}  |  ${THEME.reset}` +
        `${THEME.muted}ID: ${report.id}${THEME.reset}`,
        innerWidth - 2,
      ),
      fitString(
        `${THEME.dim}Rule: ${THEME.reset}${THEME.white}${report.alert.rule}${THEME.reset}`,
        innerWidth - 2,
      ),
    ]
    if (report.summary) {
      headerLines.push(fitString(`${THEME.muted}${report.summary}${THEME.reset}`, innerWidth - 2))
    }
    const headerBox = renderBox("Report", headerLines, innerWidth, THEME, { style: "double", padding: 1 })
    for (const l of headerBox) lines.push(fitString(`  ${l}`, width))

    const evidenceHeight = estimateEvidenceHeight(report, height, Boolean(rs.error))
    const evidenceLayout = buildEvidenceLayout(
      report,
      rs.list.selected,
      rs.expandedEvidence,
      innerWidth,
    )
    const evidenceViewport = syncReportViewport(
      rs.list,
      rs.list.selected,
      evidenceLayout.rowSpans,
      evidenceHeight,
    )
    const visibleEvidence = renderEvidenceViewport(
      evidenceLayout.lines,
      evidenceViewport.offset,
      evidenceHeight,
      innerWidth - 2,
    )

    const evidenceBox = renderBox(`Evidence (${report.evidence.length})`, visibleEvidence, innerWidth, THEME, { style: "rounded", padding: 1 })
    for (const l of evidenceBox) lines.push(fitString(`  ${l}`, width))

    // -- Merkle root --
    if (report.merkle_root) {
      lines.push(fitString(
        `  ${THEME.dim}Merkle Root:${THEME.reset} ${THEME.tertiary}${report.merkle_root}${THEME.reset}`,
        width,
      ))
    }

    // -- Recommendations --
    if (report.recommendations && report.recommendations.length > 0) {
      lines.push(fitString(`  ${THEME.secondary}Recommendations:${THEME.reset}`, width))
      for (const rec of report.recommendations.slice(0, 3)) {
        lines.push(fitString(`  ${THEME.dim}-${THEME.reset} ${THEME.muted}${rec}${THEME.reset}`, width))
      }
    }

    // Fill to bottom
    while (lines.length < height - 1) lines.push(" ".repeat(width))

    // Help bar
    lines.push(renderHelpBar(width))

    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const rs = ctx.state.hunt.report

    // Navigation: back
    if (key === "q" || key === "\x1b" || key === "\x1b\x1b") {
      ctx.app.setScreen(rs.returnScreen)
      return true
    }

    if (key === "h") {
      ctx.app.setScreen("hunt-report-history")
      return true
    }

    if (key === "r") {
      const report = buildInvestigationReport(ctx.state)
      ctx.state.hunt.report = {
        ...rs,
        report,
        error: report ? null : "No investigation data available to report.",
        statusMessage: report ? `${THEME.success}Rebuilt report from the active investigation.${THEME.reset}` : null,
      }
      ctx.app.render()
      return true
    }

    if (!rs.report) return false

    // Copy report JSON to clipboard
    if (key === "c") {
      const json = JSON.stringify(rs.report, null, 2)
      try {
        const proc = Bun.spawn(["pbcopy"], { stdin: "pipe" })
        proc.stdin.write(json)
        proc.stdin.end()
        ctx.state.hunt.report = {
          ...rs,
          error: null,
          statusMessage: `${THEME.success}Copied report JSON to clipboard.${THEME.reset}`,
        }
      } catch {
        ctx.state.hunt.report = {
          ...rs,
          error: "Clipboard export failed.",
          statusMessage: null,
        }
      }
      ctx.app.render()
      return true
    }

    if (key === "x") {
      void exportCurrentReport(ctx)
      return true
    }

    const evidenceCount = rs.report.evidence.length
    if (evidenceCount === 0) return false

    const innerWidth = Math.min(78, ctx.width - 4)
    const evidenceHeight = estimateEvidenceHeight(rs.report, ctx.height, Boolean(rs.error))
    const buildViewport = (selectedIndex: number, expandedIndex: number | null, offset = rs.list.offset) => {
      const layout = buildEvidenceLayout(rs.report!, selectedIndex, expandedIndex, innerWidth)
      return {
        layout,
        viewport: syncReportViewport(
          { offset, selected: selectedIndex },
          selectedIndex,
          layout.rowSpans,
          evidenceHeight,
        ),
      }
    }

    // Navigate evidence selection
    if (key === "j" || key === "down") {
      const nextSelected = Math.min(evidenceCount - 1, rs.list.selected + 1)
      const { viewport } = buildViewport(nextSelected, rs.expandedEvidence)
      ctx.state.hunt.report = { ...rs, list: viewport }
      ctx.app.render()
      return true
    }
    if (key === "k" || key === "up") {
      const nextSelected = Math.max(0, rs.list.selected - 1)
      const { viewport } = buildViewport(nextSelected, rs.expandedEvidence)
      ctx.state.hunt.report = { ...rs, list: viewport }
      ctx.app.render()
      return true
    }

    if (key === "J") {
      const layout = buildEvidenceLayout(rs.report, rs.list.selected, rs.expandedEvidence, innerWidth)
      ctx.state.hunt.report = {
        ...rs,
        list: {
          ...rs.list,
          offset: scrollReportViewport(rs.list.offset, 1, layout.lines.length, evidenceHeight),
        },
      }
      ctx.app.render()
      return true
    }

    if (key === "K") {
      const layout = buildEvidenceLayout(rs.report, rs.list.selected, rs.expandedEvidence, innerWidth)
      ctx.state.hunt.report = {
        ...rs,
        list: {
          ...rs.list,
          offset: scrollReportViewport(rs.list.offset, -1, layout.lines.length, evidenceHeight),
        },
      }
      ctx.app.render()
      return true
    }

    // Expand/collapse
    if (key === "enter" || key === "\r") {
      const selected = rs.list.selected
      const isExpanded = rs.expandedEvidence === selected
      const expandedEvidence = isExpanded ? null : selected
      const { viewport } = buildViewport(selected, expandedEvidence)
      ctx.state.hunt.report = {
        ...rs,
        expandedEvidence,
        list: viewport,
      }
      ctx.app.render()
      return true
    }

    return false
  },
}

function renderHelpBar(width: number): string {
  const help =
    `${THEME.dim}j/k${THEME.reset}${THEME.muted} move${THEME.reset}  ` +
    `${THEME.dim}J/K${THEME.reset}${THEME.muted} scroll${THEME.reset}  ` +
    `${THEME.dim}Enter${THEME.reset}${THEME.muted} toggle${THEME.reset}  ` +
    `${THEME.dim}h${THEME.reset}${THEME.muted} hist${THEME.reset}  ` +
    `${THEME.dim}x${THEME.reset}${THEME.muted} export${THEME.reset}  ` +
    `${THEME.dim}c${THEME.reset}${THEME.muted} copy${THEME.reset}  ` +
    `${THEME.dim}ESC${THEME.reset}${THEME.muted} back${THEME.reset}`
  return fitString(help, width)
}
