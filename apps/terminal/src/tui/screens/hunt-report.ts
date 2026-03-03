/**
 * Hunt Report Screen - Evidence report viewer with expand/collapse and export.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { EvidenceItem, RuleSeverity } from "../../hunt/types"
import { scrollUp, scrollDown, type ListItem } from "../components/scrollable-list"
import { renderBox } from "../components/box"
import { fitString } from "../components/types"

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

export const huntReportScreen: Screen = {
  render(ctx: ScreenContext): string {
    const { state, width, height } = ctx
    const rs = state.hunt.report
    const lines: string[] = []

    // Title
    const title = `${THEME.accent}${THEME.bold} HUNT ${THEME.reset}${THEME.dim} // ${THEME.reset}${THEME.secondary}Evidence Report${THEME.reset}`
    lines.push(fitString(title, width))
    lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))

    if (rs.error) {
      lines.push(fitString(`${THEME.error} Error: ${rs.error}${THEME.reset}`, width))
    }

    // Empty state
    if (!rs.report) {
      const msgY = Math.floor(height / 2) - 1
      for (let i = 2; i < msgY; i++) lines.push(" ".repeat(width))
      lines.push(fitString(`${THEME.muted}  No report loaded.${THEME.reset}`, width))
      lines.push(fitString(`${THEME.dim}  Run a correlation or open a report to view evidence.${THEME.reset}`, width))
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

    // -- Evidence list --
    const evidenceItems: ListItem[] = []
    const expandedRows: string[][] = []

    for (let i = 0; i < report.evidence.length; i++) {
      const ev = report.evidence[i]
      const isExpanded = rs.expandedEvidence === i
      evidenceItems.push(evidenceToListItem(ev, isExpanded))
      if (isExpanded) {
        expandedRows.push(renderExpandedEvidence(ev, innerWidth - 4))
      } else {
        expandedRows.push([])
      }
    }

    // Interleave items and expanded details
    const allEvidenceLines: string[] = []
    for (let i = 0; i < evidenceItems.length; i++) {
      const item = evidenceItems[i]
      const isSelected = i === rs.list.selected
      if (isSelected) {
        const marker = `${THEME.accent}${THEME.bold} \u25B8 ${THEME.reset}`
        allEvidenceLines.push(fitString(`${marker}${item.label}`, innerWidth - 2))
      } else {
        allEvidenceLines.push(fitString(`   ${item.label}`, innerWidth - 2))
      }
      for (const expLine of expandedRows[i]) {
        allEvidenceLines.push(fitString(`   ${expLine}`, innerWidth - 2))
      }
    }

    if (allEvidenceLines.length === 0) {
      allEvidenceLines.push(fitString(`${THEME.muted}  (no evidence items)${THEME.reset}`, innerWidth - 2))
    }

    // Calculate available height for evidence
    const usedLines = lines.length + 6 // 6 for merkle + help + padding
    const evidenceHeight = Math.max(3, height - usedLines)
    const visibleEvidence = allEvidenceLines.slice(0, evidenceHeight)

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
      ctx.app.setScreen("main")
      return true
    }

    if (!rs.report) return false

    const evidenceCount = rs.report.evidence.length
    if (evidenceCount === 0) return false

    // Navigate evidence
    if (key === "j" || key === "down") {
      ctx.state.hunt.report = { ...rs, list: scrollDown(rs.list, evidenceCount, 20) }
      return true
    }
    if (key === "k" || key === "up") {
      ctx.state.hunt.report = { ...rs, list: scrollUp(rs.list) }
      return true
    }

    // Expand/collapse
    if (key === "enter" || key === "\r") {
      const selected = rs.list.selected
      const isExpanded = rs.expandedEvidence === selected
      ctx.state.hunt.report = {
        ...rs,
        expandedEvidence: isExpanded ? null : selected,
      }
      return true
    }

    // Copy report JSON to clipboard
    if (key === "c") {
      const json = JSON.stringify(rs.report, null, 2)
      try {
        const proc = Bun.spawn(["pbcopy"], { stdin: "pipe" })
        proc.stdin.write(json)
        proc.stdin.end()
      } catch {
        // Clipboard copy failed silently
      }
      return true
    }

    return false
  },
}

function renderHelpBar(width: number): string {
  const help =
    `${THEME.dim}j/k${THEME.reset}${THEME.muted} navigate${THEME.reset}  ` +
    `${THEME.dim}Enter${THEME.reset}${THEME.muted} expand${THEME.reset}  ` +
    `${THEME.dim}c${THEME.reset}${THEME.muted} copy JSON${THEME.reset}  ` +
    `${THEME.dim}ESC${THEME.reset}${THEME.muted} back${THEME.reset}`
  return fitString(help, width)
}
