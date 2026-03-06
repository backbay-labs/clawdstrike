import { renderBox } from "../components/box"
import { renderList, scrollDown, scrollUp, type ListItem } from "../components/scrollable-list"
import { renderSplit } from "../components/split-pane"
import { fitString } from "../components/types"
import { renderSurfaceHeader } from "../components/surface-header"
import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import { loadExportedReport, readReportHistory, type ReportHistoryEntry } from "../report-export"

function formatTimestamp(iso: string): string {
  const parsed = new Date(iso)
  if (Number.isNaN(parsed.getTime())) {
    return iso
  }

  return parsed.toLocaleString()
}

function toListItem(entry: ReportHistoryEntry): ListItem {
  const exported = entry.exportedAt.length >= 10 ? entry.exportedAt.slice(0, 10) : entry.exportedAt
  const severityColor = entry.severity === "critical" ? THEME.error
    : entry.severity === "high" ? THEME.warning
    : entry.severity === "medium" ? THEME.warning
    : THEME.muted
  const label =
    `${THEME.dim}${exported}${THEME.reset} ` +
    `${severityColor}[${entry.severity}]${THEME.reset} ` +
    `${THEME.white}${entry.title}${THEME.reset}`
  const plain = `${exported} [${entry.severity}] ${entry.title}`
  return { label, plainLength: plain.length }
}

function selectedEntry(ctx: ScreenContext): ReportHistoryEntry | null {
  const history = ctx.state.hunt.reportHistory
  if (history.entries.length === 0) {
    return null
  }

  return history.entries[Math.min(history.list.selected, history.entries.length - 1)] ?? null
}

function renderDetailPane(entry: ReportHistoryEntry | null, width: number, height: number): string[] {
  if (!entry) {
    const empty = [
      `${THEME.muted}No exported reports found.${THEME.reset}`,
      `${THEME.dim}Press x in hunt-report to export a bundle.${THEME.reset}`,
    ]
    while (empty.length < height) {
      empty.push(" ".repeat(width))
    }
    return empty
  }

  const trace = entry.trace
  const lines = [
    `${THEME.white}${THEME.bold}${entry.title}${THEME.reset}`,
    `${THEME.dim}Exported:${THEME.reset} ${formatTimestamp(entry.exportedAt)}`,
    `${THEME.dim}Created:${THEME.reset} ${formatTimestamp(entry.reportCreatedAt)}`,
    `${THEME.dim}Severity:${THEME.reset} ${entry.severity}`,
    `${THEME.dim}Evidence:${THEME.reset} ${entry.evidenceCount}`,
    `${THEME.dim}Origin:${THEME.reset} ${entry.investigationOrigin ?? "unknown"}`,
    `${THEME.dim}Markdown:${THEME.reset} ${entry.markdownPath}`,
    `${THEME.dim}JSON:${THEME.reset} ${entry.jsonPath}`,
  ]

  if (entry.merkleRoot) {
    lines.push(`${THEME.dim}Merkle:${THEME.reset} ${entry.merkleRoot}`)
  }
  if (trace.receiptIds.length > 0) {
    lines.push(`${THEME.dim}Receipts:${THEME.reset} ${trace.receiptIds.join(", ")}`)
  }
  if (trace.auditEventIds.length > 0) {
    lines.push(`${THEME.dim}Audit IDs:${THEME.reset} ${trace.auditEventIds.join(", ")}`)
  }
  if (trace.sessionIds.length > 0) {
    lines.push(`${THEME.dim}Sessions:${THEME.reset} ${trace.sessionIds.join(", ")}`)
  }
  if (trace.eventSources.length > 0) {
    lines.push(`${THEME.dim}Sources:${THEME.reset} ${trace.eventSources.join(", ")}`)
  }
  lines.push(`${THEME.dim}Export Audit:${THEME.reset} ${entry.traceability.auditStatus}`)
  lines.push(`${THEME.dim}Export Event:${THEME.reset} ${entry.traceability.exportAuditEventId}`)
  if (entry.traceability.auditRecordedAt) {
    lines.push(`${THEME.dim}Recorded:${THEME.reset} ${formatTimestamp(entry.traceability.auditRecordedAt)}`)
  }
  if (entry.traceability.error) {
    lines.push(`${THEME.dim}Trace Error:${THEME.reset} ${entry.traceability.error}`)
  }
  lines.push("", `${THEME.muted}${entry.summary}${THEME.reset}`)

  const box = renderBox("Export Detail", lines.map((line) => fitString(line, width - 4)), width, THEME, {
    style: "rounded",
    padding: 1,
  })
  while (box.length < height) {
    box.push(" ".repeat(width))
  }
  return box.slice(0, height)
}

async function loadHistory(ctx: ScreenContext, force = false): Promise<void> {
  const current = ctx.state.hunt.reportHistory
  if (current.loading || (!force && current.entries.length > 0)) {
    return
  }

  ctx.state.hunt.reportHistory = {
    ...current,
    loading: true,
    error: null,
    statusMessage: force ? `${THEME.secondary}Reloading export history...${THEME.reset}` : null,
  }
  ctx.app.render()

  try {
    const entries = await readReportHistory(ctx.app.getCwd())
    ctx.state.hunt.reportHistory = {
      ...ctx.state.hunt.reportHistory,
      entries,
      list: {
        offset: 0,
        selected: Math.min(current.list.selected, Math.max(0, entries.length - 1)),
      },
      loading: false,
      error: null,
      statusMessage: entries.length > 0
        ? `${THEME.success}Loaded ${entries.length} exported report bundle(s).${THEME.reset}`
        : `${THEME.muted}No exported report bundles found yet.${THEME.reset}`,
    }
  } catch (err) {
    ctx.state.hunt.reportHistory = {
      ...ctx.state.hunt.reportHistory,
      loading: false,
      error: err instanceof Error ? err.message : String(err),
      statusMessage: null,
    }
  }

  ctx.app.render()
}

async function openSelectedEntry(ctx: ScreenContext): Promise<void> {
  const entry = selectedEntry(ctx)
  if (!entry) {
    return
  }

  try {
    const report = await loadExportedReport(ctx.app.getCwd(), entry)
    ctx.state.hunt.report = {
      ...ctx.state.hunt.report,
      report,
      list: { offset: 0, selected: 0 },
      expandedEvidence: null,
      error: null,
      statusMessage: `${THEME.success}Loaded exported report:${THEME.reset} ${THEME.white}${entry.jsonPath}${THEME.reset}`,
      returnScreen: "hunt-report-history",
    }
    ctx.app.setScreen("hunt-report")
  } catch (err) {
    ctx.state.hunt.reportHistory = {
      ...ctx.state.hunt.reportHistory,
      error: err instanceof Error ? err.message : String(err),
      statusMessage: null,
    }
    ctx.app.render()
  }
}

export const huntReportHistoryScreen: Screen = {
  onEnter(ctx: ScreenContext): void {
    void loadHistory(ctx)
  },

  render(ctx: ScreenContext): string {
    const { width, height } = ctx
    const history = ctx.state.hunt.reportHistory
    const lines: string[] = []

    lines.push(...renderSurfaceHeader("hunt-report-history", "Report History", width, THEME))

    if (history.error) {
      lines.push(fitString(`${THEME.error} Error: ${history.error}${THEME.reset}`, width))
    } else if (history.statusMessage) {
      lines.push(fitString(` ${history.statusMessage}`, width))
    }

    if (history.loading && history.entries.length === 0) {
      const messageY = Math.floor(height / 2) - 2
      while (lines.length < messageY) {
        lines.push(" ".repeat(width))
      }
      lines.push(fitString(`${THEME.secondary}  Loading exported report history...${THEME.reset}`, width))
      while (lines.length < height - 1) {
        lines.push(" ".repeat(width))
      }
      lines.push(renderHelpBar(width))
      return lines.join("\n")
    }

    const contentHeight = Math.max(3, height - lines.length - 1)
    const leftWidth = Math.max(28, Math.floor(width * 0.42))
    const rightWidth = Math.max(24, width - leftWidth - 1)
    const listLines = renderList(
      history.entries.map((entry) => toListItem(entry)),
      history.list,
      contentHeight,
      leftWidth,
      THEME,
    )
    const detailLines = renderDetailPane(selectedEntry(ctx), rightWidth, contentHeight)
    lines.push(...renderSplit(listLines, detailLines, width, contentHeight, THEME, 0.42))
    lines.push(renderHelpBar(width))
    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const history = ctx.state.hunt.reportHistory

    if (key === "\x1b" || key === "\x1b\x1b" || key === "q") {
      ctx.app.setScreen(ctx.state.hunt.report.report ? "hunt-report" : "main")
      return true
    }

    if (key === "r") {
      void loadHistory(ctx, true)
      return true
    }

    if (history.entries.length === 0) {
      return false
    }

    if (key === "j" || key === "down") {
      ctx.state.hunt.reportHistory = {
        ...history,
        list: scrollDown(history.list, history.entries.length, Math.max(3, ctx.height - 5)),
      }
      ctx.app.render()
      return true
    }

    if (key === "k" || key === "up") {
      ctx.state.hunt.reportHistory = {
        ...history,
        list: scrollUp(history.list),
      }
      ctx.app.render()
      return true
    }

    if (key === "\r" || key === "enter" || key === "o") {
      void openSelectedEntry(ctx)
      return true
    }

    return false
  },
}

function renderHelpBar(width: number): string {
  const help =
    `${THEME.dim}j/k${THEME.reset}${THEME.muted} navigate${THEME.reset}  ` +
    `${THEME.dim}Enter${THEME.reset}${THEME.muted} open${THEME.reset}  ` +
    `${THEME.dim}r${THEME.reset}${THEME.muted} reload${THEME.reset}  ` +
    `${THEME.dim}ESC${THEME.reset}${THEME.muted} back${THEME.reset}`
  return fitString(help, width)
}
