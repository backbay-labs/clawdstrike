import { Hushd } from "../../hushd"
import type { AuditEvent, AuditQuery } from "../../hushd"
import { renderBox } from "../components/box"
import { joinColumns, wrapText } from "../components/layout"
import { renderList, scrollDown, scrollUp, type ListItem } from "../components/scrollable-list"
import { renderSplit } from "../components/split-pane"
import { fitString } from "../components/types"
import { renderSurfaceHeader } from "../components/surface-header"
import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"

const DECISION_FILTERS = ["any", "blocked", "allowed"] as const
const EVENT_FILTERS = ["any", "check", "violation", "report_export"] as const

function truncateMiddle(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value
  }

  const head = Math.max(4, Math.floor((maxLength - 1) / 2))
  const tail = Math.max(4, maxLength - head - 1)
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

function formatTimestamp(iso: string): string {
  const parsed = new Date(iso)
  if (Number.isNaN(parsed.getTime())) {
    return iso
  }

  return parsed.toLocaleString()
}

function eventColor(event: AuditEvent): string {
  if (event.decision === "blocked") {
    return THEME.error
  }

  if (event.event_type === "report_export") {
    return THEME.secondary
  }

  return THEME.success
}

function formatEventRange(total: number, offset: number): string {
  if (total === 0) {
    return "0"
  }

  return `${offset + 1}-${offset + total}`
}

function wrapField(label: string, value: string, width: number): string[] {
  const labelWidth = label.length + 2
  const valueWidth = Math.max(12, width - labelWidth)
  const wrapped = /\s/.test(value)
    ? wrapText(value, valueWidth)
    : [truncateMiddle(value, valueWidth)]
  if (wrapped.length === 0) {
    return [fitString(`${THEME.dim}${label}:${THEME.reset}`, width)]
  }

  return wrapped.map((line, index) => (
    index === 0
      ? fitString(`${THEME.dim}${label}:${THEME.reset} ${THEME.white}${line}${THEME.reset}`, width)
      : fitString(`${" ".repeat(labelWidth)}${THEME.white}${line}${THEME.reset}`, width)
  ))
}

function wrapMetadataValue(value: string, width: number): string[] {
  if (width <= 0) {
    return [""]
  }

  const source = value.trim()
  if (!source) {
    return [""]
  }

  const logicalLines = source.split("\n")
  const lines: string[] = []

  for (const logicalLine of logicalLines) {
    const segments = wrapText(logicalLine, width).filter(Boolean)
    if (segments.length > 0) {
      lines.push(...segments)
      continue
    }

    let remainder = logicalLine
    while (remainder.length > width) {
      lines.push(remainder.slice(0, width))
      remainder = remainder.slice(width)
    }
    lines.push(remainder)
  }

  return lines.length > 0 ? lines : [""]
}

function formatMetadataValue(value: unknown): string[] {
  if (typeof value === "string") {
    return [value]
  }

  if (
    typeof value === "number" ||
    typeof value === "boolean" ||
    value === null
  ) {
    return [String(value)]
  }

  try {
    return JSON.stringify(value, null, 2)?.split("\n") ?? [String(value)]
  } catch {
    return [String(value)]
  }
}

function toListItem(event: AuditEvent): ListItem {
  const timestamp = event.timestamp.slice(0, 19).replace("T", " ")
  const target = truncateMiddle(event.target ?? event.message ?? event.id, 22)
  const eventType = truncateMiddle(event.event_type, 14)
  const label =
    `${THEME.dim}${timestamp}${THEME.reset} ` +
    `${eventColor(event)}${event.decision}${THEME.reset} ` +
    `${THEME.white}${eventType}${THEME.reset} ` +
    `${THEME.muted}${target}${THEME.reset}`
  const plain = `${timestamp} ${event.decision} ${eventType} ${target}`
  return { label, plainLength: plain.length }
}

function renderMetadata(metadata: Record<string, unknown> | null | undefined, width: number): string[] {
  if (!metadata || Object.keys(metadata).length === 0) {
    return [fitString(`${THEME.dim}No metadata${THEME.reset}`, width)]
  }

  const lines: string[] = []
  for (const [key, value] of Object.entries(metadata).slice(0, 10)) {
    const wrapped = formatMetadataValue(value)
      .flatMap((line) => wrapMetadataValue(line, Math.max(12, width - key.length - 2)))
    lines.push(
      fitString(
        `${THEME.tertiary}${key}${THEME.reset}: ${THEME.white}${wrapped[0] ?? ""}${THEME.reset}`,
        width,
      ),
    )
    for (const line of wrapped.slice(1)) {
      lines.push(
        fitString(
          `${" ".repeat(key.length + 2)}${THEME.white}${line}${THEME.reset}`,
          width,
        ),
      )
    }
  }
  if (Object.keys(metadata).length > 10) {
    lines.push(fitString(`${THEME.dim}... +${Object.keys(metadata).length - 10} more fields${THEME.reset}`, width))
  }
  return lines
}

function renderDetail(event: AuditEvent | null, width: number, height: number): string[] {
  if (!event) {
    const lines = [
      `${THEME.muted}No audit events loaded.${THEME.reset}`,
      `${THEME.dim}Reload or adjust the filters.${THEME.reset}`,
    ]
    while (lines.length < height) {
      lines.push(" ".repeat(width))
    }
    return lines
  }

  const content: string[] = [
    `${THEME.white}${THEME.bold}${event.event_type}${THEME.reset}`,
    fitString(`${THEME.dim}decision:${THEME.reset} ${eventColor(event)}${event.decision}${THEME.reset}`, width - 4),
    fitString(`${THEME.dim}action:${THEME.reset} ${THEME.white}${event.action_type}${THEME.reset}`, width - 4),
  ]
  content.push(...wrapField("time", formatTimestamp(event.timestamp), width - 4))
  content.push(...wrapField("id", event.id, width - 4))

  if (event.target) {
    content.push(...wrapField("target", event.target, width - 4))
  }
  if (event.guard) {
    content.push(...wrapField("guard", event.guard, width - 4))
  }
  if (event.session_id) {
    content.push(...wrapField("session", event.session_id, width - 4))
  }
  if (event.agent_id) {
    content.push(...wrapField("agent", event.agent_id, width - 4))
  }
  if (event.message) {
    content.push(...wrapField("message", event.message, width - 4))
  }
  content.push("")
  content.push(`${THEME.secondary}Metadata${THEME.reset}`)
  content.push(...renderMetadata(event.metadata, width - 4))

  const box = renderBox("Event Detail", content.map((line) => fitString(line, width - 4)), width, THEME, {
    style: "rounded",
    padding: 1,
  })
  while (box.length < height) {
    box.push(" ".repeat(width))
  }
  return box.slice(0, height)
}

function selectedEvent(ctx: ScreenContext): AuditEvent | null {
  const audit = ctx.state.auditLog
  if (audit.events.length === 0) {
    return null
  }

  return audit.events[Math.min(audit.list.selected, audit.events.length - 1)] ?? null
}

interface AuditPageRequest {
  cursor: string | null
  previousCursors: Array<string | null>
}

function buildQuery(ctx: ScreenContext, page: AuditPageRequest): AuditQuery {
  const filters = ctx.state.auditLog.filters
  return {
    limit: ctx.state.auditLog.limit,
    cursor: page.cursor ?? undefined,
    offset: page.cursor == null ? 0 : undefined,
    decision: filters.decision === "any" ? undefined : filters.decision,
    event_type: filters.eventType === "any" ? undefined : filters.eventType,
    session_id: filters.sessionId.trim() || undefined,
  }
}

async function loadAudit(
  ctx: ScreenContext,
  page: AuditPageRequest = {
    cursor: ctx.state.auditLog.cursor,
    previousCursors: ctx.state.auditLog.previousCursors,
  },
): Promise<void> {
  const current = ctx.state.auditLog
  ctx.state.auditLog = {
    ...current,
    loading: true,
    error: null,
    statusMessage: `${THEME.secondary}Loading audit log...${THEME.reset}`,
  }
  ctx.app.render()

  const result = await Hushd.getClient().getAuditDetailed(buildQuery(ctx, page))
  if (!result.ok || !result.data) {
    if (result.status === 401 || result.status === 403) {
      ctx.state.hushdConnected = false
      ctx.state.hushdStatus = "unauthorized"
      ctx.state.hushdLastError = result.error ?? "audit access denied"
      ctx.state.securityError = ctx.state.hushdLastError
    }

    ctx.state.auditLog = {
      ...ctx.state.auditLog,
      loading: false,
      error: result.error ?? "failed to query audit log",
      statusMessage: null,
    }
    ctx.app.render()
    return
  }

  ctx.state.auditLog = {
    ...ctx.state.auditLog,
      events: result.data.events,
      list: { offset: 0, selected: 0 },
      loading: false,
      error: null,
      statusMessage: `Loaded ${result.data.events.length} event(s) from offset ${result.data.offset ?? 0}.`,
      cursor: page.cursor,
      previousCursors: page.previousCursors,
      offset: result.data.offset ?? 0,
      limit: result.data.limit ?? ctx.state.auditLog.limit,
      nextCursor: result.data.next_cursor ?? null,
      hasMore: result.data.has_more ?? false,
  }
  ctx.app.render()
}

function detailLabel(ctx: ScreenContext): string {
  const audit = ctx.state.auditLog
  const scope = `decision ${audit.filters.decision} | event ${audit.filters.eventType}`
  const range = `rows ${formatEventRange(audit.events.length, audit.offset)}`
  return `${scope} | ${range}`
}

function renderScopeLine(ctx: ScreenContext, width: number): string {
  const audit = ctx.state.auditLog
  return fitString(
    `${THEME.dim}scope:${THEME.reset} ${THEME.white}${audit.filters.decision}${THEME.reset} / ${THEME.white}${audit.filters.eventType}${THEME.reset}`,
    width,
  )
}

function renderSessionLine(ctx: ScreenContext, width: number): string {
  const session = ctx.state.auditLog.filters.sessionId.trim() || "all sessions"
  return fitString(`${THEME.dim}session:${THEME.reset} ${THEME.muted}${session}${THEME.reset}`, width)
}

function renderPageLine(ctx: ScreenContext, width: number): string {
  const audit = ctx.state.auditLog
  const left = `${THEME.dim}showing:${THEME.reset} ${THEME.white}${formatEventRange(audit.events.length, audit.offset)}${THEME.reset}`
  const right = audit.hasMore
    ? `${THEME.secondary}next page ready${THEME.reset}`
    : `${THEME.dim}end of results${THEME.reset}`
  return joinColumns(left, right, width)
}

function renderEventListPane(ctx: ScreenContext, width: number, height: number): string[] {
  const audit = ctx.state.auditLog
  const contentWidth = width - 4
  const availableLines = Math.max(1, height - 2)
  const headerLines = [
    fitString(renderScopeLine(ctx, contentWidth), contentWidth),
    fitString(renderSessionLine(ctx, contentWidth), contentWidth),
    fitString(renderPageLine(ctx, contentWidth), contentWidth),
    "",
  ]
  const listHeight = Math.max(1, availableLines - headerLines.length)
  const listLines = renderList(
    audit.events.map((event) => toListItem(event)),
    audit.list,
    listHeight,
    contentWidth,
    THEME,
  )

  return renderBox("Audit Events", [...headerLines, ...listLines], width, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

export const auditScreen: Screen = {
  onEnter(ctx: ScreenContext): void {
    if (ctx.state.auditLog.events.length === 0 && !ctx.state.auditLog.loading) {
      void loadAudit(ctx, { cursor: null, previousCursors: [] })
    }
  },

  render(ctx: ScreenContext): string {
    const { width, height } = ctx
    const audit = ctx.state.auditLog
    const lines: string[] = []

    lines.push(...renderSurfaceHeader("audit", "Audit Log", width, THEME, detailLabel(ctx)))

    if (audit.error) {
      lines.push(fitString(`${THEME.error} Error: ${audit.error}${THEME.reset}`, width))
    } else if (audit.statusMessage) {
      lines.push(fitString(` ${audit.statusMessage}`, width))
    }

    if (audit.loading && audit.events.length === 0) {
      while (lines.length < height - 1) {
        lines.push(" ".repeat(width))
      }
      lines.push(renderHelpBar(width))
      return lines.join("\n")
    }

    const contentHeight = Math.max(6, height - lines.length - 1)
    const leftWidth = Math.max(40, Math.floor(width * 0.5))
    const rightWidth = Math.max(24, width - leftWidth - 1)
    const listLines = renderEventListPane(ctx, leftWidth, contentHeight)
    const detailLines = renderDetail(selectedEvent(ctx), rightWidth, contentHeight)
    lines.push(...renderSplit(listLines, detailLines, width, contentHeight, THEME, 0.5))
    lines.push(renderHelpBar(width))
    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const audit = ctx.state.auditLog

    if (key === "\x1b" || key === "\x1b\x1b" || key === "q") {
      ctx.app.setScreen("main")
      return true
    }

    if (audit.loading) {
      return false
    }

    if (key === "r") {
      void loadAudit(ctx, {
        cursor: audit.cursor,
        previousCursors: audit.previousCursors,
      })
      return true
    }

    if (key === "f") {
      const next = (DECISION_FILTERS.indexOf(audit.filters.decision) + 1) % DECISION_FILTERS.length
      ctx.state.auditLog = {
        ...audit,
        filters: { ...audit.filters, decision: DECISION_FILTERS[next] },
        cursor: null,
        previousCursors: [],
        offset: 0,
        nextCursor: null,
        hasMore: false,
      }
      void loadAudit(ctx, { cursor: null, previousCursors: [] })
      return true
    }

    if (key === "e") {
      const next = (EVENT_FILTERS.indexOf(audit.filters.eventType) + 1) % EVENT_FILTERS.length
      ctx.state.auditLog = {
        ...audit,
        filters: { ...audit.filters, eventType: EVENT_FILTERS[next] },
        cursor: null,
        previousCursors: [],
        offset: 0,
        nextCursor: null,
        hasMore: false,
      }
      void loadAudit(ctx, { cursor: null, previousCursors: [] })
      return true
    }

    if (key === "n" && audit.hasMore && audit.nextCursor) {
      void loadAudit(ctx, {
        cursor: audit.nextCursor,
        previousCursors: [...audit.previousCursors, audit.cursor],
      })
      return true
    }

    if (key === "p" && (audit.previousCursors.length > 0 || audit.offset > 0)) {
      const previousCursors = audit.previousCursors.slice(0, -1)
      const previousCursor = audit.previousCursors.length > 0
        ? audit.previousCursors[audit.previousCursors.length - 1] ?? null
        : null
      void loadAudit(ctx, {
        cursor: previousCursor,
        previousCursors,
      })
      return true
    }

    if (key === "j" || key === "down") {
      ctx.state.auditLog = {
        ...audit,
        list: scrollDown(audit.list, audit.events.length, Math.max(4, ctx.height - 5)),
      }
      ctx.app.render()
      return true
    }

    if (key === "k" || key === "up") {
      ctx.state.auditLog = {
        ...audit,
        list: scrollUp(audit.list),
      }
      ctx.app.render()
      return true
    }

    return false
  },
}

function renderHelpBar(width: number): string {
  const help =
    `${THEME.dim}j/k${THEME.reset}${THEME.muted} navigate${THEME.reset}  ` +
    `${THEME.dim}f${THEME.reset}${THEME.muted} decision${THEME.reset}  ` +
    `${THEME.dim}e${THEME.reset}${THEME.muted} event${THEME.reset}  ` +
    `${THEME.dim}n/p${THEME.reset}${THEME.muted} page${THEME.reset}  ` +
    `${THEME.dim}r${THEME.reset}${THEME.muted} reload${THEME.reset}  ` +
    `${THEME.dim}ESC${THEME.reset}${THEME.muted} back${THEME.reset}`
  return fitString(help, width)
}
