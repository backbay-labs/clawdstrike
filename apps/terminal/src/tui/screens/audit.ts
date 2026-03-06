import { Hushd } from "../../hushd"
import type { AuditEvent, AuditQuery } from "../../hushd"
import { renderBox } from "../components/box"
import { renderList, scrollDown, scrollUp, type ListItem } from "../components/scrollable-list"
import { renderSplit } from "../components/split-pane"
import { fitString } from "../components/types"
import { renderSurfaceHeader } from "../components/surface-header"
import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"

const DECISION_FILTERS = ["any", "blocked", "allowed"] as const
const EVENT_FILTERS = ["any", "check", "violation", "report_export"] as const

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

function toListItem(event: AuditEvent): ListItem {
  const timestamp = event.timestamp.slice(0, 19).replace("T", " ")
  const target = event.target ?? event.message ?? event.id
  const label =
    `${THEME.dim}${timestamp}${THEME.reset} ` +
    `${eventColor(event)}[${event.decision}]${THEME.reset} ` +
    `${THEME.white}${event.event_type}${THEME.reset} ` +
    `${THEME.muted}${target}${THEME.reset}`
  const plain = `${timestamp} [${event.decision}] ${event.event_type} ${target}`
  return { label, plainLength: plain.length }
}

function renderMetadata(metadata: Record<string, unknown> | null | undefined, width: number): string[] {
  if (!metadata || Object.keys(metadata).length === 0) {
    return [fitString(`${THEME.dim}No metadata${THEME.reset}`, width)]
  }

  const lines: string[] = []
  for (const [key, value] of Object.entries(metadata).slice(0, 10)) {
    const renderedValue = typeof value === "string" ? value : JSON.stringify(value)
    lines.push(
      fitString(`${THEME.tertiary}${key}${THEME.reset}: ${THEME.white}${renderedValue}${THEME.reset}`, width),
    )
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
    `${THEME.dim}Decision:${THEME.reset} ${event.decision}`,
    `${THEME.dim}Action:${THEME.reset} ${event.action_type}`,
    `${THEME.dim}Time:${THEME.reset} ${formatTimestamp(event.timestamp)}`,
    `${THEME.dim}ID:${THEME.reset} ${event.id}`,
  ]

  if (event.target) {
    content.push(`${THEME.dim}Target:${THEME.reset} ${event.target}`)
  }
  if (event.guard) {
    content.push(`${THEME.dim}Guard:${THEME.reset} ${event.guard}`)
  }
  if (event.session_id) {
    content.push(`${THEME.dim}Session:${THEME.reset} ${event.session_id}`)
  }
  if (event.agent_id) {
    content.push(`${THEME.dim}Agent:${THEME.reset} ${event.agent_id}`)
  }
  if (event.message) {
    content.push(`${THEME.dim}Message:${THEME.reset} ${event.message}`)
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

function buildQuery(ctx: ScreenContext, offset = ctx.state.auditLog.offset): AuditQuery {
  const filters = ctx.state.auditLog.filters
  return {
    limit: ctx.state.auditLog.limit,
    offset,
    decision: filters.decision === "any" ? undefined : filters.decision,
    event_type: filters.eventType === "any" ? undefined : filters.eventType,
    session_id: filters.sessionId.trim() || undefined,
  }
}

async function loadAudit(ctx: ScreenContext, offset = ctx.state.auditLog.offset): Promise<void> {
  const current = ctx.state.auditLog
  ctx.state.auditLog = {
    ...current,
    loading: true,
    error: null,
    statusMessage: `${THEME.secondary}Loading audit log...${THEME.reset}`,
  }
  ctx.app.render()

  const result = await Hushd.getClient().getAuditDetailed(buildQuery(ctx, offset))
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
    statusMessage: `Loaded ${result.data.events.length} event(s) from offset ${result.data.offset ?? offset}.`,
    offset: result.data.offset ?? offset,
    limit: result.data.limit ?? ctx.state.auditLog.limit,
    nextCursor: result.data.next_cursor ?? null,
    hasMore: result.data.has_more ?? false,
  }
  ctx.app.render()
}

function detailLabel(ctx: ScreenContext): string {
  const audit = ctx.state.auditLog
  return `decision ${audit.filters.decision}  event ${audit.filters.eventType}`
}

export const auditScreen: Screen = {
  onEnter(ctx: ScreenContext): void {
    if (ctx.state.auditLog.events.length === 0 && !ctx.state.auditLog.loading) {
      void loadAudit(ctx, 0)
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
    const leftWidth = Math.max(34, Math.floor(width * 0.55))
    const rightWidth = Math.max(24, width - leftWidth - 1)
    const listLines = renderList(
      audit.events.map((event) => toListItem(event)),
      audit.list,
      contentHeight,
      leftWidth,
      THEME,
    )
    const detailLines = renderDetail(selectedEvent(ctx), rightWidth, contentHeight)
    lines.push(...renderSplit(listLines, detailLines, width, contentHeight, THEME, 0.55))
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
      void loadAudit(ctx, audit.offset)
      return true
    }

    if (key === "f") {
      const next = (DECISION_FILTERS.indexOf(audit.filters.decision) + 1) % DECISION_FILTERS.length
      ctx.state.auditLog = {
        ...audit,
        filters: { ...audit.filters, decision: DECISION_FILTERS[next] },
        offset: 0,
      }
      void loadAudit(ctx, 0)
      return true
    }

    if (key === "e") {
      const next = (EVENT_FILTERS.indexOf(audit.filters.eventType) + 1) % EVENT_FILTERS.length
      ctx.state.auditLog = {
        ...audit,
        filters: { ...audit.filters, eventType: EVENT_FILTERS[next] },
        offset: 0,
      }
      void loadAudit(ctx, 0)
      return true
    }

    if (key === "n" && audit.hasMore) {
      void loadAudit(ctx, audit.offset + audit.limit)
      return true
    }

    if (key === "p" && audit.offset > 0) {
      void loadAudit(ctx, Math.max(0, audit.offset - audit.limit))
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
