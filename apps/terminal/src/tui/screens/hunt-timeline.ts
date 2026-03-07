/**
 * Hunt Timeline Screen - Timeline replay with source filtering and event expansion.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { TimelineEvent, EventSource, NormalizedVerdict } from "../../hunt/types"
import { runTimeline } from "../../hunt/bridge-query"
import { renderList, scrollUp, scrollDown, type ListItem } from "../components/scrollable-list"
import { renderBox } from "../components/box"
import { centerBlock, centerLine, wrapText } from "../components/layout"
import { fitString } from "../components/types"
import { renderSurfaceHeader } from "../components/surface-header"
import { updateInvestigation } from "../investigation"

const SOURCE_ICONS: Record<EventSource, string> = {
  tetragon: "T",
  hubble: "H",
  receipt: "R",
  spine: "S",
}

const SOURCE_KEYS: Record<string, EventSource> = {
  "1": "tetragon",
  "2": "hubble",
  "3": "receipt",
  "4": "spine",
}

const VERDICT_COLORS: Record<NormalizedVerdict, string> = {
  allow: THEME.success,
  deny: THEME.error,
  audit: THEME.warning,
  unknown: THEME.dim,
}

function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso)
    const h = String(d.getHours()).padStart(2, "0")
    const m = String(d.getMinutes()).padStart(2, "0")
    const s = String(d.getSeconds()).padStart(2, "0")
    return `${h}:${m}:${s}`
  } catch {
    return "??:??:??"
  }
}

function getFilteredEvents(ctx: ScreenContext): TimelineEvent[] {
  const tl = ctx.state.hunt.timeline
  return tl.events.filter((e) => {
    const filters = tl.sourceFilters
    return filters[e.source] === true
  })
}

function buildEventItems(events: TimelineEvent[]): ListItem[] {
  return events.map((e) => {
    const ts = formatTimestamp(e.timestamp)
    const icon = SOURCE_ICONS[e.source] ?? "?"
    const verdictColor = VERDICT_COLORS[e.verdict] ?? THEME.dim
    const label =
      `${THEME.dim}[${ts}]${THEME.reset} ` +
      `${THEME.tertiary}[${icon}]${THEME.reset} ` +
      `${verdictColor}[${e.verdict}]${THEME.reset} ` +
      `${THEME.white}${e.summary}${THEME.reset}`
    const plainLength = `[${ts}] [${icon}] [${e.verdict}] ${e.summary}`.length
    return { label, plainLength }
  })
}

function timelineFindings(events: TimelineEvent[]): string[] {
  return events
    .filter((event) => event.verdict === "deny" || event.verdict === "audit")
    .slice(0, 8)
    .map((event) => `${event.verdict}: ${event.summary}`)
}

function syncInvestigation(ctx: ScreenContext): void {
  const filtered = getFilteredEvents(ctx)
  updateInvestigation(ctx.state, {
    origin: "timeline",
    title: "Timeline Replay",
    summary: `${filtered.length} event(s) match the active source filters.`,
    events: filtered,
    findings: timelineFindings(filtered),
    query: Object.entries(ctx.state.hunt.timeline.sourceFilters)
      .filter(([, enabled]) => enabled)
      .map(([source]) => source)
      .join(","),
  })
}

function renderTimelineStateCard(
  title: string,
  body: string[],
  width: number,
  bodyHeight: number,
  footer: string,
): string[] {
  const boxWidth = Math.min(94, width - 6)
  const innerWidth = boxWidth - 4
  const content = body.flatMap((line) => wrapText(line, innerWidth))
  const card = renderBox(title, content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
  const lines: string[] = []
  const startY = Math.max(1, Math.floor((bodyHeight - card.length - 2) / 2))
  while (lines.length < startY) lines.push(" ".repeat(width))
  lines.push(...centerBlock(card, width))
  while (lines.length < bodyHeight - 1) lines.push(" ".repeat(width))
  lines.push(centerLine(footer, width))
  return lines
}

export const huntTimelineScreen: Screen = {
  onEnter(ctx: ScreenContext): void {
    const tl = ctx.state.hunt.timeline
    if (tl.loading) return
    if (tl.events.length > 0) {
      syncInvestigation(ctx)
      return
    }

    ctx.state.hunt.timeline = { ...tl, loading: true, error: null }
    ctx.app.render()

    runTimeline({})
      .then((events) => {
        ctx.state.hunt.timeline = {
          ...ctx.state.hunt.timeline,
          events,
          loading: false,
          list: { offset: 0, selected: 0 },
          expandedIndex: null,
        }
        syncInvestigation(ctx)
        ctx.app.render()
      })
      .catch((err) => {
        ctx.state.hunt.timeline = {
          ...ctx.state.hunt.timeline,
          loading: false,
          error: err instanceof Error ? err.message : String(err),
        }
        ctx.app.render()
      })
  },

  render(ctx: ScreenContext): string {
    const { state, width, height } = ctx
    const tl = state.hunt.timeline
    const lines: string[] = []

    lines.push(...renderSurfaceHeader("hunt-timeline", "Timeline Replay", width, THEME))

    // Source filter toggles row
    const filters = tl.sourceFilters
    const toggles = (["tetragon", "hubble", "receipt", "spine"] as EventSource[])
      .map((src, i) => {
        const active = filters[src]
        const icon = SOURCE_ICONS[src]
        const color = active ? THEME.secondary : THEME.dim
        const indicator = active ? `${THEME.success}*` : `${THEME.dim}-`
        return `${THEME.dim}${i + 1}${THEME.reset}${color}[${icon}]${indicator}${THEME.reset}`
      })
      .join("  ")
    lines.push(fitString(`  ${THEME.muted}Sources:${THEME.reset} ${toggles}`, width))
    lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))

    // Loading state
    if (tl.loading) {
      const spinChars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
      const spinner = spinChars[state.animationFrame % spinChars.length]
      const bodyHeight = Math.max(6, height - lines.length)
      lines.push(...renderTimelineStateCard(
        "Timeline Loading",
        [
          `Replaying hunt events across the enabled sources.`,
          `${spinner} fetching receipts and runtime events for the current investigation`,
        ],
        width,
        bodyHeight,
        renderHelpBar(width),
      ))
      return lines.join("\n")
    }

    // Error state
    if (tl.error) {
      const bodyHeight = Math.max(6, height - lines.length)
      lines.push(...renderTimelineStateCard(
        "Timeline Failed",
        [
          `${THEME.error}Timeline replay did not complete.${THEME.reset}`,
          tl.error,
        ],
        width,
        bodyHeight,
        renderHelpBar(width),
      ))
      return lines.join("\n")
    }

    const filtered = getFilteredEvents(ctx)

    // Empty state
    if (filtered.length === 0) {
      const bodyHeight = Math.max(6, height - lines.length)
      lines.push(...renderTimelineStateCard(
        "No Timeline Events",
        [
          tl.events.length === 0
            ? "No timeline events were returned for this investigation."
            : "No events match the currently enabled source filters.",
          "Toggle sources with 1-4 or reload the timeline to try again.",
        ],
        width,
        bodyHeight,
        renderHelpBar(width),
      ))
      return lines.join("\n")
    }

    // Calculate layout: event list takes top portion, detail takes bottom when expanded
    const helpLines = 1
    const headerLines = lines.length
    const availableHeight = height - headerLines - helpLines

    let listHeight: number
    let detailHeight: number

    if (tl.expandedIndex !== null) {
      detailHeight = Math.min(10, Math.floor(availableHeight * 0.4))
      listHeight = availableHeight - detailHeight
    } else {
      listHeight = availableHeight
      detailHeight = 0
    }

    // Event list
    const items = buildEventItems(filtered)
    const listLines = renderList(items, tl.list, listHeight, width, THEME)
    for (const l of listLines) lines.push(l)

    // Expanded detail pane
    if (tl.expandedIndex !== null && tl.expandedIndex < filtered.length) {
      const event = filtered[tl.expandedIndex]
      const detailContent: string[] = [
        `${THEME.muted}Kind:${THEME.reset}    ${THEME.white}${event.kind}${THEME.reset}`,
        `${THEME.muted}Source:${THEME.reset}  ${THEME.tertiary}${event.source}${THEME.reset}`,
        `${THEME.muted}Verdict:${THEME.reset} ${(VERDICT_COLORS[event.verdict] ?? THEME.dim)}${event.verdict}${THEME.reset}`,
        `${THEME.muted}Time:${THEME.reset}    ${THEME.white}${event.timestamp}${THEME.reset}`,
      ]
      // Add details as JSON lines
      const detailJson = JSON.stringify(event.details, null, 2)
      const jsonLines = detailJson.split("\n")
      detailContent.push(`${THEME.muted}Details:${THEME.reset}`)
      for (const jl of jsonLines.slice(0, detailHeight - 6)) {
        detailContent.push(`  ${THEME.dim}${jl}${THEME.reset}`)
      }

      const boxLines = renderBox("Event Detail", detailContent, width, THEME, { style: "rounded" })
      for (const bl of boxLines) lines.push(bl)
    }

    // Help bar
    lines.push(renderHelpBar(width))

    // Pad to fill
    while (lines.length < height) lines.push(" ".repeat(width))

    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const tl = ctx.state.hunt.timeline
    if (tl.loading) {
      if (key === "\x1b" || key === "\x1b\x1b" || key === "q") {
        ctx.app.setScreen("main")
        return true
      }
      return false
    }

    const filtered = getFilteredEvents(ctx)

    // Navigation
    if (key === "\x1b" || key === "\x1b\x1b" || key === "q") {
      ctx.app.setScreen("main")
      return true
    }

    // Scroll
    if (key === "j" || key === "down") {
      if (filtered.length > 0) {
        ctx.state.hunt.timeline = {
          ...tl,
          list: scrollDown(tl.list, filtered.length, ctx.height - 8),
          expandedIndex: null,
        }
        ctx.app.render()
      }
      return true
    }
    if (key === "k" || key === "up") {
      if (filtered.length > 0) {
        ctx.state.hunt.timeline = {
          ...tl,
          list: scrollUp(tl.list),
          expandedIndex: null,
        }
        ctx.app.render()
      }
      return true
    }

    // Page up/down
    if (key === "h") {
      if (filtered.length > 0) {
        const pageSize = Math.max(1, ctx.height - 12)
        let vp = tl.list
        for (let i = 0; i < pageSize; i++) vp = scrollUp(vp)
        ctx.state.hunt.timeline = { ...tl, list: vp, expandedIndex: null }
        ctx.app.render()
      }
      return true
    }
    if (key === "l") {
      if (filtered.length > 0) {
        const pageSize = Math.max(1, ctx.height - 12)
        let vp = tl.list
        for (let i = 0; i < pageSize; i++) vp = scrollDown(vp, filtered.length, ctx.height - 8)
        ctx.state.hunt.timeline = { ...tl, list: vp, expandedIndex: null }
        ctx.app.render()
      }
      return true
    }

    // Expand/collapse
    if (key === "\r" || key === "return") {
      if (filtered.length > 0) {
        const current = tl.expandedIndex
        const selected = tl.list.selected
        ctx.state.hunt.timeline = {
          ...tl,
          expandedIndex: current === selected ? null : selected,
        }
        ctx.app.render()
      }
      return true
    }

    // Source toggles
    const toggleSource = SOURCE_KEYS[key]
    if (toggleSource) {
      ctx.state.hunt.timeline = {
        ...tl,
        sourceFilters: {
          ...tl.sourceFilters,
          [toggleSource]: !tl.sourceFilters[toggleSource],
        },
        list: { offset: 0, selected: 0 },
        expandedIndex: null,
      }
      syncInvestigation(ctx)
      ctx.app.render()
      return true
    }

    if (key === "e") {
      ctx.state.hunt.report.returnScreen = "hunt-timeline"
      ctx.app.setScreen("hunt-report")
      return true
    }

    // Reload
    if (key === "r") {
      ctx.state.hunt.timeline = { ...tl, loading: true, error: null }
      ctx.app.render()

      runTimeline({})
        .then((events) => {
          ctx.state.hunt.timeline = {
            ...ctx.state.hunt.timeline,
            events,
            loading: false,
            list: { offset: 0, selected: 0 },
            expandedIndex: null,
          }
          syncInvestigation(ctx)
          ctx.app.render()
        })
        .catch((err) => {
          ctx.state.hunt.timeline = {
            ...ctx.state.hunt.timeline,
            loading: false,
            error: err instanceof Error ? err.message : String(err),
          }
          ctx.app.render()
        })
      return true
    }

    return false
  },
}

function renderHelpBar(width: number): string {
  const help =
    `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}  ` +
    `${THEME.dim}j/k${THEME.reset}${THEME.muted} scroll${THEME.reset}  ` +
    `${THEME.dim}h/l${THEME.reset}${THEME.muted} page${THEME.reset}  ` +
    `${THEME.dim}enter${THEME.reset}${THEME.muted} expand${THEME.reset}  ` +
    `${THEME.dim}e${THEME.reset}${THEME.muted} report${THEME.reset}  ` +
    `${THEME.dim}1-4${THEME.reset}${THEME.muted} sources${THEME.reset}  ` +
    `${THEME.dim}r${THEME.reset}${THEME.muted} reload${THEME.reset}`
  return fitString(help, width)
}
