/**
 * Hunt Query Screen - Hunt Query REPL
 *
 * Two modes: natural language (free text) and structured (filter form).
 * Results displayed as a scrollable list of timeline events.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { ListItem } from "../components/scrollable-list"
import { renderList, scrollUp, scrollDown } from "../components/scrollable-list"
import { renderForm, focusNext, focusPrev, handleFieldInput } from "../components/form"
import type { SelectField, TextField } from "../components/form"
import { renderBox } from "../components/box"
import { centerBlock, centerLine, wrapText } from "../components/layout"
import { fitString } from "../components/types"
import { renderSurfaceHeader } from "../components/surface-header"
import { runQuery } from "../../hunt/bridge-query"
import type { TimelineEvent } from "../../hunt/types"
import { updateInvestigation } from "../investigation"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function verdictColor(verdict: string): string {
  switch (verdict) {
    case "allow": return THEME.success
    case "deny": return THEME.error
    case "audit": return THEME.warning
    default: return THEME.muted
  }
}

function formatEvent(evt: TimelineEvent): string {
  const ts = evt.timestamp.length > 19 ? evt.timestamp.slice(11, 19) : evt.timestamp
  const vc = verdictColor(evt.verdict)
  return `${THEME.dim}${ts}${THEME.reset} ${vc}${evt.verdict.padEnd(5)}${THEME.reset} ${THEME.muted}${evt.source}${THEME.reset} ${THEME.white}${evt.summary}${THEME.reset}`
}

function eventsToListItems(events: TimelineEvent[]): ListItem[] {
  return events.map((evt, i) => ({
    label: formatEvent(evt),
    plainLength: `${evt.timestamp.slice(11, 19)} ${evt.verdict.padEnd(5)} ${evt.source} ${evt.summary}`.length,
    key: `evt-${i}`,
  }))
}

function queryFindings(events: TimelineEvent[]): string[] {
  return events
    .filter((event) => event.verdict === "deny" || event.verdict === "audit")
    .slice(0, 8)
    .map((event) => `${event.verdict}: ${event.summary}`)
}

function syncQueryInvestigation(
  ctx: ScreenContext,
  label: string,
  query: string | null,
  events: TimelineEvent[],
): void {
  updateInvestigation(ctx.state, {
    origin: "query",
    title: label,
    summary: `${events.length} event(s) matched the active hunt query.`,
    query,
    events,
    findings: queryFindings(events),
  })
}

function renderQueryStateCard(
  title: string,
  body: string[],
  width: number,
  bodyHeight: number,
  footer: string,
): string[] {
  const boxWidth = Math.min(92, width - 6)
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

// ---------------------------------------------------------------------------
// Screen
// ---------------------------------------------------------------------------

export const huntQueryScreen: Screen = {
  render(ctx: ScreenContext): string {
    const { state, width, height } = ctx
    const q = state.hunt.query
    const lines: string[] = []

    const modeLabel = q.mode === "nl" ? "Natural Language" : "Structured"
    lines.push(...renderSurfaceHeader("hunt-query", "Hunt Query", width, THEME, modeLabel))

    if (q.mode === "nl") {
      // NL input box
      const cursor = `${THEME.accent}\u2588${THEME.reset}`
      const inputLine = `${THEME.muted}  > ${THEME.reset}${THEME.white}${q.nlInput || `${THEME.dim}${THEME.italic}Type a query...${THEME.reset}`}${THEME.reset}${cursor}`
      const boxContent = [fitString(inputLine, width - 4)]
      const boxLines = renderBox("Query", boxContent, width, THEME, { style: "rounded", padding: 1 })
      lines.push(...boxLines)
    } else {
      // Structured form
      const formLines = renderForm(q.structuredForm, width - 4, THEME)
      const boxLines = renderBox("Filters", formLines, width, THEME, { style: "rounded", padding: 1 })
      lines.push(...boxLines)
    }

    lines.push(fitString("", width))

    // Loading indicator
    if (q.loading) {
      const spinChars = ["\u2847", "\u2846", "\u2834", "\u2831", "\u2839", "\u283B", "\u283F", "\u2857"]
      const frame = ctx.state.animationFrame % spinChars.length
      const bodyHeight = Math.max(6, height - lines.length)
      lines.push(...renderQueryStateCard(
        "Running Query",
        [
          `Executing the active ${modeLabel.toLowerCase()} hunt query.`,
          `${spinChars[frame]} collecting matching events and rebuilding the investigation view`,
        ],
        width,
        bodyHeight,
        `${THEME.dim}tab${THEME.reset}${THEME.muted} switch mode${THEME.reset}  ${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`,
      ))
      return lines.join("\n")
    }

    // Error
    if (q.error && q.results.length === 0) {
      const bodyHeight = Math.max(6, height - lines.length)
      lines.push(...renderQueryStateCard(
        "Query Failed",
        [
          `${THEME.error}The hunt query did not complete.${THEME.reset}`,
          q.error,
        ],
        width,
        bodyHeight,
        `${THEME.dim}tab${THEME.reset}${THEME.muted} switch mode${THEME.reset}  ${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`,
      ))
      return lines.join("\n")
    }

    // Results header
    const resultCount = q.results.length
    lines.push(fitString(`${THEME.muted}  Results: ${resultCount}${THEME.reset}`, width))
    lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))

    // Results list
    const usedLines = lines.length + 2 // reserve for footer
    const listHeight = Math.max(1, height - usedLines)

    if (resultCount === 0 && !q.error) {
      const bodyHeight = Math.max(6, height - lines.length)
      lines.push(...renderQueryStateCard(
        "No Matches",
        [
          `No events matched the active ${modeLabel.toLowerCase()} hunt query.`,
          q.mode === "nl"
            ? "Edit the query text and press Enter to search again."
            : "Adjust the structured filters, then press Enter to run the query again.",
        ],
        width,
        bodyHeight,
        q.mode === "nl"
          ? `${THEME.dim}enter${THEME.reset}${THEME.muted} execute${THEME.reset}  ${THEME.dim}tab${THEME.reset}${THEME.muted} structured mode${THEME.reset}  ${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`
          : `${THEME.dim}enter${THEME.reset}${THEME.muted} execute${THEME.reset}  ${THEME.dim}↑/↓${THEME.reset}${THEME.muted} fields${THEME.reset}  ${THEME.dim}tab${THEME.reset}${THEME.muted} NL mode${THEME.reset}`,
      ))
      return lines.join("\n")
    } else {
      const items = eventsToListItems(q.results)
      const listLines = renderList(items, q.resultList, listHeight, width, THEME)
      lines.push(...listLines)
    }

    // Footer
    while (lines.length < height - 1) lines.push(" ".repeat(width))
    const footerParts = q.mode === "nl"
      ? "Enter execute  Tab structured mode  t timeline  Shift+E report  ESC back"
      : "j/k navigate fields  Enter execute  Tab NL mode  t timeline  Shift+E report  ESC back"
    lines.push(fitString(`${THEME.dim}  ${footerParts}${THEME.reset}`, width))

    while (lines.length < height) lines.push(" ".repeat(width))
    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const q = ctx.state.hunt.query

    if (key === "\x1b" || key === "\x1b\x1b") {
      ctx.app.setScreen("main")
      return true
    }

    if (q.loading) return false

    // Tab: switch modes
    if (key === "\t" || key === "tab") {
      ctx.state.hunt.query.mode = q.mode === "nl" ? "structured" : "nl"
      ctx.app.render()
      return true
    }

    // t: pivot to timeline with selected event
    if (key === "t" && q.results.length > 0) {
      // Copy results to timeline state for pivot
      ctx.state.hunt.timeline.events = q.results
      ctx.state.hunt.timeline.list = { offset: 0, selected: q.resultList.selected }
      ctx.app.setScreen("hunt-timeline")
      return true
    }

    if (key === "E" && q.results.length > 0) {
      ctx.state.hunt.report.returnScreen = "hunt-query"
      ctx.app.setScreen("hunt-report")
      return true
    }

    if (q.mode === "nl") {
      // Enter: execute NL query
      if (key === "\r" || key === "enter") {
        if (q.nlInput.trim()) {
          doQuery(ctx)
        }
        return true
      }

      // Backspace
      if (key === "backspace" || key === "\x7f" || key === "\b") {
        ctx.state.hunt.query.nlInput = q.nlInput.slice(0, -1)
        ctx.app.render()
        return true
      }

      // Navigate results when we have them
      if (q.results.length > 0) {
        if (key === "j" || key === "down") {
          ctx.state.hunt.query.resultList = scrollDown(q.resultList, q.results.length, ctx.height - 12)
          ctx.app.render()
          return true
        }
        if (key === "k" || key === "up") {
          ctx.state.hunt.query.resultList = scrollUp(q.resultList)
          ctx.app.render()
          return true
        }
      }

      // Printable character: add to input
      if (key.length === 1 && key >= " ") {
        ctx.state.hunt.query.nlInput += key
        ctx.app.render()
        return true
      }

      return false
    }

    // Structured mode
    if (key === "\r" || key === "enter") {
      doStructuredQuery(ctx)
      return true
    }

    if (key === "j" || key === "down") {
      // If we have results and are past the form, navigate results
      ctx.state.hunt.query.structuredForm = focusNext(q.structuredForm)
      ctx.app.render()
      return true
    }

    if (key === "k" || key === "up") {
      ctx.state.hunt.query.structuredForm = focusPrev(q.structuredForm)
      ctx.app.render()
      return true
    }

    // Field input (left/right for selects, chars for text)
    const updated = handleFieldInput(q.structuredForm, key)
    if (updated !== q.structuredForm) {
      ctx.state.hunt.query.structuredForm = updated
      ctx.app.render()
      return true
    }

    return false
  },
}

async function doQuery(ctx: ScreenContext) {
  const q = ctx.state.hunt.query
  ctx.state.hunt.query.loading = true
  ctx.state.hunt.query.error = null
  ctx.app.render()
  try {
    const results = await runQuery({ nl: q.nlInput })
    ctx.state.hunt.query.results = results
    ctx.state.hunt.query.resultList = { offset: 0, selected: 0 }
    ctx.state.hunt.query.loading = false
    syncQueryInvestigation(ctx, "Hunt Query", q.nlInput, results)
  } catch (err) {
    ctx.state.hunt.query.error = err instanceof Error ? err.message : String(err)
    ctx.state.hunt.query.loading = false
  }
  ctx.app.render()
}

async function doStructuredQuery(ctx: ScreenContext) {
  const form = ctx.state.hunt.query.structuredForm
  const sourceField = form.fields[0] as SelectField
  const verdictField = form.fields[1] as SelectField
  const sinceField = form.fields[2] as TextField
  const limitField = form.fields[3] as TextField

  const source = sourceField.options[sourceField.selectedIndex]
  const verdict = verdictField.options[verdictField.selectedIndex]
  const since = sinceField.value.trim()
  const limit = parseInt(limitField.value.trim(), 10)

  ctx.state.hunt.query.loading = true
  ctx.state.hunt.query.error = null
  ctx.app.render()
  try {
    const results = await runQuery({
      source: source !== "any" ? source as "tetragon" | "hubble" | "receipt" | "spine" : undefined,
      verdict: verdict !== "any" ? verdict as "allow" | "deny" | "audit" : undefined,
      since: since || undefined,
      limit: isNaN(limit) ? undefined : limit,
    })
    ctx.state.hunt.query.results = results
    ctx.state.hunt.query.resultList = { offset: 0, selected: 0 }
    syncQueryInvestigation(
      ctx,
      "Structured Hunt Query",
      [source !== "any" ? `source=${source}` : null, verdict !== "any" ? `verdict=${verdict}` : null, since ? `since=${since}` : null]
        .filter(Boolean)
        .join(" "),
      results,
    )
    ctx.state.hunt.query.loading = false
  } catch (err) {
    ctx.state.hunt.query.error = err instanceof Error ? err.message : String(err)
    ctx.state.hunt.query.loading = false
  }
  ctx.app.render()
}
