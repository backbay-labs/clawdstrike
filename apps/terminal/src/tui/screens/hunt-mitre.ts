/**
 * Hunt MITRE Screen - MITRE ATT&CK Heatmap
 *
 * Grid of techniques x tactics with hit counts, plus drill-down
 * into matched events for a selected technique.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { GridCell } from "../components/grid"
import { renderGrid, moveSelection } from "../components/grid"
import type { ListItem } from "../components/scrollable-list"
import { renderList, scrollUp, scrollDown } from "../components/scrollable-list"
import { fitString } from "../components/types"
import { runTimeline } from "../../hunt/bridge-query"
import { buildCoverageMatrix, TACTICS } from "../../hunt/mitre"
import type { CoverageMatrix } from "../../hunt/mitre"
import type { TimelineEvent } from "../../hunt/types"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Short tactic labels for column headers */
function shortTactic(tactic: string): string {
  const map: Record<string, string> = {
    "Initial Access": "InitAcc",
    "Execution": "Exec",
    "Persistence": "Persist",
    "Privilege Escalation": "PrivEsc",
    "Defense Evasion": "DefEvas",
    "Credential Access": "Cred",
    "Discovery": "Discov",
    "Lateral Movement": "LatMov",
    "Collection": "Collect",
    "Exfiltration": "Exfil",
    "Command and Control": "C2",
    "Impact": "Impact",
  }
  return map[tactic] ?? tactic.slice(0, 7)
}

function verdictColor(verdict: string): string {
  switch (verdict) {
    case "allow": return THEME.success
    case "deny": return THEME.error
    case "audit": return THEME.warning
    default: return THEME.muted
  }
}

function formatDrilldownEvent(evt: TimelineEvent): string {
  const ts = evt.timestamp.length > 19 ? evt.timestamp.slice(11, 19) : evt.timestamp
  const vc = verdictColor(evt.verdict)
  return `${THEME.dim}${ts}${THEME.reset} ${vc}${evt.verdict.padEnd(5)}${THEME.reset} ${THEME.muted}${evt.source}${THEME.reset} ${THEME.white}${evt.summary}${THEME.reset}`
}

// ---------------------------------------------------------------------------
// State management
// ---------------------------------------------------------------------------

let cachedMatrix: CoverageMatrix | null = null

function getSubMode(ctx: ScreenContext): "grid" | "drilldown" {
  return ctx.state.hunt.mitre.drilldownEvents.length > 0 ? "drilldown" : "grid"
}

// ---------------------------------------------------------------------------
// Screen
// ---------------------------------------------------------------------------

export const huntMitreScreen: Screen = {
  onEnter(ctx: ScreenContext) {
    const mitre = ctx.state.hunt.mitre
    if (mitre.events.length === 0 && !mitre.loading) {
      loadEvents(ctx)
    }
  },

  onExit(_ctx: ScreenContext) {
    cachedMatrix = null
  },

  render(ctx: ScreenContext): string {
    const { state, width, height } = ctx
    const mitre = state.hunt.mitre
    const lines: string[] = []

    // Header
    const title = `${THEME.secondary}${THEME.bold} MITRE ATT&CK Heatmap ${THEME.reset}`
    lines.push(fitString(title, width))
    lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))

    if (mitre.loading) {
      const spinChars = ["\u2847", "\u2846", "\u2834", "\u2831", "\u2839", "\u283B", "\u283F", "\u2857"]
      const frame = ctx.state.animationFrame % spinChars.length
      lines.push(fitString(`${THEME.accent}  ${spinChars[frame]} Loading timeline events...${THEME.reset}`, width))
      while (lines.length < height - 1) lines.push(" ".repeat(width))
      lines.push(fitString(`${THEME.dim}  ESC back${THEME.reset}`, width))
      return lines.join("\n")
    }

    if (mitre.error) {
      lines.push(fitString(`${THEME.error}  Error: ${mitre.error}${THEME.reset}`, width))
      lines.push(fitString("", width))
      lines.push(fitString(`${THEME.muted}  r reload  ESC back${THEME.reset}`, width))
      while (lines.length < height - 1) lines.push(" ".repeat(width))
      return lines.join("\n")
    }

    if (!cachedMatrix || mitre.techniques.length === 0) {
      lines.push(fitString(`${THEME.muted}  No events or techniques detected.${THEME.reset}`, width))
      lines.push(fitString(`${THEME.dim}  Run hunt watch or load timeline data first.${THEME.reset}`, width))
      lines.push(fitString("", width))
      lines.push(fitString(`${THEME.muted}  r reload  ESC back${THEME.reset}`, width))
      while (lines.length < height - 1) lines.push(" ".repeat(width))
      return lines.join("\n")
    }

    const subMode = getSubMode(ctx)

    if (subMode === "drilldown") {
      // Drilldown: show selected technique's events
      const techIdx = mitre.grid.row
      const tech = cachedMatrix.techniques[techIdx]
      const techLabel = tech ? `${tech.id} ${tech.name}` : "Unknown"
      lines.push(fitString(`${THEME.secondary}  ${techLabel}${THEME.reset}  ${THEME.dim}(${mitre.drilldownEvents.length} events)${THEME.reset}`, width))
      lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))

      const listHeight = Math.max(1, height - lines.length - 2)
      const items: ListItem[] = mitre.drilldownEvents.map((evt, i) => ({
        label: formatDrilldownEvent(evt),
        plainLength: `${evt.timestamp.slice(11, 19)} ${evt.verdict.padEnd(5)} ${evt.source} ${evt.summary}`.length,
        key: `drill-${i}`,
      }))

      const listLines = renderList(items, mitre.drilldownList, listHeight, width, THEME)
      lines.push(...listLines)

      // Footer
      while (lines.length < height - 1) lines.push(" ".repeat(width))
      lines.push(fitString(`${THEME.dim}  j/k navigate  ESC back to grid${THEME.reset}`, width))
    } else {
      // Grid view
      const columns = cachedMatrix.tactics.map(shortTactic)
      const rows = cachedMatrix.techniques.map((t) => t.id)

      // Build GridCell[][] from matrix
      const cells: GridCell[][] = cachedMatrix.matrix.map((row) =>
        row.map((val) => ({ value: val })),
      )

      const gridHeight = Math.min(cachedMatrix.techniques.length + 3, Math.floor(height * 0.65))
      const gridLines = renderGrid(columns, rows, cells, mitre.grid, width, gridHeight, THEME)
      lines.push(...gridLines)

      // Selected technique info
      lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))
      const techIdx = mitre.grid.row
      const tech = cachedMatrix.techniques[techIdx]
      if (tech) {
        const tacticLabel = cachedMatrix.tactics[mitre.grid.col] ?? ""
        const cellVal = cachedMatrix.matrix[techIdx]?.[mitre.grid.col] ?? 0
        lines.push(fitString(
          `${THEME.secondary}  ${tech.id}${THEME.reset} ${THEME.white}${tech.name}${THEME.reset}  ${THEME.dim}[${tacticLabel}]${THEME.reset}  ${THEME.accent}${cellVal} hits${THEME.reset}`,
          width,
        ))
      } else {
        lines.push(fitString(`${THEME.muted}  No technique selected${THEME.reset}`, width))
      }

      // Legend
      lines.push(fitString("", width))
      lines.push(fitString(
        `${THEME.dim}  \u2591 low  ${THEME.muted}\u2592 med  ${THEME.warning}\u2593 high  ${THEME.accent}\u2588 critical${THEME.reset}`,
        width,
      ))

      // Footer
      while (lines.length < height - 1) lines.push(" ".repeat(width))
      lines.push(fitString(`${THEME.dim}  h/j/k/l navigate  Enter drilldown  r reload  ESC back${THEME.reset}`, width))
    }

    while (lines.length < height) lines.push(" ".repeat(width))
    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const mitre = ctx.state.hunt.mitre
    const subMode = getSubMode(ctx)

    if (mitre.loading) return false

    // ESC handling
    if (key === "\x1b" || key === "\x1b\x1b") {
      if (subMode === "drilldown") {
        // Back to grid
        ctx.state.hunt.mitre.drilldownEvents = []
        ctx.state.hunt.mitre.drilldownList = { offset: 0, selected: 0 }
        ctx.app.render()
        return true
      }
      ctx.app.setScreen("main")
      return true
    }

    if (key === "q" && subMode !== "drilldown") {
      ctx.app.setScreen("main")
      return true
    }

    if (key === "r") {
      loadEvents(ctx)
      return true
    }

    if (subMode === "drilldown") {
      if (key === "j" || key === "down") {
        ctx.state.hunt.mitre.drilldownList = scrollDown(
          mitre.drilldownList,
          mitre.drilldownEvents.length,
          ctx.height - 8,
        )
        ctx.app.render()
        return true
      }
      if (key === "k" || key === "up") {
        ctx.state.hunt.mitre.drilldownList = scrollUp(mitre.drilldownList)
        ctx.app.render()
        return true
      }
      return false
    }

    // Grid navigation
    if (cachedMatrix && cachedMatrix.techniques.length > 0) {
      if (key === "h" || key === "left") {
        ctx.state.hunt.mitre.grid = moveSelection(mitre.grid, "left", cachedMatrix.techniques.length, TACTICS.length)
        ctx.app.render()
        return true
      }
      if (key === "l" || key === "right") {
        ctx.state.hunt.mitre.grid = moveSelection(mitre.grid, "right", cachedMatrix.techniques.length, TACTICS.length)
        ctx.app.render()
        return true
      }
      if (key === "j" || key === "down") {
        ctx.state.hunt.mitre.grid = moveSelection(mitre.grid, "down", cachedMatrix.techniques.length, TACTICS.length)
        ctx.app.render()
        return true
      }
      if (key === "k" || key === "up") {
        ctx.state.hunt.mitre.grid = moveSelection(mitre.grid, "up", cachedMatrix.techniques.length, TACTICS.length)
        ctx.app.render()
        return true
      }

      // Enter: drilldown into technique
      if (key === "\r" || key === "enter") {
        const techIdx = mitre.grid.row
        const tech = cachedMatrix.techniques[techIdx]
        if (tech) {
          const events = cachedMatrix.eventsByTechnique.get(tech.id) ?? []
          ctx.state.hunt.mitre.drilldownEvents = events
          ctx.state.hunt.mitre.drilldownList = { offset: 0, selected: 0 }
          ctx.app.render()
        }
        return true
      }
    }

    return false
  },
}

async function loadEvents(ctx: ScreenContext) {
  ctx.state.hunt.mitre.loading = true
  ctx.state.hunt.mitre.error = null
  cachedMatrix = null
  ctx.app.render()
  try {
    const events = await runTimeline({ limit: 500 })
    ctx.state.hunt.mitre.events = events

    const matrix = buildCoverageMatrix(events)
    cachedMatrix = matrix

    // Store technique IDs and tactic labels in state for other screens
    ctx.state.hunt.mitre.tactics = matrix.tactics
    ctx.state.hunt.mitre.techniques = matrix.techniques.map((t) => t.id)
    ctx.state.hunt.mitre.matrix = matrix.matrix
    ctx.state.hunt.mitre.drilldownEvents = []
    ctx.state.hunt.mitre.drilldownList = { offset: 0, selected: 0 }
    ctx.state.hunt.mitre.grid = { row: 0, col: 0 }
    ctx.state.hunt.mitre.loading = false
  } catch (err) {
    ctx.state.hunt.mitre.error = err instanceof Error ? err.message : String(err)
    ctx.state.hunt.mitre.loading = false
  }
  ctx.app.render()
}
