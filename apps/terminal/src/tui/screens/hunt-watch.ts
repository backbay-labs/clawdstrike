/**
 * Hunt Watch Screen - Live event stream with filtering and alert banners.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext, HuntWatchState } from "../types"
import type { TimelineEvent, Alert, WatchStats, EventSource, NormalizedVerdict } from "../../hunt/types"
import type { HuntStreamHandle } from "../../hunt/bridge"
import { startWatch } from "../../hunt/bridge-correlate"
import {
  renderLog,
  appendLine,
  togglePause,
  scrollLogUp,
  scrollLogDown,
  clearLog,
  type LogLine,
} from "../components/streaming-log"
import { fitString } from "../components/types"
import { renderSurfaceHeader } from "../components/surface-header"
import { appendInvestigationEvent, updateInvestigation } from "../investigation"

const SOURCE_ICONS: Record<EventSource, string> = {
  tetragon: "T",
  hubble: "H",
  receipt: "R",
  spine: "S",
}

const VERDICT_COLORS: Record<NormalizedVerdict, string> = {
  allow: THEME.success,
  deny: THEME.error,
  audit: THEME.warning,
  unknown: THEME.dim,
}

const FILTERS: HuntWatchState["filter"][] = ["all", "allow", "deny", "audit"]

let watchHandle: HuntStreamHandle | null = null

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

function formatEvent(event: TimelineEvent): LogLine {
  const ts = formatTimestamp(event.timestamp)
  const icon = SOURCE_ICONS[event.source] ?? "?"
  const verdictColor = VERDICT_COLORS[event.verdict] ?? THEME.dim
  const text =
    `${THEME.dim}[${ts}]${THEME.reset} ` +
    `${THEME.tertiary}[${icon}]${THEME.reset} ` +
    `${verdictColor}[${event.verdict}]${THEME.reset} ` +
    `${THEME.white}${event.summary}${THEME.reset}`
  return { text, plainLength: `[${ts}] [${icon}] [${event.verdict}] ${event.summary}`.length }
}

function matchesFilter(event: TimelineEvent, filter: HuntWatchState["filter"]): boolean {
  if (filter === "all") return true
  return event.verdict === filter
}

export const huntWatchScreen: Screen = {
  onEnter(ctx: ScreenContext): void {
    const w = ctx.state.hunt.watch
    if (w.running) return

    ctx.state.hunt.watch = { ...w, running: true }
    updateInvestigation(ctx.state, {
      origin: "watch",
      title: "Live Watch",
      summary: "Watching live policy and hunt events.",
      query: w.filter === "all" ? null : w.filter,
      events: [],
      findings: [],
    })

    const rules = ["~/.clawdstrike/rules/*.yaml"]

    watchHandle = startWatch(
      rules,
      (event: TimelineEvent) => {
        const ws = ctx.state.hunt.watch
        if (!matchesFilter(event, ws.filter)) return
        ctx.state.hunt.watch = {
          ...ws,
          log: appendLine(ws.log, formatEvent(event)),
        }
        appendInvestigationEvent(ctx.state, event, {
          origin: "watch",
          title: "Live Watch",
          summary: event.summary,
          query: ws.filter === "all" ? null : ws.filter,
          findings: ctx.state.hunt.investigation.findings,
        })
        ctx.app.render()
      },
      (alert: Alert) => {
        const ws = ctx.state.hunt.watch

        // Clear previous fade timer
        if (ws.alertFadeTimer) clearTimeout(ws.alertFadeTimer)

        const fadeTimer = setTimeout(() => {
          ctx.state.hunt.watch = { ...ctx.state.hunt.watch, lastAlert: null, alertFadeTimer: null }
          ctx.app.render()
        }, 5000)

        const findings = [...ctx.state.hunt.investigation.findings, `${alert.severity}: ${alert.title}`]
          .slice(-8)

        ctx.state.hunt.watch = { ...ws, lastAlert: alert, alertFadeTimer: fadeTimer }
        updateInvestigation(ctx.state, {
          origin: "watch",
          title: "Live Watch",
          summary: alert.description ?? alert.title,
          query: ws.filter === "all" ? null : ws.filter,
          findings,
        })
        ctx.app.render()
      },
      (stats: WatchStats) => {
        ctx.state.hunt.watch = { ...ctx.state.hunt.watch, stats }
        updateInvestigation(ctx.state, {
          origin: "watch",
          title: "Live Watch",
          summary: `${stats.events_processed} event(s) processed with ${stats.alerts_fired} alert(s).`,
          query: ctx.state.hunt.watch.filter === "all" ? null : ctx.state.hunt.watch.filter,
        })
        ctx.app.render()
      },
    )
  },

  onExit(ctx: ScreenContext): void {
    if (watchHandle) {
      watchHandle.kill()
      watchHandle = null
    }
    const w = ctx.state.hunt.watch
    if (w.alertFadeTimer) clearTimeout(w.alertFadeTimer)
    ctx.state.hunt.watch = { ...w, running: false, alertFadeTimer: null }
  },

  render(ctx: ScreenContext): string {
    const { state, width, height } = ctx
    const w = state.hunt.watch
    const lines: string[] = []

    const filterLabel = `filter ${w.filter}`
    lines.push(...renderSurfaceHeader("hunt-watch", "Live Watch", width, THEME, filterLabel))

    if (!w.running) {
      // Not running state
      const msgY = Math.floor(height / 2) - 2
      for (let i = 2; i < msgY; i++) lines.push(" ".repeat(width))
      lines.push(fitString(`${THEME.muted}  Watch is not running.${THEME.reset}`, width))
      lines.push(fitString(`${THEME.dim}  Press any key to return, or restart the screen.${THEME.reset}`, width))
      for (let i = lines.length; i < height - 1; i++) lines.push(" ".repeat(width))
      lines.push(renderHelpBar(width))
      return lines.join("\n")
    }

    // Alert banner (if present)
    let alertLines = 0
    if (w.lastAlert) {
      const severityColor = w.lastAlert.severity === "critical" ? THEME.error : THEME.warning
      const alertText =
        `${severityColor}${THEME.bold} ALERT ${THEME.reset} ` +
        `${severityColor}${w.lastAlert.title}${THEME.reset} ` +
        `${THEME.dim}(${w.lastAlert.rule})${THEME.reset}`
      lines.push(fitString(alertText, width))
      alertLines = 1
    }

    // Stats bar height
    const statsLines = 1
    // Log area: remaining height minus header(2) - alert - stats - help(1)
    const logHeight = height - 2 - alertLines - statsLines - 1

    // Streaming log
    const logOutput = renderLog(w.log, logHeight, width, THEME)
    for (const l of logOutput) lines.push(l)

    // Stats bar
    if (w.stats) {
      const statsText =
        `${THEME.dim}events: ${THEME.reset}${THEME.white}${w.stats.events_processed}${THEME.reset}` +
        `${THEME.dim} | alerts: ${THEME.reset}${THEME.warning}${w.stats.alerts_fired}${THEME.reset}` +
        `${THEME.dim} | rules: ${THEME.reset}${THEME.white}${w.stats.active_rules}${THEME.reset}` +
        `${THEME.dim} | uptime: ${THEME.reset}${THEME.white}${w.stats.uptime_seconds}s${THEME.reset}`
      lines.push(fitString(statsText, width))
    } else {
      lines.push(fitString(`${THEME.dim}Waiting for stats...${THEME.reset}`, width))
    }

    // Help bar
    lines.push(renderHelpBar(width))

    // Pad to fill
    while (lines.length < height) lines.push(" ".repeat(width))

    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const w = ctx.state.hunt.watch

    // Navigation
    if (key === "q" || key === "\x1b" || key === "\x1b\x1b") {
      ctx.app.setScreen("main")
      return true
    }

    // Filter cycle
    if (key === "f") {
      const idx = FILTERS.indexOf(w.filter)
      const next = FILTERS[(idx + 1) % FILTERS.length]
      ctx.state.hunt.watch = { ...w, filter: next }
      updateInvestigation(ctx.state, {
        origin: "watch",
        title: "Live Watch",
        summary: ctx.state.hunt.investigation.summary,
        query: next === "all" ? null : next,
      })
      ctx.app.render()
      return true
    }

    if (key === "e") {
      ctx.app.setScreen("hunt-report")
      return true
    }

    // Clear log
    if (key === "c") {
      ctx.state.hunt.watch = { ...w, log: clearLog(w.log) }
      ctx.app.render()
      return true
    }

    // Pause/resume
    if (key === " ") {
      ctx.state.hunt.watch = { ...w, log: togglePause(w.log) }
      ctx.app.render()
      return true
    }

    // Scroll when paused
    if (key === "up" || key === "k") {
      ctx.state.hunt.watch = { ...w, log: scrollLogUp(w.log) }
      ctx.app.render()
      return true
    }
    if (key === "down" || key === "j") {
      ctx.state.hunt.watch = { ...w, log: scrollLogDown(w.log) }
      ctx.app.render()
      return true
    }

    return false
  },
}

function renderHelpBar(width: number): string {
  const help =
    `${THEME.dim}q${THEME.reset}${THEME.muted} back${THEME.reset}  ` +
    `${THEME.dim}f${THEME.reset}${THEME.muted} filter${THEME.reset}  ` +
    `${THEME.dim}e${THEME.reset}${THEME.muted} report${THEME.reset}  ` +
    `${THEME.dim}c${THEME.reset}${THEME.muted} clear${THEME.reset}  ` +
    `${THEME.dim}space${THEME.reset}${THEME.muted} pause${THEME.reset}  ` +
    `${THEME.dim}j/k${THEME.reset}${THEME.muted} scroll${THEME.reset}`
  return fitString(help, width)
}
