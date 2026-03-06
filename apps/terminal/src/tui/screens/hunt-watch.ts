/**
 * Hunt Watch Screen - Live event stream with filtering and alert banners.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext, HuntWatchState } from "../types"
import type { TimelineEvent, Alert, WatchStats, EventSource, NormalizedVerdict } from "../../hunt/types"
import type { HuntStreamHandle } from "../../hunt/bridge"
import { startWatch } from "../../hunt/bridge-correlate"
import { resolveDefaultWatchRules } from "../../hunt/bridge"
import { resolveDesktopAgentWatchConfig } from "../../desktop-agent"
import {
  renderLog,
  appendLine,
  togglePause,
  scrollLogUp,
  scrollLogDown,
  clearLog,
  type LogLine,
} from "../components/streaming-log"
import { renderBox } from "../components/box"
import { centerBlock, centerLine, wrapText } from "../components/layout"
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

function explainUnavailableWatch(error: string, ctx: ScreenContext): string {
  const desktop = ctx.state.desktopAgent
  const hint = resolveDesktopAgentWatchConfig(desktop)
  const prefix = ctx.state.hushdConnected
    ? "Local hushd is reachable, but "
    : ""

  if (hint.kind === "not_enrolled" || hint.kind === "nats_disabled") {
    return `${prefix}${hint.message} Use Security or Audit for local events, or enroll the desktop agent to enable Live Watch.`
  }

  if (hint.kind === "missing_creds") {
    return `${prefix}${hint.message}`
  }

  if (hint.kind === "read_error") {
    return `${prefix}${hint.message}`
  }

  return error
}

function renderWatchSummaryCard(ctx: ScreenContext, width: number): string[] {
  const { state } = ctx
  const w = state.hunt.watch
  const boxWidth = Math.min(108, width - 6)
  const content: string[] = [
    `${THEME.dim}Mode:${THEME.reset} ${THEME.white}${w.log.paused ? "paused" : "live"}${THEME.reset}  ` +
      `${THEME.dim}Filter:${THEME.reset} ${THEME.white}${w.filter}${THEME.reset}  ` +
      `${THEME.dim}Local hushd:${THEME.reset} ${THEME.white}${state.hushdStatus}${THEME.reset}`,
  ]

  if (w.stats) {
    content.push(
      `${THEME.dim}Events:${THEME.reset} ${THEME.white}${w.stats.events_processed}${THEME.reset}  ` +
        `${THEME.dim}Alerts:${THEME.reset} ${THEME.warning}${w.stats.alerts_fired}${THEME.reset}  ` +
        `${THEME.dim}Rules:${THEME.reset} ${THEME.white}${w.stats.active_rules}${THEME.reset}  ` +
        `${THEME.dim}Uptime:${THEME.reset} ${THEME.white}${w.stats.uptime_seconds}s${THEME.reset}`,
    )
  } else {
    content.push(`${THEME.dim}Waiting for stream statistics from the cluster watch process.${THEME.reset}`)
  }

  content.push(
    `${THEME.dim}Actions:${THEME.reset} ${THEME.white}f${THEME.reset} filter  ` +
      `${THEME.white}space${THEME.reset} pause  ${THEME.white}c${THEME.reset} clear  ${THEME.white}e${THEME.reset} report`,
  )

  return renderBox("Watch Session", content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

export const huntWatchScreen: Screen = {
  onEnter(ctx: ScreenContext): void {
    ctx.app.refreshDesktopAgent()
    const w = ctx.state.hunt.watch
    if (w.running) return

    const rules = resolveDefaultWatchRules(ctx.app.getCwd())
    if (rules.length === 0) {
      ctx.state.hunt.watch = {
        ...w,
        running: false,
        error: "No correlation rule files are available for live watch.",
      }
      ctx.app.render()
      return
    }

    const watchConfig = resolveDesktopAgentWatchConfig(ctx.state.desktopAgent)
    if (watchConfig.kind === "not_enrolled" || watchConfig.kind === "nats_disabled") {
      const error = explainUnavailableWatch(watchConfig.message, ctx)
      ctx.state.hunt.watch = {
        ...w,
        running: false,
        error,
      }
      updateInvestigation(ctx.state, {
        origin: "watch",
        title: "Live Watch",
        summary: error,
        query: w.filter === "all" ? null : w.filter,
      })
      ctx.app.render()
      return
    }

    ctx.state.hunt.watch = { ...w, running: true, error: null }
    updateInvestigation(ctx.state, {
      origin: "watch",
      title: "Live Watch",
      summary: "Watching live policy and hunt events.",
      query: w.filter === "all" ? null : w.filter,
      events: [],
      findings: [],
    })

    watchHandle = startWatch(
      rules,
      {
        onEvent: (event: TimelineEvent) => {
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
        onAlert: (alert: Alert) => {
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
        onStats: (stats: WatchStats) => {
        ctx.state.hunt.watch = { ...ctx.state.hunt.watch, stats }
        updateInvestigation(ctx.state, {
          origin: "watch",
          title: "Live Watch",
          summary: `${stats.events_processed} event(s) processed with ${stats.alerts_fired} alert(s).`,
          query: ctx.state.hunt.watch.filter === "all" ? null : ctx.state.hunt.watch.filter,
        })
        ctx.app.render()
        },
        onError: (error: string) => {
        const ws = ctx.state.hunt.watch
        const readableError = explainUnavailableWatch(error, ctx)
        ctx.state.hunt.watch = {
          ...ws,
          running: false,
          error: readableError,
          log: appendLine(ws.log, {
            text: `${THEME.error}watch error:${THEME.reset} ${THEME.muted}${readableError}${THEME.reset}`,
            plainLength: `watch error: ${readableError}`.length,
          }),
        }
        updateInvestigation(ctx.state, {
          origin: "watch",
          title: "Live Watch",
          summary: `Watch unavailable: ${readableError}`,
          query: ws.filter === "all" ? null : ws.filter,
        })
        ctx.app.render()
        },
      },
      {
        cwd: ctx.app.getCwd(),
        natsUrl: watchConfig.kind === "manual" || watchConfig.kind === "configured" ? watchConfig.natsUrl : undefined,
        natsCreds: watchConfig.kind === "manual" || watchConfig.kind === "configured" ? watchConfig.natsCreds : undefined,
        natsToken: watchConfig.kind === "manual" || watchConfig.kind === "configured" ? watchConfig.natsToken : undefined,
        natsNkeySeed: watchConfig.kind === "manual" || watchConfig.kind === "configured" ? watchConfig.natsNkeySeed : undefined,
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
      const boxWidth = Math.min(96, width - 6)
      const innerWidth = boxWidth - 4
      const content: string[] = []

      if (w.error) {
        content.push(`${THEME.error}${THEME.bold}Cluster watch unavailable${THEME.reset}`)
        content.push(...wrapText(w.error, innerWidth).map(line => `${THEME.dim}${line}${THEME.reset}`))
      } else {
        content.push(`${THEME.muted}Watch is not running.${THEME.reset}`)
        content.push(`${THEME.dim}Press q to return to the dashboard.${THEME.reset}`)
      }

      const card = renderBox("Live Watch", content.map(line => fitString(line, innerWidth)), boxWidth, THEME, {
        style: "rounded",
        titleAlign: "left",
        padding: 1,
      })
      const startY = Math.max(lines.length, Math.floor((height - card.length - 2) / 2))
      while (lines.length < startY) lines.push(" ".repeat(width))
      lines.push(...centerBlock(card, width))
      while (lines.length < height - 2) lines.push(" ".repeat(width))
      lines.push(centerLine(renderHelpBar(width), width))
      return lines.join("\n")
    }

    // Alert banner (if present)
    if (w.lastAlert) {
      const severityColor = w.lastAlert.severity === "critical" ? THEME.error : THEME.warning
      const alertText =
        `${severityColor}${THEME.bold} ALERT ${THEME.reset} ` +
        `${severityColor}${w.lastAlert.title}${THEME.reset} ` +
        `${THEME.dim}(${w.lastAlert.rule})${THEME.reset}`
      lines.push(fitString(alertText, width))
    }

    const summaryCard = renderWatchSummaryCard(ctx, width)
    lines.push(...centerBlock(summaryCard, width))
    lines.push("")

    const logHeight = Math.max(3, height - lines.length - 1)

    // Streaming log
    const logOutput = renderLog(w.log, logHeight, width, THEME)
    for (const l of logOutput) lines.push(l)

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
      ctx.state.hunt.report.returnScreen = "hunt-watch"
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
