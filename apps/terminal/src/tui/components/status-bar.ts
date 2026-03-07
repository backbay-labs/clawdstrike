/**
 * Status bar component - renders the bottom status bar.
 */

import type { ThemeColors } from "./types"
import type { ScreenStage } from "../types"
import type { HushdConnectionState } from "../../hushd"
import { fitString, stripAnsi } from "./types"

export interface StatusBarData {
  version: string
  cwd: string
  currentScreenLabel: string
  currentScreenStage: ScreenStage
  healthChecking: boolean
  health: {
    security: Array<{ available: boolean }>
    ai: Array<{ available: boolean }>
    infra: Array<{ available: boolean }>
    mcp: Array<{ available: boolean }>
  } | null
  hushdStatus: HushdConnectionState
  deniedCount: number
  activeRuns: number
  openBeads: number
  agentId: string
  investigation: {
    origin: string
    events: number
    findings: number
    stale: boolean
  } | null
  huntWatch?: { events: number; alerts: number } | null
  huntScan?: { status: string } | null
  lastExportedReport?: { title: string; severity: string } | null
}

function healthSummary(
  health: StatusBarData["health"],
  theme: ThemeColors,
): string | null {
  if (!health) {
    return null
  }

  const items = [...health.security, ...health.ai, ...health.infra, ...health.mcp]
  if (items.length === 0) {
    return `${theme.dim}health${theme.reset} ${theme.muted}--${theme.reset}`
  }

  const up = items.filter((item) => item.available).length
  const color = up === items.length ? theme.success : up === 0 ? theme.error : theme.warning
  return `${theme.dim}health${theme.reset} ${color}${up}/${items.length}${theme.reset}`
}

function renderStageBadge(stage: ScreenStage, theme: ThemeColors): string {
  if (stage === "experimental") {
    return `${theme.warning}exp${theme.reset}`
  }

  return `${theme.success}beta${theme.reset}`
}

function renderHushdBadge(status: HushdConnectionState, theme: ThemeColors): string {
  switch (status) {
    case "connected":
      return `${theme.dim}hushd${theme.reset} ${theme.success}online${theme.reset}`
    case "connecting":
      return `${theme.dim}hushd${theme.reset} ${theme.warning}connecting${theme.reset}`
    case "degraded":
      return `${theme.dim}hushd${theme.reset} ${theme.warning}degraded${theme.reset}`
    case "stale":
      return `${theme.dim}hushd${theme.reset} ${theme.warning}stale${theme.reset}`
    case "unauthorized":
      return `${theme.dim}hushd${theme.reset} ${theme.error}unauthorized${theme.reset}`
    case "error":
      return `${theme.dim}hushd${theme.reset} ${theme.error}error${theme.reset}`
    case "not_configured":
      return `${theme.dim}hushd${theme.reset} ${theme.muted}unset${theme.reset}`
    case "disconnected":
    default:
      return `${theme.dim}hushd${theme.reset} ${theme.muted}offline${theme.reset}`
  }
}

export function renderStatusBar(
  data: StatusBarData,
  width: number,
  theme: ThemeColors,
): string {
  if (width <= 0) return ""

  const segments: string[] = []

  segments.push(`${theme.dim}v${data.version}${theme.reset}`)
  segments.push(
    `${renderStageBadge(data.currentScreenStage, theme)} ${theme.white}${data.currentScreenLabel}${theme.reset}`,
  )

  if (data.healthChecking) {
    segments.push(`${theme.dim}health${theme.reset} ${theme.warning}...${theme.reset}`)
  } else {
    const summary = healthSummary(data.health, theme)
    if (summary) {
      segments.push(summary)
    }
  }

  segments.push(renderHushdBadge(data.hushdStatus, theme))

  if (data.deniedCount > 0) {
    segments.push(`${theme.dim}deny${theme.reset} ${theme.error}${data.deniedCount}${theme.reset}`)
  }

  if (data.activeRuns > 0) {
    segments.push(`${theme.dim}runs${theme.reset} ${theme.secondary}${data.activeRuns}${theme.reset}`)
  }

  if (data.openBeads > 0) {
    segments.push(`${theme.dim}beads${theme.reset} ${theme.tertiary}${data.openBeads}${theme.reset}`)
  }

  if (data.huntWatch) {
    segments.push(
      `${theme.dim}watch${theme.reset} ${theme.white}${data.huntWatch.events}e/${data.huntWatch.alerts}a${theme.reset}`,
    )
  }

  if (data.huntScan) {
    segments.push(`${theme.dim}scan${theme.reset} ${theme.muted}${data.huntScan.status}${theme.reset}`)
  }

  if (data.lastExportedReport) {
    segments.push(`${theme.dim}report${theme.reset}`)
  }

  if (data.investigation) {
    const invColor = data.investigation.stale ? theme.warning : theme.secondary
    segments.push(
      `${invColor}inv${theme.reset} ${theme.muted}${data.investigation.origin}${theme.reset} ` +
      `${theme.white}${data.investigation.events}e/${data.investigation.findings}f${theme.reset}`,
    )
  }

  const left = segments.join(` ${theme.dim}\u2502${theme.reset} `)

  const cwdShort =
    data.cwd.length > 30 ? "\u2026" + data.cwd.slice(-29) : data.cwd
  const right =
    `${theme.dim}${data.agentId}${theme.reset} ${theme.dim}\u00b7${theme.reset} ` +
    `${theme.dim}${cwdShort}${theme.reset}`

  const leftVisible = stripAnsi(left).length
  const rightVisible = stripAnsi(right).length
  const gap = Math.max(1, width - leftVisible - rightVisible)

  return fitString(`${left}${" ".repeat(gap)}${right}`, width)
}
