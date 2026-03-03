/**
 * Status bar component - renders the bottom status bar.
 */

import type { ThemeColors } from "./types"
import { fitString, stripAnsi } from "./types"

export interface StatusBarData {
  version: string
  cwd: string
  healthChecking: boolean
  health: {
    security: Array<{ available: boolean }>
    ai: Array<{ available: boolean }>
    infra: Array<{ available: boolean }>
    mcp: Array<{ available: boolean }>
  } | null
  hushdConnected: boolean
  deniedCount: number
  activeRuns: number
  openBeads: number
  agentId: string
  huntWatch?: { events: number; alerts: number } | null
  huntScan?: { status: string } | null
}

function healthDot(items: Array<{ available: boolean }> | undefined, theme: ThemeColors): string {
  if (!items || items.length === 0) return `${theme.dim}\u25CB${theme.reset}`
  const allUp = items.every((i) => i.available)
  const anyUp = items.some((i) => i.available)
  if (allUp) return `${theme.success}\u25CF${theme.reset}`
  if (anyUp) return `${theme.warning}\u25CF${theme.reset}`
  return `${theme.error}\u25CF${theme.reset}`
}

export function renderStatusBar(
  data: StatusBarData,
  width: number,
  theme: ThemeColors,
): string {
  if (width <= 0) return ""

  const segments: string[] = []

  // Version
  segments.push(`${theme.dim}v${data.version}${theme.reset}`)

  // Health dots
  if (data.healthChecking) {
    segments.push(`${theme.dim}\u2026${theme.reset}`)
  } else if (data.health) {
    const sec = healthDot(data.health.security, theme)
    const ai = healthDot(data.health.ai, theme)
    const infra = healthDot(data.health.infra, theme)
    const mcp = healthDot(data.health.mcp, theme)
    segments.push(`${sec}${ai}${infra}${mcp}`)
  }

  // Hushd connection
  if (data.hushdConnected) {
    segments.push(`${theme.success}\u25CF${theme.reset}${theme.dim} hushd${theme.reset}`)
  }

  // Denied count
  if (data.deniedCount > 0) {
    segments.push(`${theme.error}\u2716 ${data.deniedCount}${theme.reset}`)
  }

  // Active runs
  if (data.activeRuns > 0) {
    segments.push(`${theme.secondary}\u25B6 ${data.activeRuns}${theme.reset}`)
  }

  // Open beads
  if (data.openBeads > 0) {
    segments.push(`${theme.tertiary}\u25C8 ${data.openBeads}${theme.reset}`)
  }

  // Hunt watch
  if (data.huntWatch) {
    const evtColor = data.huntWatch.alerts > 0 ? theme.warning : theme.muted
    segments.push(
      `${evtColor}\u2302 ${data.huntWatch.events}e/${data.huntWatch.alerts}a${theme.reset}`,
    )
  }

  // Hunt scan
  if (data.huntScan) {
    segments.push(`${theme.muted}\u2261 ${data.huntScan.status}${theme.reset}`)
  }

  const left = segments.join(` ${theme.dim}\u2502${theme.reset} `)

  // Right side: cwd + agent
  const cwdShort =
    data.cwd.length > 30 ? "\u2026" + data.cwd.slice(-29) : data.cwd
  const right = `${theme.dim}${cwdShort}${theme.reset} ${theme.dim}${data.agentId}${theme.reset}`

  // Calculate spacing
  const leftVisible = stripAnsi(left).length
  const rightVisible = stripAnsi(right).length
  const gap = Math.max(1, width - leftVisible - rightVisible)

  return fitString(`${left}${" ".repeat(gap)}${right}`, width)
}
