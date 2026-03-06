/**
 * Security Screen - Security overview with hushd connection status
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import { renderBox } from "../components/box"
import { centerBlock, centerLine, joinColumns } from "../components/layout"
import { renderSurfaceHeader } from "../components/surface-header"

export const securityScreen: Screen = {
  render(ctx: ScreenContext): string {
    return renderSecurityScreen(ctx)
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const { app } = ctx

    if (key === "\x1b" || key === "\x1b\x1b" || key === "q") {
      app.setScreen("main")
      return true
    }

    if (key === "r") {
      app.connectHushd()
      return true
    }

    return false
  },
}

function renderEmptyRecentEventsState(ctx: ScreenContext): string[] {
  const { state } = ctx

  switch (state.hushdStatus) {
    case "unauthorized":
      return [
        `  ${THEME.error}Recent events unavailable: hushd authorization required.${THEME.reset}`,
      ]
    case "connecting":
      return [
        `  ${THEME.warning}Connecting to hushd event stream...${THEME.reset}`,
      ]
    case "degraded":
      return [
        `  ${THEME.warning}Recent events temporarily unavailable while the stream is degraded.${THEME.reset}`,
      ]
    case "stale":
      return [
        `  ${THEME.warning}Recent events are stale; waiting for a fresh hushd update.${THEME.reset}`,
      ]
    case "disconnected":
    case "error":
    case "not_configured":
      return [
        `  ${THEME.dim}Recent events unavailable because hushd is offline.${THEME.reset}`,
      ]
    case "connected":
    default:
      return [`  ${THEME.muted}No events yet${THEME.reset}`]
  }
}

function renderSecurityScreen(ctx: ScreenContext): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const boxWidth = Math.min(78, width - 8)
  const startY = Math.max(1, Math.floor(height / 10))
  const contentWidth = boxWidth - 4

  lines.push(...renderSurfaceHeader("security", "Security Overview", width, THEME, state.hushdStatus))

  for (let i = lines.length; i < startY; i++) lines.push("")

  const content: string[] = []

  // Connection status
  const connIcon = state.hushdStatus === "connected"
    ? `${THEME.success}◆`
    : state.hushdStatus === "unauthorized"
      ? `${THEME.error}✖`
      : state.hushdStatus === "connecting" || state.hushdStatus === "degraded" || state.hushdStatus === "stale"
        ? `${THEME.warning}◆`
        : `${THEME.dim}◇`
  content.push(joinColumns(
    `${connIcon}${THEME.reset} ${THEME.white}${THEME.bold}hushd${THEME.reset}`,
    `${THEME.muted}${state.hushdStatus}${THEME.reset}`,
    contentWidth,
  ))
  if (state.hushdDroppedEvents > 0 || state.hushdReconnectAttempts > 0) {
    content.push(
      `  ${THEME.dim}stream:${THEME.reset} dropped ${state.hushdDroppedEvents}  reconnect ${state.hushdReconnectAttempts}`,
    )
  }
  if (state.hushdLastError) {
    content.push(`  ${THEME.dim}last error:${THEME.reset} ${THEME.warning}${state.hushdLastError}${THEME.reset}`)
  }

  // Policy info
  if (state.activePolicy) {
    const p = state.activePolicy
    content.push("")
    content.push(`${THEME.secondary}${THEME.bold}Policy${THEME.reset}`)
    content.push(joinColumns(
      `${THEME.white}${p.name}${THEME.reset}`,
      `${THEME.dim}v${p.version}${THEME.reset}`,
      contentWidth,
    ))
    content.push(`  ${THEME.dim}guards:${THEME.reset} ${THEME.white}${p.guards.filter(g => g.enabled).length}${THEME.reset} active`)
  }

  // Stats
  if (state.auditStats) {
    const s = state.auditStats
    content.push("")
    content.push(`${THEME.secondary}${THEME.bold}Statistics${THEME.reset}`)
    content.push(
      `  ${THEME.dim}total:${THEME.reset} ${THEME.white}${s.total_events}${THEME.reset}  ` +
      `${THEME.dim}allowed:${THEME.reset} ${THEME.success}${s.allowed}${THEME.reset}  ` +
      `${THEME.dim}violations:${THEME.reset} ${THEME.error}${s.violations}${THEME.reset}`,
    )
    content.push(
      `  ${THEME.dim}uptime:${THEME.reset} ${THEME.white}${s.uptime_secs}s${THEME.reset}  ` +
      `${THEME.dim}session:${THEME.reset} ${THEME.muted}${s.session_id}${THEME.reset}`,
    )
  }

  // Recent events
  content.push("")
  content.push(`${THEME.secondary}${THEME.bold}Recent Events${THEME.reset}`)

  const maxEvents = Math.min(state.recentEvents.length, height - lines.length - 8)
  if (maxEvents === 0) {
    content.push(...renderEmptyRecentEventsState(ctx))
  } else {
    for (let i = 0; i < maxEvents; i++) {
      const evt = state.recentEvents[i]
      if (evt.type === "check") {
        const d = evt.data as { action_type?: string; target?: string; guard?: string; decision?: string }
        const icon = d.decision === "deny" ? `${THEME.error}✗` : `${THEME.success}✓`
        const target = (d.target ?? "").length > 25 ? "…" + (d.target ?? "").slice(-24) : (d.target ?? "")
        content.push(joinColumns(
          `${icon}${THEME.reset} ${THEME.muted}${d.action_type ?? "check"}${THEME.reset} ${THEME.white}${target}${THEME.reset}`,
          `${THEME.dim}${d.guard ?? ""}${THEME.reset}`,
          contentWidth,
        ))
      }
    }
  }

  const card = renderBox("Security Posture", content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
  lines.push(...centerBlock(card, width))
  lines.push("")
  lines.push(centerLine(
    `${THEME.dim}r${THEME.reset}${THEME.muted} refresh${THEME.reset}  ` +
      `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`,
    width,
  ))

  // Fill remaining
  for (let i = lines.length; i < height - 1; i++) lines.push("")
  return lines.join("\n")
}
