/**
 * Security Screen - Security overview with hushd connection status
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"

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

function renderSecurityScreen(ctx: ScreenContext): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const boxWidth = Math.min(75, width - 6)
  const boxPad = Math.max(0, Math.floor((width - boxWidth) / 2))
  const startY = Math.max(1, Math.floor(height / 8))

  for (let i = 0; i < startY; i++) lines.push("")

  // Title
  const title = "⟨ Security Overview ⟩"
  const titlePadLeft = Math.floor((boxWidth - title.length - 4) / 2)
  const titlePadRight = boxWidth - title.length - titlePadLeft - 4
  lines.push(" ".repeat(boxPad) + THEME.dim + "╔═" + "═".repeat(titlePadLeft) + title + "═".repeat(titlePadRight) + "═╗" + THEME.reset)
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)

  // Connection status
  const connIcon = state.hushdConnected ? `${THEME.success}◆` : `${THEME.dim}◇`
  const connText = state.hushdConnected ? "connected" : "disconnected"
  const connLine = `  ${connIcon}${THEME.reset} hushd: ${THEME.muted}${connText}${THEME.reset}`
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + connLine + " ".repeat(Math.max(0, boxWidth - connText.length - 16)) + THEME.dim + "║" + THEME.reset)

  // Policy info
  if (state.activePolicy) {
    const p = state.activePolicy
    const policyLine = `  ${THEME.secondary}◇${THEME.reset} policy: ${THEME.white}${p.name}${THEME.reset} ${THEME.dim}v${p.version}${THEME.reset}`
    const pLen = `  ◇ policy: ${p.name} v${p.version}`.length
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + policyLine + " ".repeat(Math.max(0, boxWidth - pLen - 2)) + THEME.dim + "║" + THEME.reset)
    const guardsLine = `    ${THEME.dim}guards: ${p.guards.filter(g => g.enabled).length} active${THEME.reset}`
    const gLen = `    guards: ${p.guards.filter(g => g.enabled).length} active`.length
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + guardsLine + " ".repeat(Math.max(0, boxWidth - gLen - 2)) + THEME.dim + "║" + THEME.reset)
  }

  // Stats
  if (state.auditStats) {
    const s = state.auditStats
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
    const statsHeader = `  ${THEME.secondary}◇${THEME.reset} ${THEME.white}${THEME.bold}Statistics${THEME.reset}`
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + statsHeader + " ".repeat(Math.max(0, boxWidth - 15)) + THEME.dim + "║" + THEME.reset)
    const totalLine = `    total: ${THEME.white}${s.total_checks}${THEME.reset}  allowed: ${THEME.success}${s.allowed}${THEME.reset}  denied: ${THEME.error}${s.denied}${THEME.reset}`
    const tLen = `    total: ${s.total_checks}  allowed: ${s.allowed}  denied: ${s.denied}`.length
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + totalLine + " ".repeat(Math.max(0, boxWidth - tLen - 2)) + THEME.dim + "║" + THEME.reset)
  }

  // Recent events
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
  const evtHeader = `  ${THEME.secondary}◇${THEME.reset} ${THEME.white}${THEME.bold}Recent Events${THEME.reset}`
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + evtHeader + " ".repeat(Math.max(0, boxWidth - 19)) + THEME.dim + "║" + THEME.reset)

  const maxEvents = Math.min(state.recentEvents.length, height - lines.length - 8)
  if (maxEvents === 0) {
    const noEvt = `    ${THEME.muted}No events yet${THEME.reset}`
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + noEvt + " ".repeat(Math.max(0, boxWidth - 17)) + THEME.dim + "║" + THEME.reset)
  } else {
    for (let i = 0; i < maxEvents; i++) {
      const evt = state.recentEvents[i]
      if (evt.type === "check") {
        const d = evt.data as { action_type?: string; target?: string; guard?: string; decision?: string }
        const icon = d.decision === "deny" ? `${THEME.error}✗` : `${THEME.success}✓`
        const target = (d.target ?? "").length > 25 ? "…" + (d.target ?? "").slice(-24) : (d.target ?? "")
        const evtLine = `    ${icon}${THEME.reset} ${THEME.muted}${(d.action_type ?? "").padEnd(7)}${THEME.reset} ${target.padEnd(26)} ${THEME.dim}${d.guard ?? ""}${THEME.reset}`
        const evtLen = `    ✗ ${(d.action_type ?? "").padEnd(7)} ${target.padEnd(26)} ${d.guard ?? ""}`.length
        lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + evtLine + " ".repeat(Math.max(0, boxWidth - evtLen - 2)) + THEME.dim + "║" + THEME.reset)
      }
    }
  }

  // Help
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
  const helpText = "r refresh  ◆  esc back"
  const helpPad = Math.max(0, Math.floor((boxWidth - helpText.length) / 2))
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(helpPad) + helpText + " ".repeat(boxWidth - helpPad - helpText.length - 2) + "║" + THEME.reset)
  lines.push(" ".repeat(boxPad) + THEME.dim + "╚" + "═".repeat(boxWidth - 2) + "╝" + THEME.reset)

  // Fill remaining
  for (let i = lines.length; i < height - 1; i++) lines.push("")
  return lines.join("\n")
}
