/**
 * Audit Screen - Audit log table
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"

export const auditScreen: Screen = {
  render(ctx: ScreenContext): string {
    return renderAuditScreen(ctx)
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

function renderAuditScreen(ctx: ScreenContext): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const boxWidth = Math.min(75, width - 6)
  const boxPad = Math.max(0, Math.floor((width - boxWidth) / 2))

  lines.push("")

  const title = "⟨ Audit Log ⟩"
  const titlePadLeft = Math.floor((boxWidth - title.length - 4) / 2)
  const titlePadRight = boxWidth - title.length - titlePadLeft - 4
  lines.push(" ".repeat(boxPad) + THEME.dim + "╔═" + "═".repeat(titlePadLeft) + title + "═".repeat(titlePadRight) + "═╗" + THEME.reset)
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)

  if (!state.hushdConnected) {
    const msg = `  ${THEME.muted}hushd not connected${THEME.reset}`
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + msg + " ".repeat(Math.max(0, boxWidth - 23)) + THEME.dim + "║" + THEME.reset)
  } else {
    // Column headers
    const header = `  ${THEME.white}${THEME.bold}${"time".padEnd(9)}${"action".padEnd(8)}${"target".padEnd(22)}${"guard".padEnd(20)}${"decision".padEnd(8)}${THEME.reset}`
    const hLen = `  ${"time".padEnd(9)}${"action".padEnd(8)}${"target".padEnd(22)}${"guard".padEnd(20)}${"decision".padEnd(8)}`.length
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + header + " ".repeat(Math.max(0, boxWidth - hLen - 2)) + THEME.dim + "║" + THEME.reset)

    const maxRows = Math.min(state.recentEvents.length, height - 10)
    for (let i = 0; i < maxRows; i++) {
      const evt = state.recentEvents[i]
      if (evt.type === "check") {
        const d = evt.data as { action_type?: string; target?: string; guard?: string; decision?: string }
        const time = new Date(evt.timestamp).toLocaleTimeString().slice(0, 8)
        const target = (d.target ?? "").length > 20 ? "…" + (d.target ?? "").slice(-19) : (d.target ?? "")
        const guard = (d.guard ?? "").length > 18 ? (d.guard ?? "").slice(0, 17) + "…" : (d.guard ?? "")
        const decColor = d.decision === "deny" ? THEME.error : THEME.success
        const row = `  ${THEME.dim}${time.padEnd(9)}${THEME.reset}${(d.action_type ?? "").padEnd(8)}${THEME.muted}${target.padEnd(22)}${THEME.reset}${THEME.dim}${guard.padEnd(20)}${THEME.reset}${decColor}${(d.decision ?? "").padEnd(8)}${THEME.reset}`
        const rLen = `  ${time.padEnd(9)}${(d.action_type ?? "").padEnd(8)}${target.padEnd(22)}${guard.padEnd(20)}${(d.decision ?? "").padEnd(8)}`.length
        lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + row + " ".repeat(Math.max(0, boxWidth - rLen - 2)) + THEME.dim + "║" + THEME.reset)
      }
    }

    if (state.recentEvents.length === 0) {
      const msg = `  ${THEME.muted}No audit events yet${THEME.reset}`
      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + msg + " ".repeat(Math.max(0, boxWidth - 23)) + THEME.dim + "║" + THEME.reset)
    }
  }

  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
  const helpText = "r refresh  ◆  esc back"
  const helpPad = Math.max(0, Math.floor((boxWidth - helpText.length) / 2))
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(helpPad) + helpText + " ".repeat(boxWidth - helpPad - helpText.length - 2) + "║" + THEME.reset)
  lines.push(" ".repeat(boxPad) + THEME.dim + "╚" + "═".repeat(boxWidth - 2) + "╝" + THEME.reset)

  for (let i = lines.length; i < height - 1; i++) lines.push("")
  return lines.join("\n")
}
