/**
 * Policy Screen - Active policy viewer
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"

export const policyScreen: Screen = {
  render(ctx: ScreenContext): string {
    return renderPolicyScreen(ctx)
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

function renderPolicyScreen(ctx: ScreenContext): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const boxWidth = Math.min(65, width - 10)
  const boxPad = Math.max(0, Math.floor((width - boxWidth) / 2))

  lines.push("")
  lines.push("")

  const title = "⟨ Active Policy ⟩"
  const titlePadLeft = Math.floor((boxWidth - title.length - 4) / 2)
  const titlePadRight = boxWidth - title.length - titlePadLeft - 4
  lines.push(" ".repeat(boxPad) + THEME.dim + "╔═" + "═".repeat(titlePadLeft) + title + "═".repeat(titlePadRight) + "═╗" + THEME.reset)
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)

  const p = state.activePolicy
  if (!state.hushdConnected || !p) {
    const msg = !state.hushdConnected ? "  hushd not connected" : "  No policy loaded"
    const mLen = msg.length
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + `  ${THEME.muted}${msg.trim()}${THEME.reset}` + " ".repeat(Math.max(0, boxWidth - mLen - 2)) + THEME.dim + "║" + THEME.reset)
  } else {
    // Policy metadata
    const fields = [
      ["Name", p.name],
      ["Version", p.version],
      ["Schema", p.schema_version],
      ["Hash", p.hash.slice(0, 16) + "…"],
      ["Loaded", new Date(p.loaded_at).toLocaleString()],
    ]

    for (const [key, value] of fields) {
      const fLine = `  ${THEME.muted}${key.padEnd(10)}${THEME.reset}${THEME.white}${value}${THEME.reset}`
      const fLen = `  ${key.padEnd(10)}${value}`.length
      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + fLine + " ".repeat(Math.max(0, boxWidth - fLen - 2)) + THEME.dim + "║" + THEME.reset)
    }

    if (p.extends && p.extends.length > 0) {
      const eLine = `  ${THEME.muted}Extends   ${THEME.reset}${THEME.dim}${p.extends.join(", ")}${THEME.reset}`
      const eLen = `  Extends   ${p.extends.join(", ")}`.length
      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + eLine + " ".repeat(Math.max(0, boxWidth - eLen - 2)) + THEME.dim + "║" + THEME.reset)
    }

    // Guards list
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
    const guardsHeader = `  ${THEME.secondary}◇${THEME.reset} ${THEME.white}${THEME.bold}Guards${THEME.reset}`
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + guardsHeader + " ".repeat(Math.max(0, boxWidth - 12)) + THEME.dim + "║" + THEME.reset)

    for (const guard of p.guards) {
      const icon = guard.enabled ? `${THEME.success}◆` : `${THEME.dim}◇`
      const status = guard.enabled ? "active" : "disabled"
      const gLine = `    ${icon}${THEME.reset} ${THEME.muted}${guard.id.padEnd(30)}${THEME.reset}${THEME.dim}${status}${THEME.reset}`
      const gLen = `    ◆ ${guard.id.padEnd(30)}${status}`.length
      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + gLine + " ".repeat(Math.max(0, boxWidth - gLen - 2)) + THEME.dim + "║" + THEME.reset)
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
