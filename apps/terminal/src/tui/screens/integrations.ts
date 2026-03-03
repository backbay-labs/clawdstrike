/**
 * Integrations Screen - System health status
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { HealthStatus } from "../../health"

export const integrationsScreen: Screen = {
  render(ctx: ScreenContext): string {
    return renderIntegrationsScreen(ctx)
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const { app } = ctx

    if (key === "\x1b" || key === "\x1b\x1b" || key === "q" || key === "i") {
      app.setScreen("main")
      return true
    }

    if (key === "r") {
      app.runHealthcheck()
      return true
    }

    return false
  },
}

function renderIntegrationsScreen(ctx: ScreenContext): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const health = state.health

  const boxWidth = Math.min(65, width - 10)
  const boxPad = Math.max(0, Math.floor((width - boxWidth) / 2))
  const startY = Math.max(2, Math.floor(height / 6))

  for (let i = 0; i < startY; i++) {
    lines.push("")
  }

  // Gothic title bar
  const title = "⟨ Integrations ⟩"
  const titlePadLeft = Math.floor((boxWidth - title.length - 4) / 2)
  const titlePadRight = boxWidth - title.length - titlePadLeft - 4
  const titleLine = "╔═" + "═".repeat(titlePadLeft) + title + "═".repeat(titlePadRight) + "═╗"
  lines.push(" ".repeat(boxPad) + THEME.dim + titleLine + THEME.reset)
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)

  const addSection = (label: string, items: HealthStatus[], color: string) => {
    lines.push(" ".repeat(boxPad) + THEME.dim + "║  " + THEME.reset + THEME.secondary + "◇ " + THEME.reset + THEME.white + THEME.bold + label + THEME.reset + " ".repeat(boxWidth - label.length - 6) + THEME.dim + "║" + THEME.reset)

    for (const item of items) {
      const icon = item.available ? `${color}◆${THEME.reset}` : `${THEME.dim}◇${THEME.reset}`
      const name = item.name.toLowerCase().padEnd(12)
      const version = item.available ? (item.version || "").padEnd(12) : ""
      const latency = item.available && item.latency ? `${THEME.muted}${item.latency}ms${THEME.reset}` : ""
      const error = !item.available && item.error ? THEME.dim + item.error + THEME.reset : ""

      const content = `    ${icon} ${THEME.muted}${name}${THEME.reset}${version}${latency}${error}`
      const contentLen = `    ◆ ${item.name.toLowerCase().padEnd(12)}${version}${item.latency ? `${item.latency}ms` : ""}${item.error || ""}`.length
      const rightPad = Math.max(0, boxWidth - contentLen - 3)

      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + content + " ".repeat(rightPad) + THEME.dim + "║" + THEME.reset)
    }

    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
  }

  if (state.healthChecking) {
    lines.push(" ".repeat(boxPad) + THEME.dim + "║  " + THEME.secondary + "◈" + THEME.reset + THEME.muted + " Divining system state..." + THEME.reset + " ".repeat(boxWidth - 30) + THEME.dim + "║" + THEME.reset)
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
  } else if (health) {
    addSection("Security", health.security, THEME.warning)
    addSection("AI Toolchains", health.ai, THEME.accent)
    addSection("Infrastructure", health.infra, THEME.white)
    addSection("MCP Server", health.mcp, THEME.success)
  } else {
    lines.push(" ".repeat(boxPad) + THEME.dim + "║  " + THEME.muted + "No readings available. Press r to divine." + THEME.reset + " ".repeat(boxWidth - 45) + THEME.dim + "║" + THEME.reset)
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
  }

  // Help text
  const helpText = "r refresh  ◆  esc back"
  const helpPad = Math.max(0, Math.floor((boxWidth - helpText.length) / 2))
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(helpPad) + helpText + " ".repeat(boxWidth - helpPad - helpText.length - 2) + "║" + THEME.reset)

  // Bottom border
  lines.push(" ".repeat(boxPad) + THEME.dim + "╚" + "═".repeat(boxWidth - 2) + "╝" + THEME.reset)

  // Fill remaining
  for (let i = lines.length; i < height - 1; i++) {
    lines.push("")
  }

  return lines.join("\n")
}
