/**
 * Integrations Screen - System health status
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { HealthStatus } from "../../health"
import { renderSurfaceHeader } from "../components/surface-header"
import { fitString } from "../components/types"

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

  lines.push(...renderSurfaceHeader("integrations", "Integrations", width, THEME))

  for (let i = lines.length; i < startY; i++) {
    lines.push("")
  }

  lines.push(" ".repeat(boxPad) + THEME.dim + "╔" + "═".repeat(boxWidth - 2) + "╗" + THEME.reset)
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)

  const runtimeLines = [
    `  ${THEME.secondary}◇${THEME.reset} ${THEME.white}${THEME.bold}Runtime${THEME.reset}`,
    fitString(
      `    source: ${THEME.white}${state.runtimeInfo?.source ?? "unknown"}${THEME.reset}` +
      `  ${THEME.dim}hushd:${THEME.reset} ${THEME.white}${state.hushdStatus}${THEME.reset}`,
      boxWidth - 2,
    ),
    fitString(
      `    entry: ${THEME.dim}${state.runtimeInfo?.scriptPath ?? "unknown"}${THEME.reset}`,
      boxWidth - 2,
    ),
  ]
  for (const line of runtimeLines) {
    const plain = line.replace(/\x1b\[[0-9;]*m/g, "")
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + line + " ".repeat(Math.max(0, boxWidth - plain.length - 2)) + THEME.dim + "║" + THEME.reset)
  }
  if (state.securityError) {
    const line = fitString(`    ${THEME.warning}${state.securityError}${THEME.reset}`, boxWidth - 2)
    const plain = line.replace(/\x1b\[[0-9;]*m/g, "")
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + line + " ".repeat(Math.max(0, boxWidth - plain.length - 2)) + THEME.dim + "║" + THEME.reset)
  }
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
