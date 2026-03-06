/**
 * Integrations Screen - System health status
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { HealthStatus } from "../../health"
import { renderBox } from "../components/box"
import { centerBlock, centerLine, joinColumns } from "../components/layout"
import { renderSurfaceHeader } from "../components/surface-header"

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

  const boxWidth = Math.min(72, width - 10)
  const startY = Math.max(2, Math.floor(height / 6))
  const contentWidth = boxWidth - 4

  lines.push(...renderSurfaceHeader("integrations", "Integrations", width, THEME))

  for (let i = lines.length; i < startY; i++) {
    lines.push("")
  }

  const content: string[] = []

  const runtimeLines = [
    `${THEME.secondary}${THEME.bold}Runtime${THEME.reset}`,
    joinColumns(
      `${THEME.dim}source:${THEME.reset} ${THEME.white}${state.runtimeInfo?.source ?? "unknown"}${THEME.reset}`,
      `${THEME.dim}hushd:${THEME.reset} ${THEME.white}${state.hushdStatus}${THEME.reset}`,
      contentWidth,
    ),
    `${THEME.dim}entry:${THEME.reset} ${THEME.muted}${state.runtimeInfo?.scriptPath ?? "unknown"}${THEME.reset}`,
  ]
  content.push(...runtimeLines)
  if (state.securityError) {
    content.push(`${THEME.warning}${state.securityError}${THEME.reset}`)
  }

  const addSection = (label: string, items: HealthStatus[], color: string) => {
    content.push("")
    content.push(`${THEME.secondary}${THEME.bold}${label}${THEME.reset}`)

    for (const item of items) {
      const icon = item.available ? `${color}◆${THEME.reset}` : `${THEME.dim}◇${THEME.reset}`
      const left = `${icon} ${THEME.white}${item.name.toLowerCase()}${THEME.reset}`
      const detail = item.available
        ? `${item.version ?? "available"}${item.latency ? `  ${item.latency}ms` : ""}`
        : item.error ?? "unavailable"
      content.push(joinColumns(
        left,
        `${item.available ? THEME.muted : THEME.dim}${detail}${THEME.reset}`,
        contentWidth,
      ))
    }
  }

  if (state.healthChecking) {
    content.push("")
    content.push(`${THEME.secondary}◈${THEME.reset} ${THEME.muted}Divining system state...${THEME.reset}`)
  } else if (health) {
    addSection("Security", health.security, THEME.warning)
    addSection("AI Toolchains", health.ai, THEME.accent)
    addSection("Infrastructure", health.infra, THEME.white)
    addSection("MCP Server", health.mcp, THEME.success)
  } else {
    content.push("")
    content.push(`${THEME.muted}No readings available. Press r to refresh.${THEME.reset}`)
  }

  const card = renderBox("System Status", content, boxWidth, THEME, {
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
  for (let i = lines.length; i < height - 1; i++) {
    lines.push("")
  }

  return lines.join("\n")
}
