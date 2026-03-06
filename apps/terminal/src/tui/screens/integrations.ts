/**
 * Integrations Screen - System health status
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { HealthStatus } from "../../health"
import { resolveDesktopAgentWatchConfig } from "../../desktop-agent"
import { renderBox } from "../components/box"
import { centerBlock, centerLine, joinColumns, wrapText } from "../components/layout"
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
      app.refreshDesktopAgent()
      app.connectHushd()
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

  const desktop = state.desktopAgent
  const watchConfig = resolveDesktopAgentWatchConfig(desktop)
  content.push("")
  content.push(`${THEME.secondary}${THEME.bold}Desktop Agent${THEME.reset}`)
  if (!desktop?.found) {
    content.push(`${THEME.muted}settings not found${THEME.reset}`)
  } else if (desktop.error) {
    content.push(`${THEME.warning}${desktop.error}${THEME.reset}`)
  } else {
    content.push(joinColumns(
      `${THEME.dim}config:${THEME.reset} ${THEME.white}${desktop.settingsPath ?? "unknown"}${THEME.reset}`,
      `${desktop.enabled ? THEME.success : THEME.warning}${desktop.enabled ? "enabled" : "disabled"}${THEME.reset}`,
      contentWidth,
    ))
    content.push(joinColumns(
      `${THEME.dim}ports:${THEME.reset} ${THEME.white}daemon ${desktop.daemonPort ?? "-"}${THEME.reset} ${THEME.dim}|${THEME.reset} ${THEME.white}mcp ${desktop.mcpPort ?? "-"}${THEME.reset}`,
      `${THEME.dim}api:${THEME.reset} ${THEME.white}${desktop.agentApiPort ?? "-"}${THEME.reset}`,
      contentWidth,
    ))
    content.push(joinColumns(
      `${THEME.dim}enrollment:${THEME.reset} ${desktop.enrolled ? `${THEME.success}enrolled${THEME.reset}` : `${THEME.warning}not enrolled${THEME.reset}`}`,
      `${THEME.dim}local id:${THEME.reset} ${THEME.muted}${desktop.localAgentId ?? "unknown"}${THEME.reset}`,
      contentWidth,
    ))
    const clusterStatus = desktop.natsEnabled
      ? `${THEME.success}enabled${THEME.reset}${desktop.natsUrl ? ` ${THEME.dim}${desktop.natsUrl}${THEME.reset}` : ""}`
      : `${THEME.warning}disabled${THEME.reset}`
    content.push(`${THEME.dim}cluster stream:${THEME.reset} ${clusterStatus}`)
    if (desktop.dashboardUrl) {
      content.push(`${THEME.dim}dashboard:${THEME.reset} ${THEME.muted}${desktop.dashboardUrl}${THEME.reset}`)
    }

    if (watchConfig.kind !== "configured" && watchConfig.kind !== "manual" && watchConfig.kind !== "not_found") {
      content.push("")
      content.push(`${THEME.secondary}${THEME.bold}Live Watch${THEME.reset}`)
      const prefix = state.hushdConnected ? "Local hushd is online. " : ""
      content.push(...wrapText(`${prefix}${watchConfig.message}`, contentWidth).map(line => `${THEME.muted}${line}${THEME.reset}`))
      if (watchConfig.kind === "not_enrolled" || watchConfig.kind === "nats_disabled") {
        content.push(...wrapText("Use Security or Audit for local events, or enroll the desktop agent to enable cluster-backed Live Watch.", contentWidth).map(line => `${THEME.muted}${line}${THEME.reset}`))
      }
    }
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
