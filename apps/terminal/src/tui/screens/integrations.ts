/**
 * Integrations Screen - System health status
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { HealthStatus } from "../../health"
import { resolveDesktopAgentWatchConfig } from "../../desktop-agent"
import { renderBox } from "../components/box"
import { centerBlock, centerLine, joinColumns, wrapText } from "../components/layout"
import { renderSplit } from "../components/split-pane"
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

function truncateMiddle(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value
  }

  const head = Math.max(5, Math.floor((maxLength - 1) / 2))
  const tail = Math.max(5, maxLength - head - 1)
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

function renderValueBlock(label: string, value: string, width: number, color = THEME.white): string[] {
  const singleLine = `${THEME.dim}${label}:${THEME.reset} ${color}${value}${THEME.reset}`
  if (singleLine.replace(/\x1b\[[0-9;]*m/g, "").length <= width) {
    return [singleLine]
  }

  return [
    `${THEME.dim}${label}:${THEME.reset}`,
    `${color}${truncateMiddle(value, width)}${THEME.reset}`,
  ]
}

function renderIntegrationsScreen(ctx: ScreenContext): string {
  const { width, height } = ctx
  const lines: string[] = []
  const splitWidth = Math.min(110, width - 8)
  const boxWidth = Math.min(72, width - 10)
  const startY = Math.max(2, Math.floor(height / 7))
  const useSplit = splitWidth >= 96 && height >= 22

  lines.push(...renderSurfaceHeader("integrations", "Integrations", width, THEME))

  for (let i = lines.length; i < startY; i++) {
    lines.push("")
  }

  if (useSplit) {
    const leftWidth = Math.max(44, Math.floor((splitWidth - 1) * 0.52))
    const rightWidth = Math.max(38, splitWidth - leftWidth - 1)
    const leftCard = renderRuntimeCard(ctx, leftWidth)
    const rightCard = renderHealthCard(ctx, rightWidth)
    const bodyHeight = Math.max(leftCard.length, rightCard.length)
    lines.push(
      ...centerBlock(
        renderSplit(leftCard, rightCard, splitWidth, bodyHeight, THEME, leftWidth / (splitWidth - 1)),
        width,
      ),
    )
  } else {
    const runtimeCard = renderRuntimeCard(ctx, boxWidth)
    const healthCard = renderHealthCard(ctx, boxWidth)
    lines.push(...centerBlock(runtimeCard, width))
    lines.push("")
    lines.push(...centerBlock(healthCard, width))
  }

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

function renderRuntimeCard(ctx: ScreenContext, boxWidth: number): string[] {
  const { state } = ctx
  const contentWidth = boxWidth - 4
  const content: string[] = []

  const runtimeSource = state.runtimeInfo?.source ?? "unknown"
  const runtimeEntry = state.runtimeInfo?.scriptPath ?? "unknown"
  content.push(`${THEME.secondary}${THEME.bold}Runtime${THEME.reset}`)
  content.push(joinColumns(
    `${THEME.dim}source:${THEME.reset} ${THEME.white}${runtimeSource}${THEME.reset}`,
    `${THEME.dim}hushd:${THEME.reset} ${THEME.white}${state.hushdStatus}${THEME.reset}`,
    contentWidth,
  ))
  content.push(...renderValueBlock("entry", runtimeEntry, contentWidth, THEME.dim))
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
      `${THEME.dim}status:${THEME.reset} ${desktop.enabled ? `${THEME.success}enabled${THEME.reset}` : `${THEME.warning}disabled${THEME.reset}`}`,
      `${THEME.dim}enrollment:${THEME.reset} ${desktop.enrolled ? `${THEME.success}enrolled${THEME.reset}` : `${THEME.warning}not enrolled${THEME.reset}`}`,
      contentWidth,
    ))
    content.push(joinColumns(
      `${THEME.dim}ports:${THEME.reset} ${THEME.white}daemon ${desktop.daemonPort ?? "-"}${THEME.reset} ${THEME.dim}|${THEME.reset} ${THEME.white}mcp ${desktop.mcpPort ?? "-"}${THEME.reset}`,
      `${THEME.dim}api:${THEME.reset} ${THEME.white}${desktop.agentApiPort ?? "-"}${THEME.reset}`,
      contentWidth,
    ))
    content.push(...renderValueBlock("config", desktop.settingsPath ?? "unknown", contentWidth, THEME.dim))
    if (desktop.localAgentId) {
      content.push(...renderValueBlock("local id", desktop.localAgentId, contentWidth, THEME.dim))
    }

    const clusterStatus = desktop.natsEnabled
      ? `enabled${desktop.natsUrl ? ` ${desktop.natsUrl}` : ""}`
      : "disabled"
    content.push(...renderValueBlock(
      "cluster stream",
      clusterStatus,
      contentWidth,
      desktop.natsEnabled ? THEME.muted : THEME.warning,
    ))

    if (watchConfig.kind === "configured" || watchConfig.kind === "manual") {
      const authLabel = watchConfig.authType === "creds"
        ? "creds file"
        : watchConfig.authType === "token"
          ? "token"
          : watchConfig.authType === "nkey"
            ? "nkey"
            : "none"
      content.push(`${THEME.dim}watch auth:${THEME.reset} ${THEME.white}${authLabel}${THEME.reset}`)
    }
    if (desktop.dashboardUrl) {
      content.push(...renderValueBlock("dashboard", desktop.dashboardUrl, contentWidth, THEME.dim))
    }

    if (watchConfig.kind !== "configured" && watchConfig.kind !== "manual" && watchConfig.kind !== "not_found") {
      content.push("")
      content.push(`${THEME.secondary}${THEME.bold}Next Step${THEME.reset}`)
      const prefix = state.hushdConnected ? "Local hushd is online. " : ""
      content.push(
        ...wrapText(`${prefix}${watchConfig.message}`, contentWidth).map((line) => (
          `${THEME.muted}${line}${THEME.reset}`
        )),
      )
      if (watchConfig.kind === "not_enrolled" || watchConfig.kind === "nats_disabled") {
        content.push(
          ...wrapText(
            "Use Security or Audit for local events, or enroll the desktop agent to enable cluster-backed Live Watch.",
            contentWidth,
          ).map((line) => `${THEME.muted}${line}${THEME.reset}`),
        )
      }
    }
  }

  return renderBox("Runtime & Agent", content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

function summarizeHealth(items: HealthStatus[]): string {
  if (items.length === 0) {
    return "0/0 ready"
  }

  const ready = items.filter((item) => item.available).length
  return `${ready}/${items.length} ready`
}

function renderHealthSection(label: string, items: HealthStatus[], width: number, color: string): string[] {
  const lines = [
    `${THEME.secondary}${THEME.bold}${label}${THEME.reset} ${THEME.dim}${summarizeHealth(items)}${THEME.reset}`,
  ]

  for (const item of items) {
    const icon = item.available ? `${color}◆${THEME.reset}` : `${THEME.dim}◇${THEME.reset}`
    const left = `${icon} ${THEME.white}${item.name.toLowerCase()}${THEME.reset}`
    const detail = item.available
      ? `${item.version ?? "available"}${item.latency ? `  ${item.latency}ms` : ""}`
      : item.error ?? "unavailable"
    lines.push(joinColumns(
      left,
      `${item.available ? THEME.muted : THEME.dim}${detail}${THEME.reset}`,
      width,
    ))
  }

  return lines
}

function renderHealthCard(ctx: ScreenContext, boxWidth: number): string[] {
  const { state } = ctx
  const contentWidth = boxWidth - 4
  const content: string[] = []

  if (state.healthChecking) {
    content.push(`${THEME.secondary}◈${THEME.reset} ${THEME.muted}Divining system state...${THEME.reset}`)
  } else if (state.health) {
    content.push(...renderHealthSection("Security", state.health.security, contentWidth, THEME.warning))
    content.push("")
    content.push(...renderHealthSection("AI Toolchains", state.health.ai, contentWidth, THEME.accent))
    content.push("")
    content.push(...renderHealthSection("Infrastructure", state.health.infra, contentWidth, THEME.white))
    content.push("")
    content.push(...renderHealthSection("MCP Server", state.health.mcp, contentWidth, THEME.success))
  } else {
    content.push(`${THEME.muted}No readings available. Press r to refresh.${THEME.reset}`)
  }

  return renderBox("Tooling & Services", content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}
