/**
 * Policy Screen - Active policy viewer
 */

import { renderBox } from "../components/box"
import { centerBlock, centerLine, joinColumns, wrapText } from "../components/layout"
import { renderSplit } from "../components/split-pane"
import { renderSurfaceHeader } from "../components/surface-header"
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

function renderUnavailablePolicyCard(ctx: ScreenContext, boxWidth: number): string[] {
  const { state } = ctx
  const message = !state.hushdConnected
    ? state.hushdStatus === "unauthorized"
      ? `${THEME.warning}hushd authorization required${THEME.reset}`
      : `${THEME.muted}hushd ${state.hushdStatus}${THEME.reset}`
    : `${THEME.muted}No policy loaded${THEME.reset}`

  return renderBox("Policy Summary", [message], boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

function renderPolicySummaryCard(ctx: ScreenContext, boxWidth: number): string[] {
  const { state } = ctx
  const p = state.activePolicy
  const contentWidth = boxWidth - 4
  const content: string[] = []

  if (!p) {
    return renderUnavailablePolicyCard(ctx, boxWidth)
  }

  const fields = [
    ["Name", p.name],
    ["Version", p.version],
    ["Schema", p.schema_version],
    ["Hash", `${p.hash.slice(0, 16)}…`],
    ["Loaded", p.loaded_at ? new Date(p.loaded_at).toLocaleString() : "unknown"],
  ]

  for (const [key, value] of fields) {
    content.push(joinColumns(
      `${THEME.dim}${key}${THEME.reset}`,
      `${THEME.white}${value}${THEME.reset}`,
      contentWidth,
    ))
  }

  if (p.description) {
    content.push("")
    content.push(`${THEME.secondary}${THEME.bold}Summary${THEME.reset}`)
    content.push(...wrapText(p.description, contentWidth).map((line) => (
      `${THEME.muted}${line}${THEME.reset}`
    )))
  }

  const sourceKind = p.source && typeof p.source === "object" && "kind" in p.source
    ? String((p.source as { kind?: unknown }).kind ?? "unknown")
    : null
  if (sourceKind) {
    content.push("")
    content.push(joinColumns(
      `${THEME.dim}Source${THEME.reset}`,
      `${THEME.muted}${sourceKind}${THEME.reset}`,
      contentWidth,
    ))
  }

  if (p.extends && p.extends.length > 0) {
    content.push("")
    content.push(`${THEME.secondary}${THEME.bold}Extends${THEME.reset}`)
    content.push(...wrapText(p.extends.join(", "), contentWidth).map((line) => (
      `${THEME.muted}${line}${THEME.reset}`
    )))
  }

  return renderBox("Policy Summary", content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

function renderPolicyGuardsCard(ctx: ScreenContext, boxWidth: number): string[] {
  const { state } = ctx
  const p = state.activePolicy
  const contentWidth = boxWidth - 4
  const content: string[] = []

  if (!p) {
    content.push(`${THEME.muted}No guards to display.${THEME.reset}`)
  } else {
    if (p.guards.length === 0) {
      content.push(`${THEME.muted}Guard summary unavailable from the active daemon policy response.${THEME.reset}`)
    } else {
      const enabled = p.guards.filter((guard) => guard.enabled).length
      content.push(`${THEME.dim}${enabled}/${p.guards.length} enabled${THEME.reset}`)
      content.push("")
      for (const guard of p.guards) {
        const icon = guard.enabled ? `${THEME.success}◆${THEME.reset}` : `${THEME.dim}◇${THEME.reset}`
        const status = guard.enabled ? "active" : "disabled"
        content.push(joinColumns(
          `${icon} ${THEME.white}${guard.id}${THEME.reset}`,
          `${THEME.dim}${status}${THEME.reset}`,
          contentWidth,
        ))
      }
    }
  }

  return renderBox("Guard Set", content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

function renderPolicyScreen(ctx: ScreenContext): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const splitWidth = Math.min(104, width - 8)
  const boxWidth = Math.min(70, width - 10)
  const useSplit = Boolean(state.activePolicy) && splitWidth >= 96 && height >= 18

  lines.push(...renderSurfaceHeader("policy", "Active Policy", width, THEME, state.hushdStatus))

  if (useSplit) {
    const leftWidth = Math.max(42, Math.floor((splitWidth - 1) * 0.52))
    const rightWidth = Math.max(34, splitWidth - leftWidth - 1)
    const summaryCard = renderPolicySummaryCard(ctx, leftWidth)
    const guardsCard = renderPolicyGuardsCard(ctx, rightWidth)
    const bodyHeight = Math.max(summaryCard.length, guardsCard.length)
    lines.push(...centerBlock(
      renderSplit(summaryCard, guardsCard, splitWidth, bodyHeight, THEME, leftWidth / (splitWidth - 1)),
      width,
    ))
  } else {
    lines.push(...centerBlock(renderPolicySummaryCard(ctx, boxWidth), width))
    if (state.activePolicy) {
      lines.push("")
      lines.push(...centerBlock(renderPolicyGuardsCard(ctx, boxWidth), width))
    }
  }

  lines.push("")
  lines.push(centerLine(
    `${THEME.dim}r${THEME.reset}${THEME.muted} refresh${THEME.reset}  ` +
      `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`,
    width,
  ))

  for (let i = lines.length; i < height - 1; i++) {
    lines.push("")
  }
  return lines.join("\n")
}
