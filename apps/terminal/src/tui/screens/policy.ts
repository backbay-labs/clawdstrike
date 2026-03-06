/**
 * Policy Screen - Active policy viewer
 */

import { renderBox } from "../components/box"
import { centerBlock, centerLine, joinColumns } from "../components/layout"
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

function renderPolicyScreen(ctx: ScreenContext): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const boxWidth = Math.min(65, width - 10)
  const contentWidth = boxWidth - 4

  lines.push(...renderSurfaceHeader("policy", "Active Policy", width, THEME, state.hushdStatus))
  const content: string[] = []

  const p = state.activePolicy
  if (!state.hushdConnected || !p) {
    content.push(!state.hushdConnected
      ? state.hushdStatus === "unauthorized"
        ? `${THEME.muted}hushd authorization required${THEME.reset}`
        : `${THEME.muted}hushd ${state.hushdStatus}${THEME.reset}`
      : `${THEME.muted}No policy loaded${THEME.reset}`)
  } else {
    const fields = [
      ["Name", p.name],
      ["Version", p.version],
      ["Schema", p.schema_version],
      ["Hash", p.hash.slice(0, 16) + "…"],
      ["Loaded", new Date(p.loaded_at).toLocaleString()],
    ]

    for (const [key, value] of fields) {
      content.push(joinColumns(
        `${THEME.dim}${key}${THEME.reset}`,
        `${THEME.white}${value}${THEME.reset}`,
        contentWidth,
      ))
    }

    if (p.extends && p.extends.length > 0) {
      content.push(`${THEME.dim}Extends${THEME.reset} ${THEME.muted}${p.extends.join(", ")}${THEME.reset}`)
    }

    content.push("")
    content.push(`${THEME.secondary}${THEME.bold}Guards${THEME.reset}`)

    for (const guard of p.guards) {
      const icon = guard.enabled ? `${THEME.success}◆` : `${THEME.dim}◇`
      const status = guard.enabled ? "active" : "disabled"
      content.push(joinColumns(
        `${icon}${THEME.reset} ${THEME.white}${guard.id}${THEME.reset}`,
        `${THEME.dim}${status}${THEME.reset}`,
        contentWidth,
      ))
    }
  }

  const card = renderBox("Policy", content, boxWidth, THEME, {
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

  for (let i = lines.length; i < height - 1; i++) lines.push("")
  return lines.join("\n")
}
