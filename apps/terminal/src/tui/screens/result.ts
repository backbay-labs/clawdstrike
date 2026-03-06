/**
 * Result Screen - Task dispatch/speculate result display
 */

import { TUI } from "../index"
import { renderBox } from "../components/box"
import { centerBlock, centerLine } from "../components/layout"
import { renderSurfaceHeader } from "../components/surface-header"
import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"

export const resultScreen: Screen = {
  render(ctx: ScreenContext): string {
    return renderResultScreen(ctx)
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    if (key === "\x1b" || key === "q" || key === "\r" || key === " ") {
      ctx.app.setScreen("main")
      return true
    }
    return false
  },
}

function renderResultScreen(ctx: ScreenContext): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const r = state.lastResult

  const boxWidth = Math.min(65, width - 10)
  const startY = Math.max(2, Math.floor(height / 6))

  lines.push(...renderSurfaceHeader("result", "Execution Result", width, THEME, r?.success ? "success" : "failed"))
  for (let i = lines.length; i < startY; i++) lines.push("")

  const titleIcon = r?.success ? `${THEME.success}✓` : `${THEME.error}✗`
  const titleText = r?.success ? "Task Completed" : "Task Failed"
  const content: string[] = []
  const addRow = (label: string, value: string) => {
    content.push(`${THEME.dim}${label.padEnd(12)}${THEME.reset} ${value}`)
  }

  if (r) {
    addRow("Status", `${titleIcon}${THEME.reset} ${titleText}`)
    addRow("Agent", `${THEME.white}${r.agent}${THEME.reset}`)
    addRow("Duration", `${THEME.muted}${TUI.formatDuration(r.duration)}${THEME.reset}`)
    if (r.taskId) addRow("Task", `${THEME.dim}${r.taskId.slice(0, 8)}${THEME.reset}`)

    if (r.routing) {
      content.push("")
      content.push(`${THEME.secondary}${THEME.bold}Routing${THEME.reset}`)
      addRow("Toolchain", `${THEME.white}${r.routing.toolchain}${THEME.reset}`)
      addRow("Strategy", `${THEME.muted}${r.routing.strategy}${THEME.reset}`)
      if (r.routing.gates.length > 0) addRow("Gates", `${THEME.muted}${r.routing.gates.join(", ")}${THEME.reset}`)
    }

    if (r.execution) {
      const execIcon = r.execution.success ? `${THEME.success}✓` : `${THEME.error}✗`
      content.push("")
      content.push(`${THEME.secondary}${THEME.bold}Execution${THEME.reset}`)
      addRow("Result", `${execIcon}${THEME.reset} ${r.execution.success ? "success" : "failed"}`)
      if (r.execution.model) addRow("Model", `${THEME.muted}${r.execution.model}${THEME.reset}`)
      if (r.execution.tokens) addRow("Tokens", `${THEME.muted}${r.execution.tokens.input} in / ${r.execution.tokens.output} out${THEME.reset}`)
      if (r.execution.cost) addRow("Cost", `${THEME.muted}$${r.execution.cost.toFixed(4)}${THEME.reset}`)
      if (r.execution.error) addRow("Error", `${THEME.error}${r.execution.error.slice(0, 40)}${THEME.reset}`)
    }

    if (r.verification) {
      const vIcon = r.verification.allPassed ? `${THEME.success}✓` : `${THEME.error}✗`
      content.push("")
      content.push(`${THEME.secondary}${THEME.bold}Verification${THEME.reset}`)
      addRow("Score", `${vIcon}${THEME.reset} ${r.verification.score}/100`)
      for (const g of r.verification.results) {
        const gIcon = g.passed ? `${THEME.success}✓` : `${THEME.error}✗`
        addRow("", `  ${gIcon}${THEME.reset} ${g.gate}`)
      }
    }

    if (r.error && !r.execution?.error) {
      addRow("Error", `${THEME.error}${r.error.slice(0, 45)}${THEME.reset}`)
    }
  }

  const card = renderBox(titleText, content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
  lines.push(...centerBlock(card, width))
  lines.push("")
  lines.push(centerLine(
    `${THEME.dim}enter${THEME.reset}${THEME.muted} continue${THEME.reset}  ` +
      `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`,
    width,
  ))

  for (let i = lines.length; i < height - 1; i++) lines.push("")
  return lines.join("\n")
}
