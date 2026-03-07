/**
 * Result Screen - Task dispatch/speculate result display
 */

import { TUI } from "../index"
import { renderBox } from "../components/box"
import { centerBlock, centerLine, wrapText } from "../components/layout"
import { renderSplit } from "../components/split-pane"
import { renderSurfaceHeader } from "../components/surface-header"
import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"

export const resultScreen: Screen = {
  render(ctx: ScreenContext): string {
    return renderResultScreen(ctx)
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    if (key === "\x1b" || key === "q" || key === "\r" || key === " ") {
      if (ctx.state.activeRunId) {
        ctx.app.openRun(ctx.state.activeRunId)
      } else {
        ctx.app.setScreen("main")
      }
      return true
    }
    return false
  },
}

function renderOverviewCard(ctx: ScreenContext, boxWidth: number): string[] {
  const { state } = ctx
  const r = state.lastResult
  const content: string[] = []
  const addRow = (label: string, value: string) => {
    content.push(`${THEME.dim}${label.padEnd(12)}${THEME.reset} ${value}`)
  }

  if (!r) {
    content.push(`${THEME.muted}No execution result recorded.${THEME.reset}`)
  } else {
    const reviewWithWarnings = Boolean(
      r.execution?.success && r.verification && !r.verification.allPassed && r.verification.criticalPassed,
    )
    const titleIcon = reviewWithWarnings
      ? `${THEME.warning}!`
      : r.success
        ? `${THEME.success}✓`
        : `${THEME.error}✗`
    const titleText = reviewWithWarnings
      ? "Task Ready With Warnings"
      : r.success
        ? "Task Completed"
        : "Task Failed"
    addRow("Status", `${titleIcon}${THEME.reset} ${titleText}`)
    addRow("Agent", `${THEME.white}${r.agent}${THEME.reset}`)
    addRow("Duration", `${THEME.muted}${TUI.formatDuration(r.duration)}${THEME.reset}`)
    if (r.taskId) addRow("Task", `${THEME.dim}${r.taskId.slice(0, 8)}${THEME.reset}`)
    if (r.error && !r.execution?.error) {
      content.push("")
      content.push(`${THEME.secondary}${THEME.bold}Failure${THEME.reset}`)
      content.push(...wrapText(r.error, boxWidth - 4).map((line) => `${THEME.error}${line}${THEME.reset}`))
    }
  }

  return renderBox("Overview", content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

function renderDetailCard(ctx: ScreenContext, boxWidth: number): string[] {
  const { state } = ctx
  const r = state.lastResult
  const content: string[] = []
  const addRow = (label: string, value: string) => {
    content.push(`${THEME.dim}${label.padEnd(12)}${THEME.reset} ${value}`)
  }

  if (!r) {
    content.push(`${THEME.muted}Dispatch a task to populate this screen.${THEME.reset}`)
  } else {
    if (r.routing) {
      content.push(`${THEME.secondary}${THEME.bold}Routing${THEME.reset}`)
      addRow("Toolchain", `${THEME.white}${r.routing.toolchain}${THEME.reset}`)
      addRow("Strategy", `${THEME.muted}${r.routing.strategy}${THEME.reset}`)
      if (r.routing.gates.length > 0) {
        addRow("Gates", `${THEME.muted}${r.routing.gates.join(", ")}${THEME.reset}`)
      }
      content.push("")
    }

    if (r.execution) {
      const execIcon = r.execution.success ? `${THEME.success}✓` : `${THEME.error}✗`
      content.push(`${THEME.secondary}${THEME.bold}Execution${THEME.reset}`)
      addRow("Result", `${execIcon}${THEME.reset} ${r.execution.success ? "success" : "failed"}`)
      if (r.execution.model) addRow("Model", `${THEME.muted}${r.execution.model}${THEME.reset}`)
      if (r.execution.tokens) addRow("Tokens", `${THEME.muted}${r.execution.tokens.input} in / ${r.execution.tokens.output} out${THEME.reset}`)
      if (r.execution.cost) addRow("Cost", `${THEME.muted}$${r.execution.cost.toFixed(4)}${THEME.reset}`)
      if (r.execution.error) {
        content.push(...wrapText(r.execution.error, boxWidth - 4).map((line) => `${THEME.error}${line}${THEME.reset}`))
      }
      content.push("")
    }

    if (r.verification) {
      const vIcon = r.verification.allPassed
        ? `${THEME.success}✓`
        : r.verification.criticalPassed
          ? `${THEME.warning}!`
          : `${THEME.error}✗`
      content.push(`${THEME.secondary}${THEME.bold}Verification${THEME.reset}`)
      addRow("Score", `${vIcon}${THEME.reset} ${r.verification.score}/100`)
      for (const g of r.verification.results) {
        const gIcon = g.passed ? `${THEME.success}✓` : `${THEME.error}✗`
        addRow("", `  ${gIcon}${THEME.reset} ${g.gate}`)
      }
    }
  }

  return renderBox("Execution Detail", content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

function renderResultScreen(ctx: ScreenContext): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const r = state.lastResult
  const splitWidth = Math.min(108, width - 8)
  const boxWidth = Math.min(68, width - 10)
  const titleText = r?.success ? "success" : "failed"
  const useSplit = Boolean(r) && splitWidth >= 96 && height >= 18

  lines.push(...renderSurfaceHeader("result", "Execution Result", width, THEME, titleText))

  if (useSplit) {
    const leftWidth = Math.max(34, Math.floor((splitWidth - 1) * 0.42))
    const rightWidth = Math.max(42, splitWidth - leftWidth - 1)
    const overviewCard = renderOverviewCard(ctx, leftWidth)
    const detailCard = renderDetailCard(ctx, rightWidth)
    const bodyHeight = Math.max(overviewCard.length, detailCard.length)
    lines.push(...centerBlock(
      renderSplit(overviewCard, detailCard, splitWidth, bodyHeight, THEME, leftWidth / (splitWidth - 1)),
      width,
    ))
  } else {
    lines.push(...centerBlock(renderOverviewCard(ctx, boxWidth), width))
    lines.push("")
    lines.push(...centerBlock(renderDetailCard(ctx, boxWidth), width))
  }

  lines.push("")
  lines.push(centerLine(
    `${THEME.dim}enter${THEME.reset}${THEME.muted} continue${THEME.reset}  ` +
      `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`,
    width,
  ))

  for (let i = lines.length; i < height - 1; i++) {
    lines.push("")
  }
  return lines.join("\n")
}
