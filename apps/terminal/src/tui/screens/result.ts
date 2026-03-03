/**
 * Result Screen - Task dispatch/speculate result display
 */

import { TUI } from "../index"
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
  const boxPad = Math.max(0, Math.floor((width - boxWidth) / 2))
  const startY = Math.max(2, Math.floor(height / 6))

  for (let i = 0; i < startY; i++) lines.push("")

  // Title
  const titleIcon = r?.success ? `${THEME.success}✓` : `${THEME.error}✗`
  const titleText = r?.success ? "Task Completed" : "Task Failed"
  const title = `⟨ ${titleText} ⟩`
  const titlePadLeft = Math.floor((boxWidth - title.length - 4) / 2)
  const titlePadRight = boxWidth - title.length - titlePadLeft - 4
  lines.push(" ".repeat(boxPad) + THEME.dim + "╔═" + "═".repeat(titlePadLeft) + title + "═".repeat(titlePadRight) + "═╗" + THEME.reset)
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)

  const addRow = (label: string, value: string) => {
    const content = `  ${THEME.muted}${label.padEnd(14)}${THEME.reset}${value}`
    const contentLen = `  ${label.padEnd(14)}${value.replace(/\x1b\[[0-9;]*m/g, "")}`.length
    const rightPad = Math.max(0, boxWidth - contentLen - 2)
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + content + " ".repeat(rightPad) + THEME.dim + "║" + THEME.reset)
  }

  if (r) {
    addRow("Status", `${titleIcon}${THEME.reset} ${titleText}`)
    addRow("Agent", `${THEME.white}${r.agent}${THEME.reset}`)
    addRow("Duration", `${THEME.muted}${TUI.formatDuration(r.duration)}${THEME.reset}`)
    if (r.taskId) addRow("Task", `${THEME.dim}${r.taskId.slice(0, 8)}${THEME.reset}`)

    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)

    // Routing
    if (r.routing) {
      lines.push(" ".repeat(boxPad) + THEME.dim + "║  " + THEME.reset + THEME.secondary + "◇ " + THEME.reset + THEME.white + THEME.bold + "Routing" + THEME.reset + " ".repeat(boxWidth - 12) + THEME.dim + "║" + THEME.reset)
      addRow("Toolchain", `${THEME.white}${r.routing.toolchain}${THEME.reset}`)
      addRow("Strategy", `${THEME.muted}${r.routing.strategy}${THEME.reset}`)
      if (r.routing.gates.length > 0) addRow("Gates", `${THEME.muted}${r.routing.gates.join(", ")}${THEME.reset}`)
      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
    }

    // Execution
    if (r.execution) {
      const execIcon = r.execution.success ? `${THEME.success}✓` : `${THEME.error}✗`
      lines.push(" ".repeat(boxPad) + THEME.dim + "║  " + THEME.reset + THEME.secondary + "◇ " + THEME.reset + THEME.white + THEME.bold + "Execution" + THEME.reset + " ".repeat(boxWidth - 14) + THEME.dim + "║" + THEME.reset)
      addRow("Result", `${execIcon}${THEME.reset} ${r.execution.success ? "success" : "failed"}`)
      if (r.execution.model) addRow("Model", `${THEME.muted}${r.execution.model}${THEME.reset}`)
      if (r.execution.tokens) addRow("Tokens", `${THEME.muted}${r.execution.tokens.input} in / ${r.execution.tokens.output} out${THEME.reset}`)
      if (r.execution.cost) addRow("Cost", `${THEME.muted}$${r.execution.cost.toFixed(4)}${THEME.reset}`)
      if (r.execution.error) addRow("Error", `${THEME.error}${r.execution.error.slice(0, 40)}${THEME.reset}`)
      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
    }

    // Verification
    if (r.verification) {
      const vIcon = r.verification.allPassed ? `${THEME.success}✓` : `${THEME.error}✗`
      lines.push(" ".repeat(boxPad) + THEME.dim + "║  " + THEME.reset + THEME.secondary + "◇ " + THEME.reset + THEME.white + THEME.bold + "Verification" + THEME.reset + " ".repeat(boxWidth - 17) + THEME.dim + "║" + THEME.reset)
      addRow("Score", `${vIcon}${THEME.reset} ${r.verification.score}/100`)
      for (const g of r.verification.results) {
        const gIcon = g.passed ? `${THEME.success}✓` : `${THEME.error}✗`
        addRow("", `  ${gIcon}${THEME.reset} ${g.gate}`)
      }
      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
    }

    // Error
    if (r.error && !r.execution?.error) {
      addRow("Error", `${THEME.error}${r.error.slice(0, 45)}${THEME.reset}`)
      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
    }
  }

  // Help
  const helpText = "enter continue  ◆  esc back"
  const helpPad2 = Math.max(0, Math.floor((boxWidth - helpText.length) / 2))
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(helpPad2) + helpText + " ".repeat(boxWidth - helpPad2 - helpText.length - 2) + "║" + THEME.reset)
  lines.push(" ".repeat(boxPad) + THEME.dim + "╚" + "═".repeat(boxWidth - 2) + "╝" + THEME.reset)

  for (let i = lines.length; i < height - 1; i++) lines.push("")
  return lines.join("\n")
}
