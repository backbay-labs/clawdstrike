import { renderBox } from "../components/box"
import { centerBlock, centerLine, wrapText } from "../components/layout"
import { renderList, scrollDown, scrollUp } from "../components/scrollable-list"
import { renderSplit } from "../components/split-pane"
import { renderSurfaceHeader } from "../components/surface-header"
import { THEME } from "../theme"
import type { RunEvent, RunRecord, Screen, ScreenContext } from "../types"
import { formatRunPhase } from "../runs"

function getCurrentRun(ctx: ScreenContext): RunRecord | null {
  const { runs, activeRunId } = ctx.state
  const runId = activeRunId ?? runs.selectedRunId
  return runs.entries.find((entry) => entry.id === runId) ?? runs.entries[0] ?? null
}

function formatTimestamp(timestamp: string): string {
  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) {
    return timestamp
  }

  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })
}

function eventPrefix(event: RunEvent): string {
  switch (event.kind) {
    case "error":
      return `${THEME.error}!${THEME.reset}`
    case "warning":
      return `${THEME.warning}!${THEME.reset}`
    case "log":
      return `${THEME.accent}>${THEME.reset}`
    default:
      return `${THEME.success}•${THEME.reset}`
  }
}

function renderSummaryCard(run: RunRecord, width: number): string[] {
  const content: string[] = []
  const addRow = (label: string, value: string) => {
    content.push(`${THEME.dim}${label.padEnd(11)}${THEME.reset} ${value}`)
  }

  addRow("Run", `${THEME.white}${run.id}${THEME.reset}`)
  addRow("Agent", `${THEME.white}${run.agentLabel}${THEME.reset} ${THEME.dim}(${run.agentId})${THEME.reset}`)
  addRow("Action", `${THEME.secondary}${run.action}${THEME.reset}`)
  addRow("Mode", `${THEME.white}${run.mode}${THEME.reset}`)
  addRow("Phase", `${THEME.white}${formatRunPhase(run.phase)}${THEME.reset}`)
  addRow("Created", `${THEME.dim}${formatTimestamp(run.createdAt)}${THEME.reset}`)
  addRow("Updated", `${THEME.dim}${formatTimestamp(run.updatedAt)}${THEME.reset}`)

  if (run.routing) {
    content.push("")
    content.push(`${THEME.secondary}${THEME.bold}Routing${THEME.reset}`)
    addRow("Toolchain", `${THEME.white}${run.routing.toolchain}${THEME.reset}`)
    addRow("Strategy", `${THEME.dim}${run.routing.strategy}${THEME.reset}`)
    if (run.routing.gates.length > 0) {
      addRow("Gates", `${THEME.dim}${run.routing.gates.join(", ")}${THEME.reset}`)
    }
  }

  if (run.worktreePath || run.workcellId) {
    content.push("")
    content.push(`${THEME.secondary}${THEME.bold}Workspace${THEME.reset}`)
    if (run.workcellId) {
      addRow("Workcell", `${THEME.dim}${run.workcellId}${THEME.reset}`)
    }
    if (run.worktreePath) {
      addRow("Worktree", `${THEME.dim}${run.worktreePath}${THEME.reset}`)
    }
  }

  content.push("")
  content.push(`${THEME.secondary}${THEME.bold}Prompt${THEME.reset}`)
  content.push(...wrapText(run.prompt, Math.max(12, width - 4)).map((line) => `${THEME.white}${line}${THEME.reset}`))

  return renderBox("Run Summary", content, width, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

function renderStatusCard(run: RunRecord, width: number): string[] {
  const content: string[] = []
  const addRow = (label: string, value: string) => {
    content.push(`${THEME.dim}${label.padEnd(11)}${THEME.reset} ${value}`)
  }

  if (!run.result) {
    content.push(`${THEME.muted}Waiting for execution result…${THEME.reset}`)
  } else {
    addRow("Outcome", run.result.success ? `${THEME.success}success${THEME.reset}` : `${THEME.error}failed${THEME.reset}`)
    addRow("Duration", `${THEME.dim}${Math.max(0, Math.round(run.result.duration / 1000))}s${THEME.reset}`)
    if (run.execution?.model) {
      addRow("Model", `${THEME.dim}${run.execution.model}${THEME.reset}`)
    }
    if (run.execution?.tokens) {
      addRow("Tokens", `${THEME.dim}${run.execution.tokens.input} in / ${run.execution.tokens.output} out${THEME.reset}`)
    }
    if (typeof run.execution?.cost === "number") {
      addRow("Cost", `${THEME.dim}$${run.execution.cost.toFixed(4)}${THEME.reset}`)
    }

    if (run.verification) {
      content.push("")
      content.push(`${THEME.secondary}${THEME.bold}Verification${THEME.reset}`)
      addRow(
        "Score",
        run.verification.allPassed
          ? `${THEME.success}${run.verification.score}/100${THEME.reset}`
          : `${THEME.warning}${run.verification.score}/100${THEME.reset}`,
      )
      if (run.verification.summary) {
        content.push(...wrapText(run.verification.summary, Math.max(12, width - 4)).map((line) => `${THEME.dim}${line}${THEME.reset}`))
      }
      for (const gate of run.verification.results) {
        const icon = gate.passed ? `${THEME.success}✓${THEME.reset}` : `${THEME.error}✗${THEME.reset}`
        addRow("", `${icon} ${gate.gate}`)
      }
    }

    if (run.error) {
      content.push("")
      content.push(`${THEME.secondary}${THEME.bold}Failure${THEME.reset}`)
      content.push(...wrapText(run.error, Math.max(12, width - 4)).map((line) => `${THEME.error}${line}${THEME.reset}`))
    }
  }

  return renderBox("Status", content, width, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

function renderEventsCard(ctx: ScreenContext, run: RunRecord, width: number, height: number): string[] {
  const listHeight = Math.max(4, height - 2)
  const items = run.events.map((event) => ({
    label: `${eventPrefix(event)} ${THEME.dim}${formatTimestamp(event.timestamp)}${THEME.reset} ${event.message}`,
    plainLength: event.message.length + 10,
  }))
  const lines = renderList(items, ctx.state.runDetailEvents, listHeight, Math.max(12, width - 2), THEME)
  return renderBox("Live Events", lines, width, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 0,
  })
}

function renderEmptyState(ctx: ScreenContext): string {
  const lines: string[] = []
  lines.push(...renderSurfaceHeader("run-detail", "Managed Run Detail", ctx.width, THEME, "idle"))
  lines.push("")
  lines.push(...centerBlock(
    renderBox(
      "Run Detail",
      [
        `${THEME.muted}No managed run is selected.${THEME.reset}`,
        `${THEME.dim}Launch a dispatch from the main surface to populate this view.${THEME.reset}`,
      ],
      Math.min(72, ctx.width - 4),
      THEME,
      { style: "rounded", titleAlign: "left", padding: 1 },
    ),
    ctx.width,
  ))

  while (lines.length < ctx.height - 1) {
    lines.push("")
  }
  return lines.join("\n")
}

function eventViewportHeight(height: number): number {
  return Math.max(6, height - 10)
}

export const runDetailScreen: Screen = {
  render(ctx: ScreenContext): string {
    const run = getCurrentRun(ctx)
    if (!run) {
      return renderEmptyState(ctx)
    }

    const lines: string[] = []
    lines.push(
      ...renderSurfaceHeader(
        "run-detail",
        "Managed Run Detail",
        ctx.width,
        THEME,
        `${run.agentLabel} • ${formatRunPhase(run.phase)}`,
      ),
    )

    const contentWidth = Math.max(40, ctx.width - 4)
    const summaryWidth = contentWidth >= 104 ? Math.max(38, Math.floor((contentWidth - 1) * 0.44)) : contentWidth
    const eventWidth = contentWidth >= 104 ? contentWidth - summaryWidth - 1 : contentWidth

    const summary = renderSummaryCard(run, summaryWidth)
    const status = renderStatusCard(run, summaryWidth)
    const leftPane = [...summary, "", ...status]

    const events = renderEventsCard(ctx, run, eventWidth, Math.max(leftPane.length, 12))

    if (contentWidth >= 104) {
      lines.push(...centerBlock(
        renderSplit(leftPane, events, contentWidth, Math.max(leftPane.length, events.length), THEME, summaryWidth / contentWidth),
        ctx.width,
      ))
    } else {
      lines.push(...centerBlock(summary, ctx.width))
      lines.push("")
      lines.push(...centerBlock(status, ctx.width))
      lines.push("")
      lines.push(...centerBlock(events, ctx.width))
    }

    lines.push("")
    lines.push(centerLine(
      `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}  ` +
        `${THEME.dim}c${THEME.reset}${THEME.muted} cancel${THEME.reset}  ` +
        `${THEME.dim}↑↓${THEME.reset}${THEME.muted} events${THEME.reset}  ` +
        `${THEME.dim}enter${THEME.reset}${THEME.muted} review${THEME.reset}`,
      ctx.width,
    ))

    while (lines.length < ctx.height) {
      lines.push("")
    }

    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const run = getCurrentRun(ctx)

    if (key === "\x1b" || key === "q" || key === "b") {
      ctx.app.setScreen("main")
      return true
    }

    if (!run) {
      return false
    }

    if (key === "c") {
      ctx.app.cancelRun(run.id)
      return true
    }

    if ((key === "\r" || key === " ") && run.result) {
      ctx.app.setScreen("result")
      return true
    }

    if (key === "\x1b[A" || key === "up" || key === "k") {
      ctx.state.runDetailEvents = scrollUp(ctx.state.runDetailEvents)
      ctx.app.render()
      return true
    }

    if (key === "\x1b[B" || key === "down" || key === "j") {
      ctx.state.runDetailEvents = scrollDown(
        ctx.state.runDetailEvents,
        run.events.length,
        eventViewportHeight(ctx.height),
      )
      ctx.app.render()
      return true
    }

    return false
  },
}
