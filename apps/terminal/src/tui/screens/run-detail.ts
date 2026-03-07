import { renderBox } from "../components/box"
import { centerBlock, centerLine, wrapText } from "../components/layout"
import { renderList, scrollDown, scrollUp } from "../components/scrollable-list"
import { renderSplit } from "../components/split-pane"
import { renderSurfaceHeader } from "../components/surface-header"
import { THEME } from "../theme"
import type { RunEvent, RunRecord, Screen, ScreenContext } from "../types"
import { getExternalAdapter } from "../external/registry"
import {
  canRunAttach,
  canRelaunchRunInMode,
  canRunExternal,
  formatRunPhase,
  getExternalAdapterLabel,
  getRunAttachDisabledReason,
  getRunExternalDisabledReason,
  getRunExternalSurfaceSummary,
  getRunReviewRoute,
  isRunTerminal,
  isRunReviewReady,
} from "../runs"

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
  const verificationWarningOnly = Boolean(
    run.execution?.success && run.verification && !run.verification.allPassed && run.verification.criticalPassed,
  )
  const currentExternalAdapter = run.external.adapterId
    ? getExternalAdapter(run.external.adapterId)
    : null
  const externalSummary = getRunExternalSurfaceSummary(run)

  if (!run.result) {
    content.push(`${THEME.muted}Waiting for execution result…${THEME.reset}`)
  } else {
    addRow(
      "Outcome",
      verificationWarningOnly
        ? `${THEME.warning}review with warnings${THEME.reset}`
        : run.result.success
          ? `${THEME.success}success${THEME.reset}`
          : `${THEME.error}failed${THEME.reset}`,
    )
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
          : run.verification.criticalPassed
            ? `${THEME.warning}${run.verification.score}/100${THEME.reset}`
            : `${THEME.error}${run.verification.score}/100${THEME.reset}`,
      )
      if (run.verification.summary) {
        content.push(...wrapText(run.verification.summary, Math.max(12, width - 4)).map((line) => `${THEME.dim}${line}${THEME.reset}`))
      }
      for (const gate of run.verification.results) {
        const icon = gate.passed ? `${THEME.success}✓${THEME.reset}` : `${THEME.error}✗${THEME.reset}`
        addRow("", `${icon} ${gate.gate}`)
      }
    }

    const reviewRoute = getRunReviewRoute(run)
    if (reviewRoute) {
      content.push("")
      content.push(`${THEME.secondary}${THEME.bold}Review${THEME.reset}`)
      content.push(
        isRunReviewReady(run)
          ? `${THEME.success}Ready${THEME.reset} open ${THEME.white}${reviewRoute}${THEME.reset} review from detail or the runs backlog.`
          : `${THEME.dim}Review target:${THEME.reset} ${THEME.white}${reviewRoute}${THEME.reset}`,
      )
    }

    if (run.error) {
      content.push("")
      content.push(`${THEME.secondary}${THEME.bold}Failure${THEME.reset}`)
      content.push(...wrapText(run.error, Math.max(12, width - 4)).map((line) => `${THEME.error}${line}${THEME.reset}`))
    }
  }

  content.push("")
  content.push(`${THEME.secondary}${THEME.bold}Attach${THEME.reset}`)
  if (run.interactiveSurface === "embedded" && run.interactiveSessionId && !isRunTerminal(run.phase)) {
    content.push(`${THEME.success}Ready${THEME.reset} reopen this embedded interactive surface from the detail footer.`)
  } else if (canRunAttach(run)) {
    content.push(`${THEME.success}Ready${THEME.reset} hand the terminal to this run from the detail footer.`)
  } else if (canRelaunchRunInMode(run, "attach")) {
    content.push(`${THEME.success}Ready${THEME.reset} relaunch this prompt in attach mode from the detail footer.`)
  } else {
    content.push(`${THEME.dim}${getRunAttachDisabledReason(run) ?? "Attach is not available for this run."}${THEME.reset}`)
  }
  if (run.ptySessionId) {
    addRow("Session", `${THEME.dim}${run.ptySessionId}${THEME.reset}`)
  }
  addRow("State", `${THEME.white}${run.attachState}${THEME.reset}`)

  content.push("")
  content.push(`${THEME.secondary}${THEME.bold}External${THEME.reset}`)
  if (run.external.status === "running" && run.external.ref && currentExternalAdapter?.focus) {
    content.push(
      `${THEME.success}Ready${THEME.reset} reopen this live ${currentExternalAdapter.label} surface from the detail footer.`,
    )
  } else if (run.external.status === "running") {
    content.push(
      `${THEME.dim}${currentExternalAdapter?.label ?? "External adapter"} is already running. Reopen is not available for this adapter yet.${THEME.reset}`,
    )
  } else if (run.external.status === "failed" && !run.result) {
    content.push(
      `${THEME.warning}Recoverable${THEME.reset} retry external launch or fall back to managed or attach from the overlay.`,
    )
  } else if (canRelaunchRunInMode(run, "external")) {
    content.push(`${THEME.success}Ready${THEME.reset} relaunch this prompt in external mode from the detail footer.`)
  } else if (canRunExternal(run)) {
    content.push(`${THEME.success}Ready${THEME.reset} open this run in an external terminal adapter.`)
  } else {
    content.push(`${THEME.dim}${getRunExternalDisabledReason(run) ?? "External execution is not available for this run."}${THEME.reset}`)
  }
  addRow("Adapter", `${THEME.white}${getExternalAdapterLabel(run.external.adapterId)}${THEME.reset}`)
  addRow("Status", `${THEME.white}${externalSummary ?? run.external.status}${THEME.reset}`)
  if (run.external.ref) {
    addRow("Surface", `${THEME.dim}${run.external.ref}${THEME.reset}`)
  }
  if (run.external.error) {
    content.push(...wrapText(run.external.error, Math.max(12, width - 4)).map((line) => `${THEME.error}${line}${THEME.reset}`))
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

function overlayAttachBanner(baseScreen: string, ctx: ScreenContext, run: RunRecord): string {
  const lines = baseScreen.split("\n")
  const instruction =
    run.agentId === "claude"
      ? `${THEME.dim}Claude will open in the embedded interactive surface with a staged task bar.${THEME.reset}`
      : `${THEME.dim}This run will open in the interactive attach flow.${THEME.reset}`
  const overlay = centerBlock(
    renderBox(
      "Attach To Run",
      [
        `${THEME.dim}Run:${THEME.reset} ${THEME.white}${run.id}${THEME.reset} ${THEME.dim}${run.title}${THEME.reset}`,
        `${THEME.dim}Mode:${THEME.reset} ${THEME.white}${run.mode}${THEME.reset} ${THEME.dim}-> attach${THEME.reset}`,
        `${THEME.dim}Surface:${THEME.reset} ${THEME.white}interactive-run${THEME.reset}`,
        "",
        instruction,
        "",
        `${THEME.white}Enter${THEME.reset} ${THEME.dim}open${THEME.reset}  ${THEME.white}Esc${THEME.reset} ${THEME.dim}cancel${THEME.reset}`,
      ],
      Math.max(56, Math.min(82, ctx.width - 12)),
      THEME,
      { style: "rounded", titleAlign: "left", padding: 1 },
    ),
    ctx.width,
  )

  for (let i = 0; i < overlay.length; i++) {
    const lineIndex = 6 + i
    if (lineIndex < lines.length) {
      lines[lineIndex] = overlay[i]
    }
  }

  return lines.join("\n")
}

function overlayExternalSheet(baseScreen: string, ctx: ScreenContext, run: RunRecord): string {
  const lines = baseScreen.split("\n")
  const sheetWidth = Math.max(58, Math.min(86, ctx.width - 12))
  const sheet = ctx.state.externalSheet
  const body: string[] = [
    `${THEME.dim}Run:${THEME.reset} ${THEME.white}${run.id}${THEME.reset} ${THEME.dim}${run.title}${THEME.reset}`,
    "",
  ]

  if (sheet.loading) {
    body.push(`${THEME.accent}⠋${THEME.reset} ${THEME.dim}Checking available adapters…${THEME.reset}`)
  } else if (sheet.adapters.length === 0) {
    body.push(`${THEME.warning}!${THEME.reset} ${THEME.dim}No supported adapters are ready.${THEME.reset}`)
  } else {
    body.push(`${THEME.secondary}${THEME.bold}Adapters${THEME.reset}`)
    for (const [index, adapter] of sheet.adapters.entries()) {
      const marker = index === sheet.selectedIndex ? `${THEME.accent}${THEME.bold}▸${THEME.reset}` : `${THEME.dim}•${THEME.reset}`
      body.push(`${marker} ${THEME.white}${adapter.label}${THEME.reset} ${THEME.dim}(${adapter.id})${THEME.reset}`)
      body.push(`  ${THEME.dim}${adapter.description}${THEME.reset}`)
    }
  }

  if (sheet.error) {
    body.push("")
    body.push(`${THEME.error}${sheet.error}${THEME.reset}`)
  }

  body.push("")
  body.push(
    `${THEME.white}Enter${THEME.reset} ${THEME.dim}open${THEME.reset}  ` +
      `${THEME.white}↑/↓${THEME.reset} ${THEME.dim}select${THEME.reset}  ` +
      `${THEME.white}m${THEME.reset} ${THEME.dim}managed fallback${THEME.reset}  ` +
      `${THEME.white}a${THEME.reset} ${THEME.dim}attach fallback${THEME.reset}  ` +
      `${THEME.white}Esc${THEME.reset} ${THEME.dim}cancel${THEME.reset}`,
  )

  const overlay = centerBlock(
    renderBox("Open External Execution", body, sheetWidth, THEME, {
      style: "rounded",
      titleAlign: "left",
      padding: 1,
    }),
    ctx.width,
  )

  for (let i = 0; i < overlay.length; i++) {
    const lineIndex = 6 + i
    if (lineIndex < lines.length) {
      lines[lineIndex] = overlay[i]
    }
  }

  return lines.join("\n")
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
    const currentExternalAdapter = run.external.adapterId
      ? getExternalAdapter(run.external.adapterId)
      : null
    const hasEmbeddedInteractive = run.interactiveSurface === "embedded" && run.interactiveSessionId && !isRunTerminal(run.phase)
    const externalActionLabel =
      run.external.status === "running" && run.external.ref && currentExternalAdapter?.focus
        ? "reopen"
        : run.external.status === "failed" && !run.result
          ? "retry"
          : canRelaunchRunInMode(run, "external")
            ? "relaunch"
          : "external"
    const attachActionLabel = hasEmbeddedInteractive ? "resume" : canRelaunchRunInMode(run, "attach") ? "relaunch" : "attach"
    lines.push(centerLine(
      `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}  ` +
        `${THEME.dim}r${THEME.reset}${THEME.muted} runs${THEME.reset}  ` +
        `${THEME.dim}a${THEME.reset}${THEME.muted} ${attachActionLabel}${THEME.reset}  ` +
        `${THEME.dim}o${THEME.reset}${THEME.muted} ${externalActionLabel}${THEME.reset}  ` +
        `${THEME.dim}c${THEME.reset}${THEME.muted} cancel${THEME.reset}  ` +
        `${THEME.dim}↑↓${THEME.reset}${THEME.muted} events${THEME.reset}  ` +
        `${THEME.dim}enter${THEME.reset}${THEME.muted} ${isRunReviewReady(run) ? "review" : "result"}${THEME.reset}`,
      ctx.width,
    ))

    while (lines.length < ctx.height) {
      lines.push("")
    }

    const rendered = lines.join("\n")
    if (ctx.state.pendingAttachRunId === run.id) {
      return overlayAttachBanner(rendered, ctx, run)
    }
    if (ctx.state.externalSheet.runId === run.id) {
      return overlayExternalSheet(rendered, ctx, run)
    }

    return rendered
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const run = getCurrentRun(ctx)

    if (run && ctx.state.pendingAttachRunId === run.id) {
      if (key === "\r") {
        ctx.app.confirmAttachRun()
        return true
      }

      if (key === "\x1b" || key === "q") {
        ctx.app.cancelAttachRun()
        return true
      }
    }

    if (run && ctx.state.externalSheet.runId === run.id) {
      if (key === "\r") {
        ctx.app.confirmExternalRun()
        return true
      }

      if (key === "\x1b" || key === "q") {
        ctx.app.cancelExternalRun()
        return true
      }

      if (key === "\x1b[A" || key === "up" || key === "k") {
        if (ctx.state.externalSheet.adapters.length > 0) {
          const count = ctx.state.externalSheet.adapters.length
          ctx.state.externalSheet.selectedIndex = (ctx.state.externalSheet.selectedIndex + count - 1) % count
          ctx.app.render()
        }
        return true
      }

      if (key === "\x1b[B" || key === "down" || key === "j") {
        if (ctx.state.externalSheet.adapters.length > 0) {
          const count = ctx.state.externalSheet.adapters.length
          ctx.state.externalSheet.selectedIndex = (ctx.state.externalSheet.selectedIndex + 1) % count
          ctx.app.render()
        }
        return true
      }

      if (key === "m") {
        ctx.app.launchRunInMode(run.id, "managed")
        return true
      }

      if (key === "a") {
        ctx.app.launchRunInMode(run.id, "attach")
        return true
      }
    }

    if (key === "\x1b" || key === "q" || key === "b") {
      ctx.app.setScreen("main")
      return true
    }

    if (key === "r") {
      ctx.app.showRuns()
      return true
    }

    if (!run) {
      return false
    }

    if (key === "c") {
      ctx.app.cancelRun(run.id)
      return true
    }

    if (key === "a") {
      if (run.interactiveSurface === "embedded" && run.interactiveSessionId && !isRunTerminal(run.phase)) {
        ctx.app.setScreen("interactive-run")
        return true
      }
      if (canRelaunchRunInMode(run, "attach")) {
        ctx.app.relaunchRunInMode(run.id, "attach")
        return true
      }
      ctx.app.beginAttachRun(run.id)
      return true
    }

    if (key === "o") {
      if (canRelaunchRunInMode(run, "external")) {
        ctx.app.relaunchRunInMode(run.id, "external")
        return true
      }
      ctx.app.beginExternalRun(run.id)
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
