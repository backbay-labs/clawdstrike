import { renderBox } from "../components/box"
import { centerBlock, centerLine, wrapText } from "../components/layout"
import { renderList, scrollDown, scrollUp, type ListItem, type ListViewport } from "../components/scrollable-list"
import { renderSplit } from "../components/split-pane"
import { renderSurfaceHeader } from "../components/surface-header"
import { THEME } from "../theme"
import type { RunListFilter, RunRecord, Screen, ScreenContext } from "../types"
import {
  filterRuns,
  formatRunPhase,
  getExternalAdapterLabel,
  getRunExternalSurfaceSummary,
  getRunReviewRoute,
  isRunTerminal,
} from "../runs"

const FILTERS: RunListFilter[] = ["active", "review_ready", "all"]

function formatTimestamp(timestamp: string | null): string {
  if (!timestamp) {
    return "pending"
  }

  const date = new Date(timestamp)
  if (Number.isNaN(date.getTime())) {
    return timestamp
  }

  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
  })
}

function nextFilter(filter: RunListFilter): RunListFilter {
  const index = FILTERS.indexOf(filter)
  return FILTERS[(index + 1) % FILTERS.length] ?? "active"
}

function getVisibleRuns(ctx: ScreenContext): RunRecord[] {
  return filterRuns(ctx.state.runs.entries, ctx.state.runs.filter)
}

function syncSelection(ctx: ScreenContext, viewportHeight: number): RunRecord | null {
  const visibleRuns = getVisibleRuns(ctx)
  if (visibleRuns.length === 0) {
    ctx.state.runs.selectedRunId = null
    ctx.state.runs.list = { offset: 0, selected: 0 }
    return null
  }

  const selectedIndex = visibleRuns.findIndex((entry) => entry.id === ctx.state.runs.selectedRunId)
  const nextSelected = selectedIndex >= 0 ? selectedIndex : 0
  const maxOffset = Math.max(0, visibleRuns.length - Math.max(1, viewportHeight))
  let nextOffset = Math.min(ctx.state.runs.list.offset, maxOffset)

  if (nextSelected < nextOffset) {
    nextOffset = nextSelected
  } else if (nextSelected >= nextOffset + viewportHeight) {
    nextOffset = Math.max(0, nextSelected - viewportHeight + 1)
  }

  ctx.state.runs.selectedRunId = visibleRuns[nextSelected]?.id ?? null
  ctx.state.runs.list = { offset: nextOffset, selected: nextSelected }
  return visibleRuns[nextSelected] ?? null
}

function listLabel(run: RunRecord): string {
  const activity = formatTimestamp(run.completedAt ?? run.updatedAt)
  const externalSummary = getRunExternalSurfaceSummary(run)
  return `${run.title}  ${THEME.dim}•${THEME.reset} ${run.agentLabel}  ${THEME.dim}•${THEME.reset} ${formatRunPhase(run.phase)}  ${THEME.dim}•${THEME.reset} ${run.mode}${externalSummary ? ` ${THEME.dim}(${externalSummary})${THEME.reset}` : ""}  ${THEME.dim}•${THEME.reset} ${activity}`
}

function renderRunsList(ctx: ScreenContext, width: number, height: number): string[] {
  const runs = getVisibleRuns(ctx)
  const viewportHeight = Math.max(6, height - 2)
  const selectedRun = syncSelection(ctx, viewportHeight)
  const items: ListItem[] = runs.map((run) => ({
    label: listLabel(run),
    plainLength: run.title.length + run.agentLabel.length + run.phase.length + run.mode.length + 24,
    key: run.id,
  }))
  const lines = renderList(items, ctx.state.runs.list, viewportHeight, Math.max(12, width - 2), THEME)
  const title = `Runs • ${ctx.state.runs.filter.replace("_", " ")}`

  if (!selectedRun && runs.length === 0) {
    return renderBox(
      title,
      [
        `${THEME.muted}No runs match this filter.${THEME.reset}`,
        `${THEME.dim}Launch a managed dispatch from the main surface to populate the backlog.${THEME.reset}`,
      ],
      width,
      THEME,
      { style: "rounded", titleAlign: "left", padding: 1 },
    )
  }

  return renderBox(title, lines, width, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 0,
  })
}

function renderRunSummary(run: RunRecord, width: number): string[] {
  const reviewRoute = getRunReviewRoute(run)
  const lines: string[] = []
  const reviewWithWarnings = Boolean(
    run.execution?.success && run.verification && !run.verification.allPassed && run.verification.criticalPassed,
  )
  const addRow = (label: string, value: string) => {
    lines.push(`${THEME.dim}${label.padEnd(12)}${THEME.reset} ${value}`)
  }

  addRow("Run", `${THEME.white}${run.id}${THEME.reset}`)
  addRow("Agent", `${THEME.white}${run.agentLabel}${THEME.reset} ${THEME.dim}(${run.agentId})${THEME.reset}`)
  addRow("Phase", `${THEME.white}${formatRunPhase(run.phase)}${THEME.reset}`)
  addRow("Mode", `${THEME.white}${run.mode}${THEME.reset}`)
  addRow("Updated", `${THEME.dim}${formatTimestamp(run.updatedAt)}${THEME.reset}`)
  addRow("Completed", `${THEME.dim}${formatTimestamp(run.completedAt)}${THEME.reset}`)
  lines.push("")
  lines.push(`${THEME.secondary}${THEME.bold}Prompt${THEME.reset}`)
  lines.push(...wrapText(run.prompt, Math.max(12, width - 4)).map((line) => `${THEME.white}${line}${THEME.reset}`))

  lines.push("")
  lines.push(`${THEME.secondary}${THEME.bold}Routing${THEME.reset}`)
  if (run.routing) {
    addRow("Toolchain", `${THEME.white}${run.routing.toolchain}${THEME.reset}`)
    addRow("Strategy", `${THEME.dim}${run.routing.strategy}${THEME.reset}`)
    addRow(
      "Gates",
      run.routing.gates.length > 0
        ? `${THEME.dim}${run.routing.gates.join(", ")}${THEME.reset}`
        : `${THEME.muted}none${THEME.reset}`,
    )
  } else {
    lines.push(`${THEME.muted}Routing metadata will appear after launch.${THEME.reset}`)
  }

  lines.push("")
  lines.push(`${THEME.secondary}${THEME.bold}Execution${THEME.reset}`)
  if (run.result) {
    addRow(
      "Outcome",
      reviewWithWarnings
        ? `${THEME.warning}review with warnings${THEME.reset}`
        : run.result.success
          ? `${THEME.success}success${THEME.reset}`
          : `${THEME.error}failed${THEME.reset}`,
    )
    if (run.verification) {
      addRow(
        "Verification",
        run.verification.allPassed
          ? `${THEME.success}${run.verification.score}/100${THEME.reset}`
          : run.verification.criticalPassed
            ? `${THEME.warning}${run.verification.score}/100${THEME.reset}`
            : `${THEME.error}${run.verification.score}/100${THEME.reset}`,
      )
    } else {
      addRow("Verification", `${THEME.muted}not available${THEME.reset}`)
    }
  } else {
    lines.push(`${THEME.muted}Execution is still in progress.${THEME.reset}`)
  }

  if (run.external.adapterId || run.external.status !== "idle") {
    lines.push("")
    lines.push(`${THEME.secondary}${THEME.bold}External Surface${THEME.reset}`)
    addRow("Adapter", `${THEME.white}${getExternalAdapterLabel(run.external.adapterId)}${THEME.reset}`)
    addRow("Status", `${THEME.white}${getRunExternalSurfaceSummary(run) ?? run.external.status}${THEME.reset}`)
    if (run.external.ref) {
      addRow("Surface", `${THEME.dim}${run.external.ref}${THEME.reset}`)
    }
  }

  lines.push("")
  lines.push(`${THEME.secondary}${THEME.bold}Review Guidance${THEME.reset}`)
  if (run.phase === "review_ready" && reviewRoute) {
    lines.push(`${THEME.success}Ready${THEME.reset} open ${THEME.white}${reviewRoute}${THEME.reset} review from this backlog.`)
    if (run.verification?.summary) {
      lines.push(...wrapText(run.verification.summary, Math.max(12, width - 4)).map((line) => `${THEME.dim}${line}${THEME.reset}`))
    }
  } else if (isRunTerminal(run.phase) && reviewRoute) {
    lines.push(`${THEME.dim}Result available via ${reviewRoute}. Review-ready routing is reserved for verified runs.${THEME.reset}`)
  } else if (isRunTerminal(run.phase)) {
    lines.push(`${THEME.muted}No review target was derived for this run.${THEME.reset}`)
  } else {
    lines.push(`${THEME.dim}This run is still active. Open detail to follow logs or cancel from here.${THEME.reset}`)
  }

  lines.push("")
  lines.push(`${THEME.secondary}${THEME.bold}Actions${THEME.reset}`)
  lines.push(`${THEME.dim}Enter${THEME.reset} open detail`)
  lines.push(`${THEME.dim}r${THEME.reset} open review`)
  lines.push(`${THEME.dim}c${THEME.reset} cancel active run`)
  lines.push(`${THEME.dim}f${THEME.reset} cycle filter`)

  return renderBox("Selected Run", lines, width, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

function renderEmptyDetail(width: number): string[] {
  return renderBox(
    "Selected Run",
    [
      `${THEME.muted}No run is selected.${THEME.reset}`,
      `${THEME.dim}Change the filter or launch a managed run from the main surface.${THEME.reset}`,
    ],
    width,
    THEME,
    { style: "rounded", titleAlign: "left", padding: 1 },
  )
}

function moveSelection(ctx: ScreenContext, direction: "up" | "down", viewportHeight: number): void {
  const visibleRuns = getVisibleRuns(ctx)
  if (visibleRuns.length === 0) {
    ctx.state.runs.list = { offset: 0, selected: 0 }
    ctx.state.runs.selectedRunId = null
    return
  }

  syncSelection(ctx, viewportHeight)
  const current = ctx.state.runs.list
  const nextViewport: ListViewport =
    direction === "up"
      ? scrollUp(current)
      : scrollDown(current, visibleRuns.length, viewportHeight)
  ctx.state.runs.list = nextViewport
  ctx.state.runs.selectedRunId = visibleRuns[nextViewport.selected]?.id ?? visibleRuns[0]?.id ?? null
}

export const runsScreen: Screen = {
  onEnter(ctx: ScreenContext): void {
    syncSelection(ctx, Math.max(6, ctx.height - 8))
  },

  render(ctx: ScreenContext): string {
    const lines: string[] = []
    const contentWidth = Math.max(40, ctx.width - 4)
    const leftWidth = contentWidth >= 112 ? Math.max(42, Math.floor((contentWidth - 1) * 0.48)) : contentWidth
    const rightWidth = contentWidth >= 112 ? contentWidth - leftWidth - 1 : contentWidth
    const viewportHeight = Math.max(6, ctx.height - 8)
    const selectedRun = syncSelection(ctx, viewportHeight)

    lines.push(
      ...renderSurfaceHeader(
        "runs",
        "Managed Runs",
        ctx.width,
        THEME,
        `${ctx.state.runs.filter.replace("_", " ")} • ${getVisibleRuns(ctx).length} visible`,
      ),
    )

    const listPane = renderRunsList(ctx, leftWidth, viewportHeight + 2)
    const detailPane = selectedRun ? renderRunSummary(selectedRun, rightWidth) : renderEmptyDetail(rightWidth)

    if (contentWidth >= 112) {
      lines.push(...centerBlock(
        renderSplit(listPane, detailPane, contentWidth, Math.max(listPane.length, detailPane.length), THEME, leftWidth / contentWidth),
        ctx.width,
      ))
    } else {
      lines.push(...centerBlock(listPane, ctx.width))
      lines.push("")
      lines.push(...centerBlock(detailPane, ctx.width))
    }

    lines.push("")
    lines.push(centerLine(
      `${THEME.dim}↑↓${THEME.reset}${THEME.muted} browse${THEME.reset}  ` +
        `${THEME.dim}enter${THEME.reset}${THEME.muted} detail${THEME.reset}  ` +
        `${THEME.dim}r${THEME.reset}${THEME.muted} review${THEME.reset}  ` +
        `${THEME.dim}c${THEME.reset}${THEME.muted} cancel${THEME.reset}  ` +
        `${THEME.dim}f${THEME.reset}${THEME.muted} filter${THEME.reset}  ` +
        `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`,
      ctx.width,
    ))

    while (lines.length < ctx.height) {
      lines.push("")
    }

    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const viewportHeight = Math.max(6, ctx.height - 8)
    const selectedRun = syncSelection(ctx, viewportHeight)

    if (key === "\x1b" || key === "q" || key === "b") {
      ctx.app.setScreen("main")
      return true
    }

    if (key === "f") {
      ctx.state.runs.filter = nextFilter(ctx.state.runs.filter)
      ctx.state.runs.list = { offset: 0, selected: 0 }
      syncSelection(ctx, viewportHeight)
      ctx.app.render()
      return true
    }

    if (key === "\x1b[A" || key === "k" || key === "up") {
      moveSelection(ctx, "up", viewportHeight)
      ctx.app.render()
      return true
    }

    if (key === "\x1b[B" || key === "j" || key === "down") {
      moveSelection(ctx, "down", viewportHeight)
      ctx.app.render()
      return true
    }

    if (!selectedRun) {
      return false
    }

    if (key === "c" && !isRunTerminal(selectedRun.phase)) {
      ctx.app.cancelRun(selectedRun.id)
      return true
    }

    if ((key === "\r" || key === " ") && selectedRun) {
      ctx.app.openRun(selectedRun.id)
      return true
    }

    if (key === "r" && selectedRun.phase === "review_ready" && selectedRun.result) {
      ctx.state.activeRunId = selectedRun.id
      ctx.state.runs.selectedRunId = selectedRun.id
      ctx.state.lastResult = selectedRun.result
      ctx.app.setScreen("result")
      return true
    }

    return false
  },
}
