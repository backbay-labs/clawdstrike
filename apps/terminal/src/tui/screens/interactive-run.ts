import { renderBox } from "../components/box"
import { centerBlock, centerLine, wrapText } from "../components/layout"
import { renderSurfaceHeader } from "../components/surface-header"
import { THEME } from "../theme"
import type { RunRecord, Screen, ScreenContext } from "../types"

function getCurrentRun(ctx: ScreenContext): RunRecord | null {
  const { runs, activeRunId } = ctx.state
  const runId = ctx.state.interactiveSession.runId ?? activeRunId ?? runs.selectedRunId
  return runs.entries.find((entry) => entry.id === runId) ?? runs.entries[0] ?? null
}

function renderEmptyState(ctx: ScreenContext): string {
  const lines: string[] = []
  lines.push(...renderSurfaceHeader("interactive-run", "Interactive Run", ctx.width, THEME, "phase 6 scaffold"))
  lines.push("")
  lines.push(...centerBlock(
    renderBox(
      "Interactive Run",
      [
        `${THEME.muted}No interactive run is selected.${THEME.reset}`,
        `${THEME.dim}Phase 6 will mount the embedded PTY surface here.${THEME.reset}`,
      ],
      Math.min(76, ctx.width - 4),
      THEME,
      { style: "rounded", titleAlign: "left", padding: 1 },
    ),
    ctx.width,
  ))

  while (lines.length < ctx.height) {
    lines.push("")
  }

  return lines.join("\n")
}

export const interactiveRunScreen: Screen = {
  render(ctx: ScreenContext): string {
    const run = getCurrentRun(ctx)
    if (!run) {
      return renderEmptyState(ctx)
    }

    const lines: string[] = []
    const session = ctx.state.interactiveSession
    lines.push(
      ...renderSurfaceHeader(
        "interactive-run",
        "Interactive Run",
        ctx.width,
        THEME,
        `${run.agentLabel} • ${session.phase}`,
      ),
    )
    lines.push("")

    const summary = renderBox(
      "Session Scaffold",
      [
        `${THEME.dim}Run:${THEME.reset} ${THEME.white}${run.id}${THEME.reset}`,
        `${THEME.dim}Agent:${THEME.reset} ${THEME.white}${run.agentLabel}${THEME.reset} ${THEME.dim}(${run.agentId})${THEME.reset}`,
        `${THEME.dim}Mode:${THEME.reset} ${THEME.white}${run.mode}${THEME.reset}`,
        `${THEME.dim}Focus:${THEME.reset} ${THEME.white}${session.focus}${THEME.reset}`,
        `${THEME.dim}Interactive phase:${THEME.reset} ${THEME.white}${session.phase}${THEME.reset}`,
        `${THEME.dim}Surface:${THEME.reset} ${THEME.white}${run.interactiveSurface}${THEME.reset}`,
        `${THEME.dim}Session id:${THEME.reset} ${THEME.white}${session.sessionId ?? "pending"}${THEME.reset}`,
        "",
        `${THEME.warning}Phase 6 scaffold only.${THEME.reset} ${THEME.dim}Embedded PTY rendering is not wired yet.${THEME.reset}`,
      ],
      Math.min(88, ctx.width - 6),
      THEME,
      { style: "rounded", titleAlign: "left", padding: 1 },
    )

    const stagedTaskLines = run.prompt.trim()
      ? wrapText(run.prompt.trim(), Math.max(24, Math.min(72, ctx.width - 12)))
      : ["(empty prompt)"]
    const stagedTask = renderBox(
      "Staged Task",
      [
        ...stagedTaskLines.map((line) => `${THEME.white}${line}${THEME.reset}`),
        "",
        `${THEME.dim}Future behavior:${THEME.reset} ${THEME.white}Enter${THEME.reset} ${THEME.dim}send task${THEME.reset}  ${THEME.white}Tab${THEME.reset} ${THEME.dim}edit${THEME.reset}`,
      ],
      Math.min(88, ctx.width - 6),
      THEME,
      { style: "rounded", titleAlign: "left", padding: 1 },
    )

    const plan = renderBox(
      "Planned Surface",
      [
        `${THEME.dim}•${THEME.reset} PTY viewport with bounded scrollback`,
        `${THEME.dim}•${THEME.reset} explicit staged-task bar for blank-prompt agents`,
        `${THEME.dim}•${THEME.reset} ${THEME.white}Ctrl+G${THEME.reset} ${THEME.dim}control overlay for return, review, and escalation${THEME.reset}`,
        `${THEME.dim}•${THEME.reset} reliable return to ${THEME.white}run-detail${THEME.reset} without raw terminal takeover`,
      ],
      Math.min(88, ctx.width - 6),
      THEME,
      { style: "rounded", titleAlign: "left", padding: 1 },
    )

    lines.push(...centerBlock(summary, ctx.width))
    lines.push("")
    lines.push(...centerBlock(stagedTask, ctx.width))
    lines.push("")
    lines.push(...centerBlock(plan, ctx.width))
    lines.push("")
    lines.push(centerLine(
      `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}  ` +
        `${THEME.dim}r${THEME.reset}${THEME.muted} run detail${THEME.reset}`,
      ctx.width,
    ))

    while (lines.length < ctx.height) {
      lines.push("")
    }

    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    if (key === "\x1b" || key === "q" || key === "b" || key === "r") {
      ctx.app.setScreen(ctx.state.activeRunId ? "run-detail" : "main")
      return true
    }

    return false
  },
}
