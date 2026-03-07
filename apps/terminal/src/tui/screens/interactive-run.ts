import { renderBox } from "../components/box"
import { fitString } from "../components/types"
import { centerBlock, centerLine, wrapText } from "../components/layout"
import { renderSplit } from "../components/split-pane"
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
  lines.push(...renderSurfaceHeader("interactive-run", "Interactive Run", ctx.width, THEME, "idle"))
  lines.push("")
  lines.push(...centerBlock(
    renderBox(
      "Interactive Run",
      [
        `${THEME.muted}No interactive run is selected.${THEME.reset}`,
        `${THEME.dim}Open an attach-mode dispatch to populate this surface.${THEME.reset}`,
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

function renderRail(run: RunRecord, ctx: ScreenContext, width: number): string[] {
  const session = ctx.state.interactiveSession
  const content: string[] = [
    `${THEME.dim}Run:${THEME.reset} ${THEME.white}${run.id}${THEME.reset}`,
    `${THEME.dim}Agent:${THEME.reset} ${THEME.white}${run.agentLabel}${THEME.reset} ${THEME.dim}(${run.agentId})${THEME.reset}`,
    `${THEME.dim}Mode:${THEME.reset} ${THEME.white}${run.mode}${THEME.reset}`,
    `${THEME.dim}Phase:${THEME.reset} ${THEME.white}${session.phase}${THEME.reset}`,
    `${THEME.dim}Focus:${THEME.reset} ${THEME.white}${session.focus}${THEME.reset}`,
    `${THEME.dim}Session:${THEME.reset} ${THEME.white}${session.sessionId ?? "pending"}${THEME.reset}`,
  ]

  if (run.worktreePath) {
    content.push(`${THEME.dim}Worktree:${THEME.reset}`)
    content.push(`${THEME.dim}${fitString(run.worktreePath, Math.max(12, width - 4))}${THEME.reset}`)
  }

  if (session.lastOutputAt) {
    content.push(`${THEME.dim}Output:${THEME.reset} ${THEME.white}${new Date(session.lastOutputAt).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}${THEME.reset}`)
  }

  if (session.error) {
    content.push("")
    content.push(`${THEME.error}${session.error}${THEME.reset}`)
  }

  return renderBox("Session Rail", content, width, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
}

function renderStagedTask(run: RunRecord, ctx: ScreenContext, width: number): string[] {
  const session = ctx.state.interactiveSession
  const title =
    session.focus === "staged_task"
      ? `${THEME.secondary}${THEME.bold}Staged Task • focused${THEME.reset}`
      : `${THEME.secondary}${THEME.bold}Staged Task${THEME.reset}`
  const body: string[] = [title]

  if (session.launchConsumesPrompt && session.stagedTask.sent) {
    body.push(`${THEME.success}Prompt preloaded at launch.${THEME.reset}`)
    body.push(`${THEME.dim}${run.agentLabel} already consumed the staged task when the session opened.${THEME.reset}`)
  } else {
    const taskLines = wrapText(session.stagedTask.text || "(empty prompt)", Math.max(16, width - 4))
    body.push(...taskLines.map((line) => `${THEME.white}${line}${THEME.reset}`))
    body.push("")
    if (session.stagedTask.sent) {
      body.push(`${THEME.success}Task sent to the session.${THEME.reset} ${THEME.dim}Use Ctrl+G for ClawdStrike controls.${THEME.reset}`)
      if (session.toolchain === "claude") {
        body.push(`${THEME.dim}Claude interactive responses can take a few seconds before the first visible line appears.${THEME.reset}`)
      }
    } else if (session.focus === "staged_task") {
      body.push(`${THEME.white}Enter${THEME.reset} ${THEME.dim}send task${THEME.reset}  ${THEME.white}Tab${THEME.reset} ${THEME.dim}focus PTY${THEME.reset}`)
    } else {
      body.push(`${THEME.dim}Return focus here to edit or send the staged task.${THEME.reset}`)
    }
  }

  return renderBox("Task Bar", body, width, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
    borderColor: session.focus === "staged_task" ? THEME.secondary : THEME.dim,
  })
}

function isDecorativeTranscriptLine(line: string): boolean {
  const normalized = line.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, "").trim()
  if (normalized.length === 0) {
    return true
  }
  return !/[\p{L}\p{N}]/u.test(normalized)
}

function isLocalSessionEcho(line: string, stagedTask: string): boolean {
  const normalized = line.trim()
  if (!normalized) {
    return true
  }
  if (normalized.startsWith("› staged task sent:")) {
    return true
  }
  const trimmedTask = stagedTask.trim()
  if (!trimmedTask) {
    return false
  }
  if (normalized === trimmedTask) {
    return true
  }
  return normalized.replace(/^[>❯•*\s]+/u, "").trim() === trimmedTask
}

function renderViewport(run: RunRecord, ctx: ScreenContext, width: number, height: number): string[] {
  const session = ctx.state.interactiveSession
  const focusLabel =
    session.focus === "pty"
      ? `${THEME.secondary}${THEME.bold}PTY • focused${THEME.reset}`
      : `${THEME.secondary}${THEME.bold}PTY View${THEME.reset}`
  const body: string[] = [focusLabel]
  const viewportHeight = Math.max(6, height - 4)
  const scrollback = session.scrollback
  const offset = session.viewport.scrollOffset
  const start = Math.max(0, scrollback.length - viewportHeight - offset)
  const end = Math.max(start, scrollback.length - offset)
  const lines = scrollback.slice(start, end)
  const stableTranscriptLines = lines.filter((line) => !isLocalSessionEcho(line, session.stagedTask.text))
  const activityLines = session.activityLines.filter((line) => !isLocalSessionEcho(line, session.stagedTask.text))

  if (
    lines.length === 0 ||
    stableTranscriptLines.length === 0 ||
    stableTranscriptLines.every(isDecorativeTranscriptLine)
  ) {
    body.push(`${THEME.dim}Waiting for interactive output…${THEME.reset}`)
    if (session.stagedTask.sent) {
      body.push(`${THEME.dim}${run.agentLabel} is processing the staged task now.${THEME.reset}`)
      body.push(`${THEME.dim}The first visible response can take a few seconds in interactive mode.${THEME.reset}`)
    } else {
      body.push(`${THEME.dim}The session is open. Send the staged task or type directly into the PTY.${THEME.reset}`)
    }
    if (activityLines.length > 0) {
      body.push("")
      body.push(`${THEME.secondary}${THEME.bold}Recent Activity${THEME.reset}`)
      body.push(...activityLines.slice(-4).map((line) => `${THEME.dim}• ${fitString(line, Math.max(12, width - 8))}${THEME.reset}`))
    }
  } else {
    body.push(...lines.map((line) => fitString(line, Math.max(12, width - 4))))
  }

  while (body.length < viewportHeight + 1) {
    body.push("")
  }

  if (offset > 0) {
    body.push(`${THEME.warning}Scrollback paused${THEME.reset} ${THEME.dim}PgDn to follow live output.${THEME.reset}`)
  } else if (session.focus === "pty") {
    body.push(`${THEME.dim}Typing goes directly to the interactive session.${THEME.reset}`)
  } else {
    body.push(`${THEME.dim}Press Ctrl+G for ClawdStrike controls.${THEME.reset}`)
  }

  return renderBox("Transcript", body, width, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
    borderColor: session.focus === "pty" ? THEME.secondary : THEME.dim,
  })
}

function overlayControls(baseScreen: string, ctx: ScreenContext): string {
  const lines = baseScreen.split("\n")
  const session = ctx.state.interactiveSession
  const body = [
    `${THEME.white}p${THEME.reset} ${THEME.dim}return to PTY${THEME.reset}`,
    `${THEME.white}t${THEME.reset} ${THEME.dim}focus staged task${THEME.reset}`,
    `${THEME.white}x${THEME.reset} ${THEME.dim}back to run detail${THEME.reset}`,
    `${THEME.white}c${THEME.reset} ${THEME.dim}cancel interactive session${THEME.reset}`,
    `${THEME.white}Esc${THEME.reset} ${THEME.dim}close controls${THEME.reset}`,
    "",
    `${THEME.dim}Current focus:${THEME.reset} ${THEME.white}${session.returnFocus}${THEME.reset}`,
  ]

  const overlay = centerBlock(
    renderBox("ClawdStrike Controls", body, Math.max(44, Math.min(64, ctx.width - 16)), THEME, {
      style: "rounded",
      titleAlign: "left",
      padding: 1,
      borderColor: THEME.secondary,
    }),
    ctx.width,
  )

  for (let i = 0; i < overlay.length; i++) {
    const lineIndex = Math.max(3, Math.floor((lines.length - overlay.length) / 2) + i)
    if (lineIndex < lines.length) {
      lines[lineIndex] = overlay[i]
    }
  }

  return lines.join("\n")
}

function renderFooter(ctx: ScreenContext): string {
  const session = ctx.state.interactiveSession
  if (session.focus === "controls") {
    return centerLine(
      `${THEME.dim}p${THEME.reset}${THEME.muted} PTY${THEME.reset}  ` +
        `${THEME.dim}t${THEME.reset}${THEME.muted} task${THEME.reset}  ` +
        `${THEME.dim}x${THEME.reset}${THEME.muted} detail${THEME.reset}  ` +
        `${THEME.dim}c${THEME.reset}${THEME.muted} cancel${THEME.reset}  ` +
        `${THEME.dim}Esc${THEME.reset}${THEME.muted} close${THEME.reset}`,
      ctx.width,
    )
  }

  return centerLine(
    `${THEME.dim}Ctrl+G${THEME.reset}${THEME.muted} controls${THEME.reset}  ` +
      `${THEME.dim}PgUp/PgDn${THEME.reset}${THEME.muted} scroll${THEME.reset}  ` +
      `${THEME.dim}${session.focus === "staged_task" ? "Enter" : "typing"}${THEME.reset}${THEME.muted} ${session.focus === "staged_task" ? "send task" : "to PTY"}${THEME.reset}`,
    ctx.width,
  )
}

function printableTextChunk(key: string): string | null {
  if (!key || key.includes("\x1b")) {
    return null
  }
  const text = [...key].filter((ch) => ch >= " " && ch !== "\x7f").join("")
  return text.length > 0 ? text : null
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

    const contentWidth = Math.max(40, ctx.width - 4)
    const railWidth = contentWidth >= 104 ? Math.max(34, Math.floor((contentWidth - 1) * 0.34)) : contentWidth
    const viewWidth = contentWidth >= 104 ? contentWidth - railWidth - 1 : contentWidth

    const rail = [...renderRail(run, ctx, railWidth), "", ...renderStagedTask(run, ctx, railWidth)]
    const view = renderViewport(run, ctx, viewWidth, Math.max(16, ctx.height - 8))

    if (contentWidth >= 104) {
      lines.push(...centerBlock(
        renderSplit(rail, view, contentWidth, Math.max(rail.length, view.length), THEME, railWidth / contentWidth),
        ctx.width,
      ))
    } else {
      lines.push(...centerBlock(rail, ctx.width))
      lines.push("")
      lines.push(...centerBlock(view, ctx.width))
    }

    lines.push("")
    lines.push(renderFooter(ctx))

    while (lines.length < ctx.height) {
      lines.push("")
    }

    const rendered = lines.join("\n")
    return session.focus === "controls" ? overlayControls(rendered, ctx) : rendered
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const session = ctx.state.interactiveSession

    if (key === "\x07") {
      ctx.app.interactiveToggleControls?.()
      return true
    }

    if (session.focus === "controls") {
      if (key === "\x1b" || key === "q" || key === "\x07") {
        ctx.app.interactiveToggleControls?.()
        return true
      }
      if (key === "p") {
        ctx.app.interactiveSetFocus?.("pty")
        return true
      }
      if (key === "t") {
        ctx.app.interactiveSetFocus?.("staged_task")
        return true
      }
      if (key === "x" || key === "r") {
        if (ctx.app.interactiveReturnToRunDetail) {
          ctx.app.interactiveReturnToRunDetail()
        } else {
          ctx.app.setScreen("run-detail")
        }
        return true
      }
      if (key === "c") {
        ctx.app.interactiveCancelSession?.()
        return true
      }
      return true
    }

    if (session.focus === "staged_task") {
      if (key === "\x1b") {
        if (ctx.app.interactiveReturnToRunDetail) {
          ctx.app.interactiveReturnToRunDetail()
        } else {
          ctx.app.setScreen("run-detail")
        }
        return true
      }
      if (key === "\t") {
        ctx.app.interactiveSetFocus?.("pty")
        return true
      }
      if (key === "\r") {
        ctx.app.interactiveSendStagedTask?.()
        return true
      }
      if ((key === "\x7f" || key === "\b") && session.stagedTask.editable) {
        ctx.app.interactiveUpdateStagedTask?.(session.stagedTask.text.slice(0, -1))
        return true
      }
      const stagedChunk = session.stagedTask.editable ? printableTextChunk(key) : null
      if (stagedChunk) {
        ctx.app.interactiveUpdateStagedTask?.(`${session.stagedTask.text}${stagedChunk}`)
        return true
      }
      return true
    }

    if (key === "\x1b[5~") {
      ctx.app.interactiveScrollViewport?.(5)
      return true
    }
    if (key === "\x1b[6~") {
      ctx.app.interactiveScrollViewport?.(-5)
      return true
    }

    if (key === "\x1b") {
      ctx.app.interactiveSendInput?.(key)
      return true
    }

    ctx.app.interactiveSendInput?.(key)
    return true
  },
}
