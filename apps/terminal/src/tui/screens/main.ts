/**
 * Main Screen - Hero input + command palette overlay
 */

import { THEME, LOGO, AGENTS, getAnimatedStrike } from "../theme"
import type { Screen, ScreenContext, Command, HomeFocus } from "../types"
import { renderBox } from "../components/box"
import { centerBlock, centerLine, joinColumns, wrapText } from "../components/layout"
import { fitString } from "../components/types"
import { getInvestigationCounts, isInvestigationStale } from "../investigation"
import type { AppState } from "../types"
import { asCheckEventData, eventDecision, type DaemonEvent } from "../../hushd"

const STREAM_STALE_MS = 5 * 60_000
const HOME_ACTION_COLUMNS = 2
const HOME_ACTION_SELECTED_BG = "\x1b[48;5;52m"
const BOX_TRACE_FRAMES = 8

interface HomeAction {
  key: string
  label: string
  description: string
  action: (ctx: ScreenContext) => void
}

function formatAge(ms: number): string {
  if (ms < 60_000) {
    return `${Math.max(1, Math.floor(ms / 1000))}s`
  }
  if (ms < 3_600_000) {
    return `${Math.floor(ms / 60_000)}m`
  }
  return `${Math.floor(ms / 3_600_000)}h`
}

function truncateMiddle(value: string, maxLength: number): string {
  if (value.length <= maxLength) {
    return value
  }

  const head = Math.max(4, Math.floor((maxLength - 1) / 2))
  const tail = Math.max(4, maxLength - head - 1)
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

function flattenHealth(state: AppState) {
  return state.health
    ? [...state.health.security, ...state.health.ai, ...state.health.infra, ...state.health.mcp]
    : []
}

function renderHealthStatus(state: AppState): string {
  if (state.healthChecking) {
    return `${THEME.secondary}checking${THEME.reset}`
  }

  const items = flattenHealth(state)
  if (items.length === 0) {
    return `${THEME.dim}unknown${THEME.reset}`
  }

  const unavailable = items.filter((item) => !item.available)
  if (unavailable.length === 0) {
    return `${THEME.success}healthy${THEME.reset} ${THEME.dim}${items.length}/${items.length} up${THEME.reset}`
  }

  return `${THEME.warning}degraded${THEME.reset} ${THEME.dim}${unavailable.length}/${items.length} down${THEME.reset}`
}

function renderStreamStatus(state: AppState, now = Date.now()): string {
  if (state.hushdStatus === "connecting") {
    return `${THEME.warning}connecting${THEME.reset}`
  }

  if (state.hushdStatus === "unauthorized") {
    return `${THEME.error}unauthorized${THEME.reset}`
  }

  if (state.hushdStatus === "degraded") {
    return `${THEME.warning}degraded${THEME.reset}`
  }

  if (state.hushdStatus === "disconnected" || state.hushdStatus === "error") {
    return `${THEME.dim}offline${THEME.reset}`
  }

  const latestTimestamp = state.hushdLastEventAt ?? state.recentEvents[0]?.timestamp
  if (!latestTimestamp) {
    return `${THEME.muted}idle${THEME.reset} ${THEME.dim}no recent events${THEME.reset}`
  }

  const timestamp = new Date(latestTimestamp).getTime()
  if (Number.isNaN(timestamp)) {
    return `${THEME.success}live${THEME.reset}`
  }

  const age = Math.max(0, now - timestamp)
  if (state.hushdStatus === "stale" || age > STREAM_STALE_MS) {
    return `${THEME.warning}stale${THEME.reset} ${THEME.dim}${formatAge(age)} since last event${THEME.reset}`
  }

  return `${THEME.success}live${THEME.reset} ${THEME.dim}${formatAge(age)} ago${THEME.reset}`
}

function findLastDeniedEvent(state: AppState): DaemonEvent | null {
  return state.recentEvents.find((event) => eventDecision(event) === "deny") ?? null
}

function renderLastDenied(state: AppState): string | null {
  const event = findLastDeniedEvent(state)
  if (!event) {
    return null
  }

  const data = asCheckEventData(event)
  if (!data) {
    return null
  }
  const target = truncateMiddle(data.target, 42)
  return `${THEME.error}${data.action_type}${THEME.reset} ${THEME.white}${target}${THEME.reset} ${THEME.dim}via ${data.guard ?? "stream"}${THEME.reset}`
}

const HOME_ACTIONS: HomeAction[] = [
  { key: "S", label: "Security", description: "overview", action: (ctx) => ctx.app.setScreen("security") },
  { key: "A", label: "Audit", description: "event log", action: (ctx) => ctx.app.setScreen("audit") },
  { key: "P", label: "Policy", description: "active rules", action: (ctx) => ctx.app.setScreen("policy") },
  { key: "I", label: "Integrations", description: "runtime status", action: (ctx) => ctx.app.setScreen("integrations") },
  { key: "R", label: "Runs", description: "managed backlog", action: (ctx) => ctx.app.showRuns() },
  { key: "W", label: "Watch", description: "live stream", action: (ctx) => ctx.app.setScreen("hunt-watch") },
  { key: "X", label: "Scan", description: "MCP exposure", action: (ctx) => ctx.app.setScreen("hunt-scan") },
  { key: "T", label: "Timeline", description: "event replay", action: (ctx) => ctx.app.setScreen("hunt-timeline") },
  { key: "Q", label: "Query", description: "search events", action: (ctx) => ctx.app.setScreen("hunt-query") },
  {
    key: "E",
    label: "Report",
    description: "evidence review",
    action: (ctx) => {
      ctx.state.hunt.report.returnScreen = "main"
      ctx.app.setScreen("hunt-report")
    },
  },
  { key: "H", label: "History", description: "report index", action: (ctx) => ctx.app.setScreen("hunt-report-history") },
]

function findHomeActionIndex(key: string): number {
  return HOME_ACTIONS.findIndex((action) => action.key === key.toUpperCase())
}

function activateHomeAction(index: number, ctx: ScreenContext): boolean {
  const action = HOME_ACTIONS[index]
  if (!action) {
    return false
  }

  ctx.state.homeActionIndex = index
  action.action(ctx)
  return true
}

function moveHomeActionSelection(index: number, key: string): number {
  const maxIndex = HOME_ACTIONS.length - 1
  switch (key) {
    case "\x1b[A":
    case "up":
      return Math.max(0, index - HOME_ACTION_COLUMNS)
    case "\x1b[B":
    case "down":
      return Math.min(maxIndex, index + HOME_ACTION_COLUMNS)
    case "\x1b[D":
    case "left":
      return index % HOME_ACTION_COLUMNS === 0 ? index : index - 1
    case "\x1b[C":
    case "right":
      return index + 1 > maxIndex || index % HOME_ACTION_COLUMNS === HOME_ACTION_COLUMNS - 1 ? index : index + 1
    default:
      return index
  }
}

function renderHomeActionCell(action: HomeAction, selected: boolean, width: number): string {
  if (selected) {
    const innerWidth = Math.max(0, width - 2)
    const content = fitString(
      `${THEME.bold}[${action.key}]${THEME.reset} ${THEME.bold}${action.label}${THEME.reset} ${THEME.white}${action.description}${THEME.reset}`,
      innerWidth,
    )
    return `${THEME.accent}${THEME.bold}▌${THEME.reset}${HOME_ACTION_SELECTED_BG}${THEME.white}${content}${THEME.reset}${THEME.accent}${THEME.bold}▐${THEME.reset}`
  }

  const prefix = `${THEME.dim}•${THEME.reset}`
  const badge = `${THEME.secondary}${action.key}${THEME.reset}`
  const label = `${THEME.white}${action.label}${THEME.reset}`
  return fitString(`${prefix} ${badge} ${label} ${THEME.dim}${action.description}${THEME.reset}`, width)
}

function cycleHomeFocus(focus: HomeFocus): HomeFocus {
  return focus === "prompt" ? "actions" : "prompt"
}

function homeFocusTitle(focus: HomeFocus): string {
  switch (focus) {
    case "actions":
      return "Dispatch [actions]"
    case "nav":
      return "Dispatch [nav]"
    default:
      return "Dispatch [prompt]"
  }
}

function setHomeFocus(state: AppState, focus: HomeFocus): void {
  if (state.homeFocus === focus) {
    return
  }

  const previousFocus = state.homeFocus
  state.homeFocus = focus
  if (focus === "prompt") {
    state.homePromptTraceStartFrame = state.animationFrame
  } else if (previousFocus === "prompt") {
    state.homeActionsTraceStartFrame = state.animationFrame
  }
}

function boxTraceProgress(animationFrame: number, traceStartFrame: number): number {
  const age = Math.max(0, animationFrame - traceStartFrame)
  if (age >= BOX_TRACE_FRAMES) {
    return 1
  }

  return Math.max(0.08, (age + 1) / BOX_TRACE_FRAMES)
}

function renderTracedBox(
  title: string,
  contentLines: string[],
  width: number,
  state: AppState,
  options: {
    focused: boolean
    traceStartFrame: number
    focusedTitleColor?: string
    unfocusedTitleColor?: string
  },
): string[] {
  const { focused, traceStartFrame, focusedTitleColor = THEME.secondary, unfocusedTitleColor = THEME.dim } = options
  const baseBorderColor = THEME.dim
  const activeBorderColor = THEME.secondary
  const titleColor = focused ? focusedTitleColor : unfocusedTitleColor

  if (!focused) {
    return renderBox(title, contentLines, width, THEME, {
      style: "rounded",
      titleAlign: "left",
      padding: 1,
      borderColor: baseBorderColor,
      titleColor,
    })
  }

  const padding = 1
  const innerWidth = width - 2
  const paddedInnerWidth = innerWidth - padding * 2
  const padStr = " ".repeat(padding)
  const border = { tl: "╭", tr: "╮", bl: "╰", br: "╯", h: "─", v: "│" }
  const rows = contentLines.length === 0 ? [""] : contentLines
  const decoratedTitle = ` \u27E8 ${title} \u27E9 `
  const titleFits = decoratedTitle.length < innerWidth
  const remaining = titleFits ? innerWidth - decoratedTitle.length : innerWidth
  const leftFill = titleFits ? 1 : 0
  const rightFill = titleFits ? remaining - leftFill : innerWidth
  const visibleTopSegments = titleFits ? leftFill + rightFill + 2 : innerWidth + 2
  const perimeterSegments = visibleTopSegments + width + rows.length * 2
  const activeSegments = Math.min(
    perimeterSegments,
    Math.max(1, Math.ceil(perimeterSegments * boxTraceProgress(state.animationFrame, traceStartFrame))),
  )

  let segmentIndex = 0
  const segment = (char: string): string => {
    const color = segmentIndex < activeSegments ? activeBorderColor : baseBorderColor
    segmentIndex += 1
    return `${color}${char}${THEME.reset}`
  }

  const topLine = titleFits
    ? `${segment(border.tl)}${Array.from({ length: leftFill }, () => segment(border.h)).join("")}` +
      `${titleColor}${decoratedTitle}${THEME.reset}` +
      `${Array.from({ length: rightFill }, () => segment(border.h)).join("")}${segment(border.tr)}`
    : `${segment(border.tl)}${Array.from({ length: innerWidth }, () => segment(border.h)).join("")}${segment(border.tr)}`

  const lines = [topLine]
  for (const line of rows) {
    const fitted = fitString(line, paddedInnerWidth)
    lines.push(`${segment(border.v)}${padStr}${fitted}${padStr}${segment(border.v)}`)
  }
  lines.push(
    `${segment(border.bl)}${Array.from({ length: innerWidth }, () => segment(border.h)).join("")}${segment(border.br)}`,
  )

  return lines
}

function renderPromptBox(title: string, contentLines: string[], width: number, state: AppState): string[] {
  return renderTracedBox(title, contentLines, width, state, {
    focused: state.homeFocus === "prompt",
    traceStartFrame: state.homePromptTraceStartFrame,
  })
}

function renderHomeActionGuide(focus: HomeFocus, contentWidth: number): string[] {
  switch (focus) {
    case "actions":
      return wrapText(
        `${THEME.dim}Actions focus:${THEME.reset} ${THEME.white}↑↓←→${THEME.reset} move  ` +
          `${THEME.white}Enter${THEME.reset} open  ${THEME.white}Tab${THEME.reset} prompt  ` +
          `${THEME.white}Esc${THEME.reset} prompt`,
        contentWidth,
      )
    case "nav":
      return wrapText(
        `${THEME.dim}Nav mode:${THEME.reset} ${THEME.white}S/A/P/I${THEME.reset} core surfaces  ` +
          `${THEME.white}R${THEME.reset} runs  ${THEME.white}W/X/T/Q/E/H${THEME.reset} hunt loop  ${THEME.white}Esc${THEME.reset} prompt`,
        contentWidth,
      )
    default:
      return wrapText(
        `${THEME.dim}Prompt focus:${THEME.reset} ${THEME.white}Tab${THEME.reset} actions  ` +
          `${THEME.white}Enter${THEME.reset} dispatch sheet  ${THEME.white}Esc${THEME.reset} nav  ` +
          `${THEME.dim}empty prompt keeps W/X/T/Q/E/H live; once you type, keys stay in the prompt${THEME.reset}`,
        contentWidth,
      )
  }
}

function renderHomeActionRows(ctx: ScreenContext, contentWidth: number): string[] {
  const rows: string[] = []
  const selection = Math.min(ctx.state.homeActionIndex, HOME_ACTIONS.length - 1)
  const activeSelection = ctx.state.homeFocus !== "prompt"
  const selectedAction = HOME_ACTIONS[selection]
  const gap = 3
  const cellWidth = Math.max(22, Math.floor((contentWidth - gap) / HOME_ACTION_COLUMNS))

  rows.push(...renderHomeActionGuide(ctx.state.homeFocus, contentWidth))
  if (activeSelection && selectedAction) {
    rows.push(
      fitString(
        `${THEME.accent}${THEME.bold}Selected${THEME.reset} ${THEME.secondary}[${selectedAction.key}]${THEME.reset} ` +
          `${THEME.white}${selectedAction.label}${THEME.reset} ${THEME.dim}${selectedAction.description}${THEME.reset}`,
        contentWidth,
      ),
    )
  }

  for (let i = 0; i < HOME_ACTIONS.length; i += HOME_ACTION_COLUMNS) {
    const left = renderHomeActionCell(HOME_ACTIONS[i], activeSelection && selection === i, cellWidth)
    const rightAction = HOME_ACTIONS[i + 1]
    const right = rightAction
      ? renderHomeActionCell(rightAction, activeSelection && selection === i + 1, cellWidth)
      : ""
    rows.push(joinColumns(left, right, contentWidth))
  }

  return rows
}

export function createMainScreen(commands: Command[]): Screen {
  return {
    render(ctx: ScreenContext): string {
      let content = renderMainContent(ctx, commands)
      if (ctx.state.inputMode === "commands") {
        content = overlayCommandPalette(content, ctx, commands)
      } else if (ctx.state.inputMode === "dispatch-sheet") {
        content = overlayDispatchSheet(content, ctx)
      }
      return content
    },

    handleInput(key: string, ctx: ScreenContext): boolean {
      if (ctx.state.inputMode === "commands") {
        return handleCommandsInput(key, ctx, commands)
      }
      if (ctx.state.inputMode === "dispatch-sheet") {
        return handleDispatchSheetInput(key, ctx)
      }
      return handleMainInput(key, ctx)
    },
  }
}

function handleMainInput(key: string, ctx: ScreenContext): boolean {
  const { state, app } = ctx

  // Ctrl+S - security overview
  if (key === "\x13") {
    app.setScreen("security")
    return true
  }

  // Ctrl+N - cycle agents
  if (key === "\x0e") {
    state.agentIndex = (state.agentIndex + 1) % AGENTS.length
    app.render()
    return true
  }

  // Tab - cycle prompt/actions focus
  if (key === "\t") {
    setHomeFocus(state, cycleHomeFocus(state.homeFocus))
    app.render()
    return true
  }

  // Ctrl+P - open command palette
  if (key === "\x10") {
    state.inputMode = "commands"
    state.commandIndex = 0
    app.render()
    return true
  }

  const isArrowKey =
    key === "\x1b[A" ||
    key === "\x1b[B" ||
    key === "\x1b[C" ||
    key === "\x1b[D" ||
    key === "up" ||
    key === "down" ||
    key === "left" ||
    key === "right"

  if (state.homeFocus === "actions" || state.homeFocus === "nav") {
    if (isArrowKey) {
      state.homeActionIndex = moveHomeActionSelection(state.homeActionIndex, key)
      app.render()
      return true
    }
  }

  if (state.homeFocus === "nav") {
    const actionIndex = findHomeActionIndex(key)
    if (actionIndex >= 0) {
      return activateHomeAction(actionIndex, ctx)
    }
  }

  if (state.homeFocus === "prompt" && state.promptBuffer.length === 0) {
    const actionIndex = HOME_ACTIONS.findIndex((action) => action.key === key)
    if (actionIndex >= 0) {
      return activateHomeAction(actionIndex, ctx)
    }
  }

  // Enter - submit prompt or open selected action
  if (key === "\r") {
    if (state.homeFocus !== "prompt") {
      return activateHomeAction(state.homeActionIndex, ctx)
    }
    if (state.promptBuffer.trim()) {
      app.submitPrompt("dispatch")
    }
    return true
  }

  // Backspace
  if ((key === "\x7f" || key === "\b") && state.homeFocus === "prompt") {
    state.promptBuffer = state.promptBuffer.slice(0, -1)
    app.render()
    return true
  }

  // Ctrl+U - clear line
  if (key === "\x15" && state.homeFocus === "prompt") {
    state.promptBuffer = ""
    app.render()
    return true
  }

  // Escape - toggle prompt/nav, or exit actions focus back to prompt
  if (key === "\x1b" || key === "\x1b\x1b") {
    if (state.homeFocus === "actions") {
      setHomeFocus(state, "prompt")
    } else {
      setHomeFocus(state, state.homeFocus === "prompt" ? "nav" : "prompt")
    }
    app.render()
    return true
  }

  // Regular characters or pasted text - add to prompt
  const printableChunk = state.homeFocus === "prompt" ? printableTextChunk(key) : null
  if (printableChunk) {
    state.promptBuffer += printableChunk
    app.render()
    return true
  }

  return false
}

function handleCommandsInput(key: string, ctx: ScreenContext, commands: Command[]): boolean {
  const { state, app } = ctx

  // Escape - close palette
  if (key === "\x1b" || key === "\x1b\x1b" || key === "\x10") {
    state.inputMode = "main"
    app.render()
    return true
  }

  // Arrow up / k
  if (key === "\x1b[A" || key === "k") {
    state.commandIndex = Math.max(0, state.commandIndex - 1)
    app.render()
    return true
  }

  // Arrow down / j
  if (key === "\x1b[B" || key === "j") {
    state.commandIndex = Math.min(commands.length - 1, state.commandIndex + 1)
    app.render()
    return true
  }

  // Enter - execute command
  if (key === "\r") {
    const cmd = commands[state.commandIndex]
    state.inputMode = "main"
    cmd.action()
    return true
  }

  // Direct key shortcuts
  const cmd = commands.find((c) => c.key.toLowerCase() === key.toLowerCase())
  if (cmd) {
    state.inputMode = "main"
    cmd.action()
    return true
  }

  return false
}

function buildOpsSnapshot(ctx: ScreenContext, width: number): { boxWidth: number; lines: string[] } | null {
  const { state, height } = ctx
  const boxWidth = Math.min(84, width - 8)
  if (boxWidth < 28) {
    return null
  }

  const investigation = state.hunt.investigation
  const counts = getInvestigationCounts(investigation)
  const hasInvestigation =
    Boolean(investigation.origin) || counts.events > 0 || counts.findings > 0
  const stale = hasInvestigation ? isInvestigationStale(investigation) : false
  const compact = height < 28
  const hushdState = state.hushdStatus === "connected"
    ? `${THEME.success}online${THEME.reset}`
    : state.hushdStatus === "connecting"
      ? `${THEME.warning}connecting${THEME.reset}`
      : state.hushdStatus === "unauthorized"
        ? `${THEME.error}unauthorized${THEME.reset}`
        : state.hushdStatus === "stale"
          ? `${THEME.warning}stale${THEME.reset}`
          : state.hushdStatus === "degraded"
            ? `${THEME.warning}degraded${THEME.reset}`
            : `${THEME.dim}offline${THEME.reset}`
  const lines: string[] = [
    `${THEME.dim}Local:${THEME.reset} hushd ${hushdState}  ` +
      `${THEME.dim}runs:${THEME.reset} ${THEME.white}${state.activeRuns}${THEME.reset}  ` +
      `${THEME.dim}beads:${THEME.reset} ${THEME.white}${state.openBeads}${THEME.reset}`,
    `${THEME.dim}Health:${THEME.reset} ${renderHealthStatus(state)}  ` +
      `${THEME.dim}Stream:${THEME.reset} ${renderStreamStatus(state)}`,
  ]

  const lastDenied = renderLastDenied(state)
  if (lastDenied) {
    lines.push(`${THEME.dim}Last deny:${THEME.reset} ${lastDenied}`)
  }

  const latestExport = state.hunt.reportHistory.entries[0]
  if (latestExport) {
    lines.push(
      `${THEME.dim}Last export:${THEME.reset} ${THEME.white}${latestExport.title}${THEME.reset} ` +
        `${THEME.dim}${latestExport.exportedAt.slice(0, 19).replace("T", " ")}${THEME.reset}`,
    )
  }

  if (hasInvestigation) {
    const freshness = stale
      ? `${THEME.warning}stale${THEME.reset}`
      : `${THEME.success}active${THEME.reset}`
    const summary = investigation.summary ?? "Evidence is available for review."
    lines.push(
      `${THEME.dim}Investigation:${THEME.reset} ${THEME.white}${investigation.title || "Untitled"}${THEME.reset}`,
    )
    lines.push(
      `${THEME.dim}State:${THEME.reset} ${THEME.white}${investigation.origin ?? "manual"}${THEME.reset} ${freshness}  ` +
        `${THEME.dim}events:${THEME.reset} ${THEME.white}${counts.events}${THEME.reset}  ` +
        `${THEME.dim}findings:${THEME.reset} ${THEME.white}${counts.findings}${THEME.reset}`,
    )
    if (!compact) {
      lines.push(`${THEME.dim}Summary:${THEME.reset} ${THEME.muted}${summary}${THEME.reset}`)
    }
  } else {
    lines.push(`${THEME.muted}No active investigation loaded.${THEME.reset}`)
  }

  lines.push("")
  if (compact && hasInvestigation) {
    lines.push(
      `${THEME.dim}Jump:${THEME.reset} ${THEME.white}E${THEME.reset} report  ` +
        `${THEME.white}H${THEME.reset} history  ${THEME.white}R${THEME.reset} runs  ${THEME.white}T${THEME.reset} timeline`,
    )
  }
  lines.push(...renderHomeActionRows(ctx, boxWidth - 4))

  return {
    boxWidth,
    lines: renderTracedBox(
      hasInvestigation
        ? state.homeFocus === "prompt"
          ? "Active Investigation"
          : `Active Investigation • ${state.homeFocus}`
        : state.homeFocus === "prompt"
          ? "Ops Snapshot"
          : `Ops Snapshot • ${state.homeFocus}`,
      lines,
      boxWidth,
      state,
      {
        focused: state.homeFocus !== "prompt",
        traceStartFrame: state.homeActionsTraceStartFrame,
      },
    ),
  }
}

function renderMainContent(ctx: ScreenContext, _commands: Command[]): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const opsSnapshot = buildOpsSnapshot(ctx, width)
  const opsHeight = opsSnapshot ? opsSnapshot.lines.length + 2 : 0
  const tickerHeight = state.recentEvents.length > 0 ? 2 : 0
  const statusHeight = state.statusMessage ? 2 : 0

  // Calculate vertical centering for logo + input
  const contentHeight = LOGO.main.length + LOGO.strike.length + 10 + opsHeight + tickerHeight + statusHeight
  const startY = Math.max(1, Math.floor((height - contentHeight) / 3))

  // Top padding
  for (let i = 0; i < startY; i++) {
    lines.push("")
  }

  // Logo - stacked layout: CLAWD on top, STRIKE below
  // Render CLAWD lines in crimson
  lines.push(...centerBlock(
    LOGO.main.map((line) => `${THEME.accent}${line}${THEME.reset}`),
    width,
  ))

  // Get animated STRIKE for current frame and render below
  const animatedStrike = getAnimatedStrike(state.animationFrame)
  lines.push(...centerBlock(animatedStrike, width))

  lines.push("")

  // Hero input box
  const inputWidth = Math.min(78, width - 10)

  const prompt = state.promptBuffer
  const placeholder = 'Ask anything... "Fix broken tests"'
  const cursor = prompt ? THEME.secondary + "▎" + THEME.reset : ""
  const promptFocused = state.homeFocus === "prompt"
  const promptTextColor = promptFocused ? THEME.white : THEME.muted
  const placeholderColor = promptFocused ? THEME.dim : THEME.dimAttr + THEME.muted
  const metaColor = promptFocused ? THEME.dim : THEME.muted

  const innerWidth = inputWidth - 4
  const visiblePrompt = prompt.length > innerWidth - 2
    ? "…" + prompt.slice(-(innerWidth - 3))
    : prompt
  const inputContent = visiblePrompt + cursor
  const agent = AGENTS[state.agentIndex]
  const inputBox = renderPromptBox(
    homeFocusTitle(state.homeFocus),
    [
      prompt
        ? `${promptTextColor}${inputContent}${THEME.reset}`
        : `${placeholderColor}${placeholder}${THEME.reset}`,
      "",
      joinColumns(
        `${THEME.accent}${agent.name}${THEME.reset}  ${metaColor}${agent.model}${THEME.reset} ${THEME.dim}${agent.provider}${THEME.reset}`,
        `${metaColor}ctrl+n${THEME.reset} ${metaColor}next agent${THEME.reset}`,
        inputWidth - 4,
      ),
    ],
    inputWidth,
    state,
  )
  lines.push(...centerBlock(inputBox, width))

  lines.push("")

  // Hint bar - centered
  const primaryHints = state.homeFocus === "prompt"
    ? `${THEME.bold}Enter${THEME.reset}${THEME.muted} dispatch sheet${THEME.reset}    ` +
      `${THEME.bold}Tab${THEME.reset}${THEME.muted} actions${THEME.reset}    ` +
      `${THEME.bold}Ctrl+P${THEME.reset}${THEME.muted} commands${THEME.reset}    ` +
      `${THEME.bold}Esc${THEME.reset}${THEME.muted} nav${THEME.reset}`
    : state.homeFocus === "actions"
      ? `${THEME.bold}↑↓←→${THEME.reset}${THEME.muted} move${THEME.reset}    ` +
        `${THEME.bold}Enter${THEME.reset}${THEME.muted} open${THEME.reset}    ` +
        `${THEME.bold}Tab${THEME.reset}${THEME.muted} prompt${THEME.reset}    ` +
        `${THEME.bold}Esc${THEME.reset}${THEME.muted} prompt${THEME.reset}`
      : `${THEME.bold}S/A/P/I${THEME.reset}${THEME.muted} core pages${THEME.reset}    ` +
        `${THEME.bold}R${THEME.reset}${THEME.muted} runs${THEME.reset}    ` +
        `${THEME.bold}W/X/T/Q/E/H${THEME.reset}${THEME.muted} hunt pages${THEME.reset}    ` +
        `${THEME.bold}Esc${THEME.reset}${THEME.muted} prompt${THEME.reset}`
  const secondaryHints = state.homeFocus === "prompt"
    ? `${THEME.bold}Ctrl+N${THEME.reset}${THEME.muted} next agent${THEME.reset}    ` +
      `${THEME.bold}↑↓←→${THEME.reset}${THEME.muted} available after Tab${THEME.reset}`
    : `${THEME.bold}Ctrl+P${THEME.reset}${THEME.muted} commands${THEME.reset}    ` +
      `${THEME.bold}Ctrl+N${THEME.reset}${THEME.muted} next agent${THEME.reset}`
  lines.push(centerLine(primaryHints, width))
  lines.push(centerLine(secondaryHints, width))

  // Security event ticker
  if (state.recentEvents.length > 0) {
    lines.push("")
    const latest = state.recentEvents[0]
    if (latest.type === "check") {
      const data = latest.data as { action_type?: string; target?: string; guard?: string; decision?: string }
      const icon = data.decision === "deny" ? THEME.error + "◆" : THEME.success + "◆"
      const target = (data.target ?? "").length > 40 ? "…" + (data.target ?? "").slice(-39) : (data.target ?? "")
      const ticker = `${icon}${THEME.reset} ${data.action_type ?? ""} ${THEME.muted}${target}${THEME.reset} via ${THEME.dim}${data.guard ?? ""}${THEME.reset}`
      lines.push(centerLine(ticker, width))
    }
  }

  // Status message (if any)
  if (state.statusMessage) {
    lines.push("")
    lines.push(centerLine(state.statusMessage, width))
  }

  if (opsSnapshot) {
    lines.push("")
    lines.push(...centerBlock(opsSnapshot.lines, width))
  }

  // Fill remaining space (leave room for status bar)
  const currentLines = lines.length
  for (let i = currentLines; i < height - 2; i++) {
    lines.push("")
  }

  return lines.join("\n")
}

function cycleDispatchSheetOption(
  current: number,
  length: number,
  direction: -1 | 1,
): number {
  return (current + direction + length) % length
}

function printableTextChunk(key: string): string | null {
  if (!key || key.includes("\x1b")) {
    return null
  }
  const text = [...key].filter((ch) => ch >= " " && ch !== "\x7f").join("")
  return text.length > 0 ? text : null
}

function handleDispatchSheetInput(key: string, ctx: ScreenContext): boolean {
  const { state, app } = ctx
  const sheet = state.dispatchSheet
  if (!sheet.open) {
    return false
  }

  if (key === "\x1b" || key === "\x1b\x1b" || key.toLowerCase() === "q") {
    app.closeDispatchSheet()
    return true
  }

  if (key === "\r") {
    app.launchDispatchSheet()
    return true
  }

  if (key === "\t" || key === "\x1b[B" || key === "down") {
    sheet.focusedField = ((sheet.focusedField + 1) % 4) as 0 | 1 | 2 | 3
    sheet.error = null
    app.render()
    return true
  }

  if (key === "\x1b[A" || key === "up") {
    sheet.focusedField = ((sheet.focusedField + 3) % 4) as 0 | 1 | 2 | 3
    sheet.error = null
    app.render()
    return true
  }

  if (key === "\x1b[C" || key === "right" || key === "\x1b[D" || key === "left") {
    const direction: -1 | 1 = key === "\x1b[D" || key === "left" ? -1 : 1
    if (sheet.focusedField === 1) {
      sheet.action = sheet.action === "dispatch" ? "speculate" : "dispatch"
    } else if (sheet.focusedField === 2) {
      const modes = ["managed", "attach", "external"] as const
      sheet.mode = modes[cycleDispatchSheetOption(modes.indexOf(sheet.mode), modes.length, direction)]
    } else if (sheet.focusedField === 3) {
      sheet.agentIndex = cycleDispatchSheetOption(sheet.agentIndex, AGENTS.length, direction)
    }
    sheet.error = null
    app.render()
    return true
  }

  if (key === "d" || key === "s") {
    sheet.action = key === "d" ? "dispatch" : "speculate"
    sheet.error = null
    app.render()
    return true
  }

  return false
}

function dispatchField(label: string, value: string, selected: boolean): string {
  const marker = selected ? `${THEME.accent}${THEME.bold}▸${THEME.reset}` : `${THEME.dim}•${THEME.reset}`
  return `${marker} ${THEME.dim}${label}:${THEME.reset} ${value}`
}

function overlayDispatchSheet(baseScreen: string, ctx: ScreenContext): string {
  const { state, width } = ctx
  const lines = baseScreen.split("\n")
  const sheetWidth = Math.max(52, Math.min(82, width - 12))
  const startY = 6
  const sheet = state.dispatchSheet
  const promptPreview = wrapText(sheet.prompt, sheetWidth - 8)
  const content: string[] = [
    `${THEME.dim}Use${THEME.reset} ${THEME.white}↑/↓${THEME.reset} ${THEME.dim}focus${THEME.reset}  ` +
      `${THEME.white}←/→${THEME.reset} ${THEME.dim}change${THEME.reset}  ` +
      `${THEME.white}Enter${THEME.reset} ${THEME.dim}launch${THEME.reset}  ` +
      `${THEME.white}Esc${THEME.reset} ${THEME.dim}cancel${THEME.reset}`,
    "",
    dispatchField(
      "Prompt",
      promptPreview[0]
        ? `${THEME.white}${promptPreview[0]}${THEME.reset}`
        : `${THEME.muted}(empty)${THEME.reset}`,
      sheet.focusedField === 0,
    ),
    ...promptPreview.slice(1).map((line) => `  ${THEME.muted}${line}${THEME.reset}`),
    "",
    dispatchField("Action", `${THEME.white}${sheet.action}${THEME.reset}`, sheet.focusedField === 1),
    dispatchField(
      "Mode",
      sheet.mode === "managed"
        ? `${THEME.white}${sheet.mode}${THEME.reset}`
        : sheet.mode === "attach"
          ? `${THEME.success}${sheet.mode}${THEME.reset} ${THEME.dim}(phase 3)${THEME.reset}`
          : `${THEME.warning}${sheet.mode}${THEME.reset} ${THEME.dim}(phase 5)${THEME.reset}`,
      sheet.focusedField === 2,
    ),
    dispatchField(
      "Agent",
      `${THEME.white}${AGENTS[sheet.agentIndex]?.name ?? AGENTS[0].name}${THEME.reset}`,
      sheet.focusedField === 3,
    ),
  ]

  if (sheet.error) {
    content.push("")
    content.push(`${THEME.error}${sheet.error}${THEME.reset}`)
  }

  const overlay = centerBlock(
    renderBox("Dispatch Sheet", content, sheetWidth, THEME, {
      style: "rounded",
      titleAlign: "left",
      padding: 1,
    }),
    width,
  )

  for (let i = 0; i < overlay.length; i++) {
    const lineIndex = startY + i
    if (lineIndex < lines.length) {
      lines[lineIndex] = overlay[i]
    }
  }

  return lines.join("\n")
}

function commandStageTag(command: Command): { text: string; plainLength: number } {
  if (command.stage === "experimental") {
    return {
      text: `${THEME.warning}exp${THEME.reset}`,
      plainLength: 3,
    }
  }

  return {
    text: `${THEME.success}beta${THEME.reset}`,
    plainLength: 4,
  }
}

function overlayCommandPalette(baseScreen: string, ctx: ScreenContext, commands: Command[]): string {
  const { state, width } = ctx
  const lines = baseScreen.split("\n")
  const paletteWidth = Math.min(78, width - 12)
  const startY = 4
  const contentWidth = paletteWidth - 4

  const paletteLines: string[] = [
    `${THEME.dim}Navigate:${THEME.reset} ${THEME.white}↑/↓${THEME.reset} select  ` +
      `${THEME.white}Enter${THEME.reset} run  ${THEME.white}Esc${THEME.reset} close  ` +
      `${THEME.dim}or press a shortcut key directly${THEME.reset}`,
    "",
  ]

  // Group commands by category
  const categories = [
    { name: "Actions", commands: commands.filter(c => ["d", "s", "g"].includes(c.key)) },
    { name: "Security", commands: commands.filter(c => ["S", "a", "p"].includes(c.key)) },
    { name: "Hunt", commands: commands.filter(c => ["W", "X", "T", "R", "Q", "D", "E", "H", "M", "P"].includes(c.key)) },
    { name: "Views", commands: commands.filter(c => ["b", "r", "i"].includes(c.key)) },
    { name: "System", commands: commands.filter(c => ["?", "q"].includes(c.key)) },
  ]

  let globalIndex = 0
  for (const category of categories) {
    if (category.commands.length === 0) continue

    paletteLines.push(`${THEME.secondary}${THEME.bold}${category.name}${THEME.reset}`)

    for (const cmd of category.commands) {
      const isSelected = globalIndex === state.commandIndex
      const stage = commandStageTag(cmd)
      const left = isSelected
        ? `${THEME.accent}${THEME.bold}▶${THEME.reset} ${THEME.white}${THEME.bold}${cmd.label}${THEME.reset} ${THEME.dim}${cmd.description}${THEME.reset}`
        : `${THEME.dim}•${THEME.reset} ${THEME.white}${cmd.label}${THEME.reset} ${THEME.dim}${cmd.description}${THEME.reset}`
      const right = `${stage.text} ${THEME.dim}${cmd.key}${THEME.reset}`
      paletteLines.push(joinColumns(left, right, contentWidth))
      globalIndex++
    }

    paletteLines.push("")
  }

  while (paletteLines.length > 0 && paletteLines[paletteLines.length - 1] === "") {
    paletteLines.pop()
  }

  const palette = centerBlock(
    renderBox("Commands", paletteLines, paletteWidth, THEME, {
      style: "rounded",
      titleAlign: "left",
      padding: 1,
    }),
    width,
  )

  // Overlay palette onto base screen
  for (let i = 0; i < palette.length; i++) {
    const lineIndex = startY + i
    if (lineIndex < lines.length) {
      lines[lineIndex] = palette[i]
    }
  }

  return lines.join("\n")
}
