/**
 * Main Screen - Hero input + command palette overlay
 */

import { THEME, LOGO, AGENTS, getAnimatedStrike } from "../theme"
import type { Screen, ScreenContext, Command } from "../types"
import { renderBox } from "../components/box"
import { getInvestigationCounts, isInvestigationStale } from "../investigation"
import type { AppState } from "../types"
import type { CheckEventData, DaemonEvent } from "../../hushd"

const STREAM_STALE_MS = 5 * 60_000

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
  return state.recentEvents.find((event) => (
    event.type === "check" &&
    (event.data as CheckEventData).decision === "deny"
  )) ?? null
}

function renderLastDenied(state: AppState): string | null {
  const event = findLastDeniedEvent(state)
  if (!event || event.type !== "check") {
    return null
  }

  const data = event.data as CheckEventData
  const target = truncateMiddle(data.target, 42)
  return `${THEME.error}${data.action_type}${THEME.reset} ${THEME.white}${target}${THEME.reset} ${THEME.dim}via ${data.guard}${THEME.reset}`
}

export function createMainScreen(commands: Command[]): Screen {
  return {
    render(ctx: ScreenContext): string {
      let content = renderMainContent(ctx, commands)
      if (ctx.state.inputMode === "commands") {
        content = overlayCommandPalette(content, ctx, commands)
      }
      return content
    },

    handleInput(key: string, ctx: ScreenContext): boolean {
      if (ctx.state.inputMode === "commands") {
        return handleCommandsInput(key, ctx, commands)
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

  // Tab - cycle agents
  if (key === "\t") {
    state.agentIndex = (state.agentIndex + 1) % AGENTS.length
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

  if (!state.promptBuffer) {
    if (key === "W") {
      app.setScreen("hunt-watch")
      return true
    }
    if (key === "X") {
      app.setScreen("hunt-scan")
      return true
    }
    if (key === "T") {
      app.setScreen("hunt-timeline")
      return true
    }
    if (key === "Q") {
      app.setScreen("hunt-query")
      return true
    }
    if (key === "E") {
      app.setScreen("hunt-report")
      return true
    }
    if (key === "H") {
      app.setScreen("hunt-report-history")
      return true
    }
  }

  // Enter - submit prompt
  if (key === "\r") {
    if (state.promptBuffer.trim()) {
      app.submitPrompt("dispatch")
    }
    return true
  }

  // Backspace
  if (key === "\x7f" || key === "\b") {
    state.promptBuffer = state.promptBuffer.slice(0, -1)
    app.render()
    return true
  }

  // Ctrl+U - clear line
  if (key === "\x15") {
    state.promptBuffer = ""
    app.render()
    return true
  }

  // Escape - clear or quit
  if (key === "\x1b" || key === "\x1b\x1b") {
    if (state.promptBuffer) {
      state.promptBuffer = ""
      app.render()
    } else {
      app.quit()
    }
    return true
  }

  // Regular characters - add to prompt
  if (key.length === 1 && key >= " ") {
    state.promptBuffer += key
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
    lines.push(
      `${THEME.dim}Jump:${THEME.reset} ${THEME.white}E${THEME.reset} report  ` +
        `${THEME.white}H${THEME.reset} history  ` +
        `${THEME.white}T${THEME.reset} timeline  ` +
        `${THEME.white}W${THEME.reset} watch  ` +
        `${THEME.white}X${THEME.reset} scan  ` +
        `${THEME.white}Q${THEME.reset} query`,
    )
  } else {
    lines.push(`${THEME.muted}No active investigation loaded.${THEME.reset}`)
    if (!compact) {
      lines.push(
        `${THEME.dim}Loop:${THEME.reset} ${THEME.white}X${THEME.reset} scan  ->  ` +
          `${THEME.white}Q${THEME.reset} query  ->  ` +
          `${THEME.white}T${THEME.reset} timeline  ->  ` +
          `${THEME.white}E${THEME.reset} report  ->  ` +
          `${THEME.white}H${THEME.reset} history`,
      )
    }
    lines.push(
      `${THEME.dim}Start:${THEME.reset} ${THEME.white}W${THEME.reset} watch live events  ` +
        `${THEME.white}X${THEME.reset} scan local MCP  ` +
        `${THEME.white}Q${THEME.reset} run a hunt query`,
    )
  }

  return {
    boxWidth,
    lines: renderBox(
      hasInvestigation ? "Active Investigation" : "Ops Snapshot",
      lines,
      boxWidth,
      THEME,
      { style: "rounded", padding: 1 },
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
  const contentHeight = LOGO.main.length + LOGO.strike.length + 9 + opsHeight + tickerHeight + statusHeight
  const startY = Math.max(1, Math.floor((height - contentHeight) / 3))

  // Top padding
  for (let i = 0; i < startY; i++) {
    lines.push("")
  }

  // Logo - stacked layout: CLAWD on top, STRIKE below
  const mainWidth = LOGO.main[0].length
  const strikeWidth = LOGO.strike[0].length
  const mainPad = Math.max(0, Math.floor((width - mainWidth) / 2))
  const strikePad = Math.max(0, Math.floor((width - strikeWidth) / 2))

  // Render CLAWD lines in crimson
  for (let i = 0; i < LOGO.main.length; i++) {
    lines.push(" ".repeat(mainPad) + THEME.accent + LOGO.main[i] + THEME.reset)
  }

  // Get animated STRIKE for current frame and render below
  const animatedStrike = getAnimatedStrike(state.animationFrame)
  for (let i = 0; i < animatedStrike.length; i++) {
    lines.push(" ".repeat(strikePad) + animatedStrike[i])
  }

  lines.push("")
  lines.push("")

  // Hero input box
  const inputWidth = Math.min(80, width - 8)
  const inputPad = Math.max(0, Math.floor((width - inputWidth) / 2))

  const prompt = state.promptBuffer
  const placeholder = 'Ask anything... "Fix broken tests"'
  const cursor = prompt ? THEME.secondary + "▎" + THEME.reset : ""

  // Top of input box
  lines.push(" ".repeat(inputPad) + THEME.dim + "┌" + "─".repeat(inputWidth - 2) + "┐" + THEME.reset)

  // Input line with accent bar
  const innerWidth = inputWidth - 4
  const visiblePrompt = prompt.length > innerWidth - 2
    ? "…" + prompt.slice(-(innerWidth - 3))
    : prompt
  const inputContent = visiblePrompt + cursor
  const inputPadding = Math.max(0, innerWidth - visiblePrompt.length - 1)

  if (prompt) {
    lines.push(" ".repeat(inputPad) + THEME.accent + "│" + THEME.reset + " " + THEME.white + inputContent + THEME.reset + " ".repeat(inputPadding) + THEME.dim + "│" + THEME.reset)
  } else {
    lines.push(" ".repeat(inputPad) + THEME.accent + "│" + THEME.reset + " " + THEME.dim + placeholder + THEME.reset + " ".repeat(Math.max(0, innerWidth - placeholder.length)) + THEME.dim + "│" + THEME.reset)
  }

  lines.push(" ".repeat(inputPad) + THEME.dim + "│" + " ".repeat(inputWidth - 2) + "│" + THEME.reset)

  // Agent info line
  const agent = AGENTS[state.agentIndex]
  const agentLine = `${THEME.accent}${agent.name}${THEME.reset}  ${THEME.muted}${agent.model}${THEME.reset} ${THEME.dim}${agent.provider}${THEME.reset}`
  const agentTextLen = agent.name.length + 2 + agent.model.length + 1 + agent.provider.length
  const agentPadding = Math.max(0, inputWidth - 4 - agentTextLen)
  lines.push(" ".repeat(inputPad) + THEME.dim + "│" + THEME.reset + " " + agentLine + " ".repeat(agentPadding) + THEME.dim + "│" + THEME.reset)

  // Bottom of input box
  lines.push(" ".repeat(inputPad) + THEME.dim + "└" + "─".repeat(inputWidth - 2) + "┘" + THEME.reset)

  lines.push("")

  // Hint bar - centered
  const hints =
    `${THEME.bold}tab${THEME.reset}${THEME.muted} switch agent${THEME.reset}    ` +
    `${THEME.bold}ctrl+p${THEME.reset}${THEME.muted} commands${THEME.reset}    ` +
    `${THEME.bold}W/X/Q/T/E/H${THEME.reset}${THEME.muted} hunt loop${THEME.reset}`
  const hintsTextLen = "tab switch agent    ctrl+p commands    W/X/Q/T/E/H hunt loop".length
  const hintsPad = Math.max(0, Math.floor((width - hintsTextLen) / 2))
  lines.push(" ".repeat(hintsPad) + hints)

  // Security event ticker
  if (state.recentEvents.length > 0) {
    lines.push("")
    const latest = state.recentEvents[0]
    if (latest.type === "check") {
      const data = latest.data as { action_type?: string; target?: string; guard?: string; decision?: string }
      const icon = data.decision === "deny" ? THEME.error + "◆" : THEME.success + "◆"
      const target = (data.target ?? "").length > 40 ? "…" + (data.target ?? "").slice(-39) : (data.target ?? "")
      const ticker = `${icon}${THEME.reset} ${data.action_type ?? ""} ${THEME.muted}${target}${THEME.reset} via ${THEME.dim}${data.guard ?? ""}${THEME.reset}`
      const tickerLen = `◆ ${data.action_type ?? ""} ${target} via ${data.guard ?? ""}`.length
      const tickerPad = Math.max(0, Math.floor((width - tickerLen) / 2))
      lines.push(" ".repeat(tickerPad) + ticker)
    }
  }

  // Status message (if any)
  if (state.statusMessage) {
    lines.push("")
    const statusLen = state.statusMessage.replace(/\x1b\[[0-9;]*m/g, "").length
    const statusPad = Math.max(0, Math.floor((width - statusLen) / 2))
    lines.push(" ".repeat(statusPad) + state.statusMessage)
  }

  if (opsSnapshot) {
    lines.push("")
    const boxPad = Math.max(0, Math.floor((width - opsSnapshot.boxWidth) / 2))
    for (const line of opsSnapshot.lines) {
      lines.push(" ".repeat(boxPad) + line)
    }
  }

  // Fill remaining space (leave room for status bar)
  const currentLines = lines.length
  for (let i = currentLines; i < height - 2; i++) {
    lines.push("")
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

  const paletteWidth = Math.min(70, width - 10)
  const startX = Math.max(0, Math.floor((width - paletteWidth) / 2))
  const startY = 3

  const modalBg = "\x1b[48;2;32;32;36m"
  const highlightBg = "\x1b[48;2;204;153;102m"
  const highlightFg = "\x1b[38;5;235m"

  const paletteLines: string[] = []

  // Top border (rounded)
  paletteLines.push(modalBg + THEME.dim + "╭" + "─".repeat(paletteWidth - 2) + "╮" + THEME.reset)

  // Header
  const title = "Commands"
  const escHint = "esc"
  const headerPad = paletteWidth - 4 - title.length - escHint.length
  paletteLines.push(modalBg + THEME.dim + "│" + THEME.reset + modalBg + " " + THEME.white + THEME.bold + title + THEME.reset + modalBg + " ".repeat(headerPad) + THEME.muted + escHint + " " + THEME.dim + "│" + THEME.reset)

  paletteLines.push(modalBg + THEME.dim + "│" + THEME.reset + modalBg + " ".repeat(paletteWidth - 2) + THEME.dim + "│" + THEME.reset)

  // Search placeholder
  paletteLines.push(modalBg + THEME.dim + "│" + THEME.reset + modalBg + " " + THEME.dim + "Search" + THEME.reset + modalBg + " ".repeat(paletteWidth - 9) + THEME.dim + "│" + THEME.reset)

  paletteLines.push(modalBg + THEME.dim + "│" + THEME.reset + modalBg + " ".repeat(paletteWidth - 2) + THEME.dim + "│" + THEME.reset)

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

    const catPad = paletteWidth - 3 - category.name.length
    paletteLines.push(modalBg + THEME.dim + "│" + THEME.reset + modalBg + " " + THEME.secondary + category.name + THEME.reset + modalBg + " ".repeat(catPad) + THEME.dim + "│" + THEME.reset)

    for (const cmd of category.commands) {
      const isSelected = globalIndex === state.commandIndex
      const label = cmd.label
      const shortcut = cmd.key
      const stage = commandStageTag(cmd)
      const contentWidth = paletteWidth - 4

      if (isSelected) {
        const labelPad = contentWidth - label.length - stage.plainLength - shortcut.length - 4
        paletteLines.push(
          modalBg + THEME.dim + "│" + THEME.reset +
          highlightBg + highlightFg + " " + THEME.bold + label + THEME.reset +
          highlightBg + " " + stage.text + THEME.reset +
          highlightBg + " ".repeat(Math.max(1, labelPad)) +
          highlightFg + shortcut + " " + THEME.reset +
          modalBg + THEME.dim + "│" + THEME.reset
        )
      } else {
        const labelPad = contentWidth - label.length - stage.plainLength - shortcut.length - 4
        paletteLines.push(
          modalBg + THEME.dim + "│" + THEME.reset +
          modalBg + " " + THEME.white + label + THEME.reset +
          modalBg + " " + stage.text + THEME.reset +
          modalBg + " ".repeat(Math.max(1, labelPad)) +
          THEME.dim + shortcut + " " + THEME.reset +
          modalBg + THEME.dim + "│" + THEME.reset
        )
      }
      globalIndex++
    }

    if (category !== categories[categories.length - 1]) {
      paletteLines.push(modalBg + THEME.dim + "│" + THEME.reset + modalBg + " ".repeat(paletteWidth - 2) + THEME.dim + "│" + THEME.reset)
    }
  }

  paletteLines.push(modalBg + THEME.dim + "│" + THEME.reset + modalBg + " ".repeat(paletteWidth - 2) + THEME.dim + "│" + THEME.reset)
  paletteLines.push(modalBg + THEME.dim + "╰" + "─".repeat(paletteWidth - 2) + "╯" + THEME.reset)

  // Overlay palette onto base screen
  for (let i = 0; i < paletteLines.length; i++) {
    const lineIndex = startY + i
    if (lineIndex < lines.length) {
      lines[lineIndex] = " ".repeat(startX) + paletteLines[i]
    }
  }

  return lines.join("\n")
}
