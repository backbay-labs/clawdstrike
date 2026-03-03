/**
 * Main Screen - Hero input + command palette overlay
 */

import { THEME, LOGO, AGENTS, getAnimatedStrike } from "../theme"
import type { Screen, ScreenContext, Command } from "../types"

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

function renderMainContent(ctx: ScreenContext, _commands: Command[]): string {
  const { state, width, height } = ctx
  const lines: string[] = []

  // Calculate vertical centering for logo + input
  const contentHeight = LOGO.main.length + LOGO.strike.length + 9
  const startY = Math.max(2, Math.floor((height - contentHeight) / 2))

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
  const hints = `${THEME.bold}tab${THEME.reset}${THEME.muted} switch agent${THEME.reset}    ${THEME.bold}ctrl+p${THEME.reset}${THEME.muted} commands${THEME.reset}`
  const hintsTextLen = "tab switch agent    ctrl+p commands".length
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

  // Fill remaining space (leave room for status bar)
  const currentLines = lines.length
  for (let i = currentLines; i < height - 2; i++) {
    lines.push("")
  }

  return lines.join("\n")
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
    { name: "Hunt", commands: commands.filter(c => ["W", "X", "T", "R", "Q", "D", "E", "M", "P"].includes(c.key)) },
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
      const contentWidth = paletteWidth - 4

      if (isSelected) {
        const labelPad = contentWidth - label.length - shortcut.length - 1
        paletteLines.push(
          modalBg + THEME.dim + "│" + THEME.reset +
          highlightBg + highlightFg + " " + THEME.bold + label + THEME.reset +
          highlightBg + " ".repeat(Math.max(1, labelPad)) +
          highlightFg + shortcut + " " + THEME.reset +
          modalBg + THEME.dim + "│" + THEME.reset
        )
      } else {
        const labelPad = contentWidth - label.length - shortcut.length - 1
        paletteLines.push(
          modalBg + THEME.dim + "│" + THEME.reset +
          modalBg + " " + THEME.white + label + THEME.reset +
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
