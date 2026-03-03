/**
 * Setup Screen - First-run wizard
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { SandboxMode } from "../../types"
import { Config } from "../../config"

export const setupScreen: Screen = {
  render(ctx: ScreenContext): string {
    return renderSetupScreen(ctx)
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    return handleSetupInput(key, ctx)
  },
}

function getAvailableSandboxModes(ctx: ScreenContext): number[] {
  const modes = [0] // inplace always available
  if (ctx.state.setupDetection?.git_available) {
    modes.push(1) // worktree
  }
  modes.push(2) // tmpdir always available
  return modes
}

function handleSetupInput(key: string, ctx: ScreenContext): boolean {
  const { state, app } = ctx

  if (state.setupStep === "detecting") return true

  // j/↓: next sandbox option
  if (key === "j" || key === "\x1b[B") {
    const modes = getAvailableSandboxModes(ctx)
    const currentIdx = modes.indexOf(state.setupSandboxIndex)
    if (currentIdx < modes.length - 1) {
      state.setupSandboxIndex = modes[currentIdx + 1]
    }
    app.render()
    return true
  }

  // k/↑: previous sandbox option
  if (key === "k" || key === "\x1b[A") {
    const modes = getAvailableSandboxModes(ctx)
    const currentIdx = modes.indexOf(state.setupSandboxIndex)
    if (currentIdx > 0) {
      state.setupSandboxIndex = modes[currentIdx - 1]
    }
    app.render()
    return true
  }

  // Enter: confirm
  if (key === "\r") {
    confirmSetup(ctx)
    return true
  }

  // Esc: quit
  if (key === "\x1b" || key === "\x1b\x1b") {
    app.quit()
    return true
  }

  return true
}

async function confirmSetup(ctx: ScreenContext): Promise<void> {
  const { state, app } = ctx
  const detection = state.setupDetection
  if (!detection) return

  const modeNames: SandboxMode[] = ["inplace", "worktree", "tmpdir"]
  const config = {
    schema_version: "1.0.0" as const,
    sandbox: modeNames[state.setupSandboxIndex],
    toolchain: detection.recommended_toolchain,
    adapters: detection.adapters,
    git_available: detection.git_available,
    project_id: "default",
  }
  await Config.save(app.getCwd(), config)

  state.inputMode = "main"
  state.statusMessage = `${THEME.success}✓${THEME.reset} Configuration saved`
  app.render()

  setTimeout(() => {
    state.statusMessage = ""
    app.render()
  }, 3000)
}

function renderSetupScreen(ctx: ScreenContext): string {
  const { state, width, height } = ctx
  const lines: string[] = []
  const detection = state.setupDetection

  const boxWidth = Math.min(60, width - 10)
  const boxPad = Math.max(0, Math.floor((width - boxWidth) / 2))
  const startY = Math.max(2, Math.floor(height / 6))

  for (let i = 0; i < startY; i++) lines.push("")

  // Title
  const title = "⟨ Setup ⟩"
  const titlePadLeft = Math.floor((boxWidth - title.length - 4) / 2)
  const titlePadRight = boxWidth - title.length - titlePadLeft - 4
  lines.push(" ".repeat(boxPad) + THEME.dim + "╔═" + "═".repeat(titlePadLeft) + title + "═".repeat(titlePadRight) + "═╗" + THEME.reset)
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)

  if (state.setupStep === "detecting" || !detection) {
    const msg = "◈ Divining system state..."
    lines.push(" ".repeat(boxPad) + THEME.dim + "║  " + THEME.reset + THEME.secondary + msg + THEME.reset + " ".repeat(Math.max(0, boxWidth - msg.length - 4)) + THEME.dim + "║" + THEME.reset)
  } else {
    // Detected Toolchains section
    const tcLabel = "Detected Toolchains"
    lines.push(" ".repeat(boxPad) + THEME.dim + "║  " + THEME.reset + THEME.secondary + "◇ " + THEME.reset + THEME.white + THEME.bold + tcLabel + THEME.reset + " ".repeat(boxWidth - tcLabel.length - 6) + THEME.dim + "║" + THEME.reset)

    const adapterOrder = ["claude", "codex", "opencode", "crush"]
    for (const id of adapterOrder) {
      const adapter = detection.adapters[id]
      const available = adapter?.available ?? false
      const icon = available ? `${THEME.success}◆` : `${THEME.dim}◇`
      const status = available ? "available" : "not found"
      const statusColor = available ? THEME.muted : THEME.dim
      const content = `    ${icon}${THEME.reset} ${THEME.muted}${id.padEnd(12)}${THEME.reset}${statusColor}${status}${THEME.reset}`
      const contentLen = `    ◆ ${id.padEnd(12)}${status}`.length
      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + content + " ".repeat(Math.max(0, boxWidth - contentLen - 2)) + THEME.dim + "║" + THEME.reset)
    }

    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)

    // Sandbox Mode section
    const sbLabel = "Sandbox Mode"
    lines.push(" ".repeat(boxPad) + THEME.dim + "║  " + THEME.reset + THEME.secondary + "◇ " + THEME.reset + THEME.white + THEME.bold + sbLabel + THEME.reset + " ".repeat(boxWidth - sbLabel.length - 6) + THEME.dim + "║" + THEME.reset)

    const sandboxOptions: Array<{ idx: number; name: string; desc: string; disabled: boolean }> = [
      { idx: 0, name: "inplace", desc: "run in current directory", disabled: false },
      { idx: 1, name: "worktree", desc: "git worktree isolation", disabled: !detection.git_available },
      { idx: 2, name: "tmpdir", desc: "copy to temp directory", disabled: false },
    ]

    for (const opt of sandboxOptions) {
      const selected = state.setupSandboxIndex === opt.idx
      const selIcon = selected ? `${THEME.accent}>` : " "
      const boxIcon = selected ? `${THEME.secondary}■` : `${THEME.dim}□`
      const nameColor = opt.disabled ? THEME.dim : THEME.muted
      const descColor = opt.disabled ? THEME.dim : THEME.dim
      const suffix = opt.idx === 0 ? " (recommended)" : opt.disabled ? " (no git)" : ""
      const content = `  ${selIcon}${THEME.reset} ${boxIcon}${THEME.reset} ${nameColor}${opt.name.padEnd(12)}${THEME.reset}${descColor}${opt.desc}${suffix}${THEME.reset}`
      const contentLen = `  > ■ ${opt.name.padEnd(12)}${opt.desc}${suffix}`.length
      lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + content + " ".repeat(Math.max(0, boxWidth - contentLen - 2)) + THEME.dim + "║" + THEME.reset)
    }

    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)

    // Environment section
    const envLabel = "Environment"
    lines.push(" ".repeat(boxPad) + THEME.dim + "║  " + THEME.reset + THEME.secondary + "◇ " + THEME.reset + THEME.white + THEME.bold + envLabel + THEME.reset + " ".repeat(boxWidth - envLabel.length - 6) + THEME.dim + "║" + THEME.reset)

    const gitIcon = detection.git_available ? `${THEME.success}◆` : `${THEME.dim}◇`
    const gitStatus = detection.git_available ? "detected" : "not found"
    const gitLine = `    ${gitIcon}${THEME.reset} ${THEME.muted}${"git".padEnd(12)}${THEME.reset}${THEME.dim}${gitStatus}${THEME.reset}`
    const gitLen = `    ◆ ${"git".padEnd(12)}${gitStatus}`.length
    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + THEME.reset + gitLine + " ".repeat(Math.max(0, boxWidth - gitLen - 2)) + THEME.dim + "║" + THEME.reset)

    lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(boxWidth - 2) + "║" + THEME.reset)
  }

  // Help text
  const helpText = "enter confirm  ◆  j/k select  ◆  esc quit"
  const helpPad = Math.max(0, Math.floor((boxWidth - helpText.length) / 2))
  lines.push(" ".repeat(boxPad) + THEME.dim + "║" + " ".repeat(helpPad) + helpText + " ".repeat(Math.max(0, boxWidth - helpPad - helpText.length - 2)) + "║" + THEME.reset)

  // Bottom border
  lines.push(" ".repeat(boxPad) + THEME.dim + "╚" + "═".repeat(boxWidth - 2) + "╝" + THEME.reset)

  // Fill remaining
  for (let i = lines.length; i < height - 1; i++) lines.push("")

  return lines.join("\n")
}
