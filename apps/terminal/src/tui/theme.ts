/**
 * Theme - Techno Classical Gothic
 *
 * Extracted from app.ts. Contains all visual constants:
 * colors, logo, animation, escape sequences, and agent definitions.
 */

// =============================================================================
// COLORS
// =============================================================================

// Background color - deep obsidian black (defined first so reset can use it)
export const BG_COLOR = "\x1b[48;2;12;12;16m"

export const THEME = {
  // Primary accent - deep crimson (gothic blood)
  accent: BG_COLOR + "\x1b[38;5;124m",
  // Secondary accent - antique gold (classical elegance)
  secondary: BG_COLOR + "\x1b[38;5;178m",
  // Tertiary - deep violet (gothic shadow)
  tertiary: BG_COLOR + "\x1b[38;5;97m",
  // Success - verdigris/aged copper
  success: BG_COLOR + "\x1b[38;5;30m",
  // Warning - burnt sienna
  warning: BG_COLOR + "\x1b[38;5;166m",
  // Error - dark crimson
  error: BG_COLOR + "\x1b[38;5;160m",
  // Muted text - stone gray
  muted: BG_COLOR + "\x1b[38;5;246m",
  // Dimmer muted - charcoal
  dim: BG_COLOR + "\x1b[38;5;240m",
  // White text - ivory/pearl
  white: BG_COLOR + "\x1b[38;5;188m",
  // Background - deep obsidian black
  bg: BG_COLOR,
  // Reset - resets foreground but keeps background
  reset: "\x1b[0m" + BG_COLOR,
  // Bold
  bold: "\x1b[1m",
  // Dim
  dimAttr: "\x1b[2m",
  // Italic
  italic: "\x1b[3m",
} as const

export type ThemeColors = typeof THEME

// =============================================================================
// LOGO
// =============================================================================

// Gothic ASCII logo - stacked two-part layout
// "CLAWD" is static crimson, "STRIKE" is animated with gold shimmer
export const LOGO = {
  // "CLAWD" - static crimson
  main: [
    " ██████╗██╗      █████╗ ██╗    ██╗██████╗ ",
    "██╔════╝██║     ██╔══██╗██║    ██║██╔══██╗",
    "██║     ██║     ███████║██║ █╗ ██║██║  ██║",
    "██║     ██║     ██╔══██║██║███╗██║██║  ██║",
    "╚██████╗███████╗██║  ██║╚███╔███╔╝██████╔╝",
    " ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═════╝",
  ],
  // "STRIKE" - will be animated with gold shimmer
  strike: [
    "███████╗████████╗██████╗ ██╗██╗  ██╗███████╗",
    "██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝",
    "███████╗   ██║   ██████╔╝██║█████╔╝ █████╗  ",
    "╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝  ",
    "███████║   ██║   ██║  ██║██║██║  ██╗███████╗",
    "╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝",
  ],
}

// =============================================================================
// ANIMATION
// =============================================================================

// Gold shimmer palette for the animated "STRIKE"
export const GOLD_SHIMMER_COLORS = [
  "\x1b[38;2;132;90;32m",   // Deep brass
  "\x1b[38;2;165;113;40m",  // Burnished bronze
  "\x1b[38;2;198;142;58m",  // Antique gold
  "\x1b[38;2;224;180;96m",  // Warm gold
  "\x1b[38;2;242;215;150m", // Champagne
  "\x1b[38;2;255;246;228m", // Ivory glint
] as const

// Get animated "STRIKE" with smooth metallic shimmer
export function getAnimatedStrike(frame: number): string[] {
  const result: string[] = []

  const height = LOGO.strike.length
  const width = LOGO.strike[0]?.length ?? 0

  const diagonalSlope = 0.75
  const travel = (width - 1) + (height - 1) * diagonalSlope
  const shimmerCenter = (frame * 0.32) % (travel + 1)
  const bandWidth = 1.65

  for (let row = 0; row < height; row++) {
    let line = ""
    let currentColor: string | null = null
    const chars = [...LOGO.strike[row]]

    for (let col = 0; col < chars.length; col++) {
      const char = chars[col]

      if (char === " ") {
        line += " "
        continue
      }

      // Smooth diagonal shimmer band + subtle micro-variation for "metal" feel
      const pos = col + row * diagonalSlope
      let dist = Math.abs(pos - shimmerCenter)
      dist = Math.min(dist, (travel + 1) - dist)
      const glint = Math.exp(-(dist * dist) / (2 * bandWidth * bandWidth))

      const microWave = (Math.sin(frame * 0.18 + row * 1.1 + col * 0.65) + 1) / 2
      const intensity = Math.min(1, Math.max(0, 0.58 + glint * 0.42 + (microWave - 0.5) * 0.08))

      const colorIdx = Math.min(
        GOLD_SHIMMER_COLORS.length - 1,
        Math.floor(intensity * (GOLD_SHIMMER_COLORS.length - 1)),
      )
      const color = GOLD_SHIMMER_COLORS[colorIdx]

      if (color !== currentColor) {
        line += BG_COLOR + color
        currentColor = color
      }
      line += char
    }
    result.push(line + THEME.reset)
  }

  return result
}

// =============================================================================
// ESCAPE SEQUENCES
// =============================================================================

export const ESC = {
  clearScreen: "\x1b[2J",
  moveTo: (row: number, col: number) => `\x1b[${row};${col}H`,
  hideCursor: "\x1b[?25l",
  showCursor: "\x1b[?25h",
  altScreen: "\x1b[?1049h",
  mainScreen: "\x1b[?1049l",
  clearLine: "\x1b[2K",
  clearToEndOfScreen: "\x1b[J",
} as const

// =============================================================================
// AGENTS
// =============================================================================

export const AGENTS = [
  { id: "claude", name: "Claude", model: "Opus 4", provider: "Anthropic" },
  { id: "codex", name: "Codex", model: "GPT-5.2", provider: "OpenAI" },
  { id: "opencode", name: "OpenCode", model: "Multi", provider: "Open" },
  { id: "crush", name: "Crush", model: "Fallback", provider: "Multi" },
] as const

export type Agent = (typeof AGENTS)[number]
