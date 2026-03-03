/**
 * Shared types for TUI components.
 */

export interface ThemeColors {
  accent: string
  secondary: string
  tertiary: string
  success: string
  warning: string
  error: string
  muted: string
  dim: string
  white: string
  bg: string
  reset: string
  bold: string
  dimAttr: string
  italic: string
}

// ---- ANSI Utilities ----

/** Strip ANSI escape sequences from a string */
export function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, "")
}

/** Get the visible (non-ANSI) length of a string */
export function visibleLength(s: string): number {
  return stripAnsi(s).length
}

/** Pad or truncate an ANSI string to exactly `width` visible characters */
export function fitString(s: string, width: number, padChar = " "): string {
  if (width <= 0) return ""
  const vis = stripAnsi(s)
  if (vis.length === width) return s
  if (vis.length > width) return truncateAnsi(s, width)
  return s + padChar.repeat(width - vis.length)
}

/** Truncate an ANSI string to `maxWidth` visible characters */
export function truncateAnsi(s: string, maxWidth: number): string {
  if (maxWidth <= 0) return ""
  let visible = 0
  let result = ""
  let inEscape = false
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]
    if (ch === "\x1b") {
      inEscape = true
      result += ch
      continue
    }
    if (inEscape) {
      result += ch
      if (ch === "m") inEscape = false
      continue
    }
    if (visible >= maxWidth) break
    result += ch
    visible++
  }
  return result
}
