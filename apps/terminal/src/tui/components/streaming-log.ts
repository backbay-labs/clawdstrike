/**
 * Streaming log component - auto-scrolling log view with pause support.
 */

import type { ThemeColors } from "./types"
import { fitString } from "./types"

export interface LogLine {
  text: string
  plainLength: number
  timestamp?: string
}

export interface LogState {
  lines: LogLine[]
  maxLines: number
  viewport: number
  paused: boolean
}

export function createLogState(maxLines = 1000): LogState {
  return {
    lines: [],
    maxLines,
    viewport: 0,
    paused: false,
  }
}

export function renderLog(
  state: LogState,
  height: number,
  width: number,
  theme: ThemeColors,
): string[] {
  if (height <= 0 || width <= 0) return []

  const total = state.lines.length
  const statusHeight = 1
  const viewHeight = height - statusHeight

  if (viewHeight <= 0) {
    // Only room for status
    return [renderLogStatus(state, width, theme)]
  }

  const lines: string[] = []

  if (total === 0) {
    for (let i = 0; i < viewHeight; i++) {
      if (i === Math.floor(viewHeight / 2)) {
        lines.push(fitString(`${theme.dim}  Waiting for log output...${theme.reset}`, width))
      } else {
        lines.push(" ".repeat(width))
      }
    }
  } else {
    // Calculate visible window
    let startIdx: number
    if (state.paused && state.viewport > 0) {
      // Scroll offset from bottom
      startIdx = Math.max(0, total - state.viewport - viewHeight)
    } else {
      // Auto-scroll: show most recent
      startIdx = Math.max(0, total - viewHeight)
    }

    for (let i = 0; i < viewHeight; i++) {
      const idx = startIdx + i
      if (idx >= total) {
        lines.push(" ".repeat(width))
        continue
      }
      const logLine = state.lines[idx]
      const ts = logLine.timestamp
        ? `${theme.dim}${logLine.timestamp} ${theme.reset}`
        : ""
      lines.push(fitString(`${ts}${logLine.text}`, width))
    }
  }

  // Status bar
  lines.push(renderLogStatus(state, width, theme))

  return lines
}

function renderLogStatus(state: LogState, width: number, theme: ThemeColors): string {
  const pauseIndicator = state.paused
    ? `${theme.warning} PAUSED${theme.reset}`
    : `${theme.success} LIVE${theme.reset}`
  const lineCount = `${theme.dim}${state.lines.length} lines${theme.reset}`
  const status = `${pauseIndicator} ${theme.dim}\u2502${theme.reset} ${lineCount}`
  return fitString(status, width)
}

export function appendLine(state: LogState, line: LogLine): LogState {
  const newLines = [...state.lines, line]
  // Ring buffer: trim from front if over capacity
  if (newLines.length > state.maxLines) {
    const excess = newLines.length - state.maxLines
    newLines.splice(0, excess)
  }
  return { ...state, lines: newLines }
}

export function togglePause(state: LogState): LogState {
  return {
    ...state,
    paused: !state.paused,
    // Reset viewport when unpausing (return to auto-scroll)
    viewport: state.paused ? 0 : state.viewport,
  }
}

export function scrollLogUp(state: LogState, amount = 1): LogState {
  if (!state.paused) return state
  const maxScroll = Math.max(0, state.lines.length - 1)
  return {
    ...state,
    viewport: Math.min(maxScroll, state.viewport + amount),
  }
}

export function scrollLogDown(state: LogState, amount = 1): LogState {
  if (!state.paused) return state
  return {
    ...state,
    viewport: Math.max(0, state.viewport - amount),
  }
}

export function clearLog(state: LogState): LogState {
  return {
    ...state,
    lines: [],
    viewport: 0,
  }
}
