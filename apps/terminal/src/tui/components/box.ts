/**
 * Box component - renders a bordered box with an optional title.
 */

import type { ThemeColors } from "./types"
import { fitString } from "./types"

export interface BoxOptions {
  style?: "single" | "double" | "rounded"
  titleAlign?: "left" | "center" | "right"
  padding?: number
}

const BORDERS = {
  single: { tl: "┌", tr: "┐", bl: "└", br: "┘", h: "─", v: "│" },
  double: { tl: "╔", tr: "╗", bl: "╚", br: "╝", h: "═", v: "║" },
  rounded: { tl: "╭", tr: "╮", bl: "╰", br: "╯", h: "─", v: "│" },
} as const

export function renderBox(
  title: string,
  contentLines: string[],
  width: number,
  theme: ThemeColors,
  opts?: BoxOptions,
): string[] {
  if (width < 4) return []
  const style = opts?.style ?? "single"
  const titleAlign = opts?.titleAlign ?? "center"
  const padding = opts?.padding ?? 0
  const b = BORDERS[style]

  const innerWidth = width - 2
  const paddedInnerWidth = innerWidth - padding * 2
  const padStr = " ".repeat(padding)

  // Build top border
  let topBar: string
  if (title) {
    const decorated = ` \u27E8 ${title} \u27E9 `
    const titleLen = decorated.length
    if (titleLen >= innerWidth) {
      topBar = `${theme.dim}${b.tl}${b.h.repeat(innerWidth)}${b.tr}${theme.reset}`
    } else {
      const remaining = innerWidth - titleLen
      let leftFill: number
      let rightFill: number
      if (titleAlign === "left") {
        leftFill = 1
        rightFill = remaining - 1
      } else if (titleAlign === "right") {
        rightFill = 1
        leftFill = remaining - 1
      } else {
        leftFill = Math.floor(remaining / 2)
        rightFill = remaining - leftFill
      }
      topBar =
        `${theme.dim}${b.tl}${b.h.repeat(leftFill)}${theme.reset}` +
        `${theme.secondary}${decorated}${theme.reset}` +
        `${theme.dim}${b.h.repeat(rightFill)}${b.tr}${theme.reset}`
    }
  } else {
    topBar = `${theme.dim}${b.tl}${b.h.repeat(innerWidth)}${b.tr}${theme.reset}`
  }

  // Build bottom border
  const bottomBar = `${theme.dim}${b.bl}${b.h.repeat(innerWidth)}${b.br}${theme.reset}`

  // Build content lines
  const lines: string[] = [topBar]
  if (contentLines.length === 0) {
    lines.push(`${theme.dim}${b.v}${theme.reset}${" ".repeat(innerWidth)}${theme.dim}${b.v}${theme.reset}`)
  } else {
    for (const line of contentLines) {
      const fitted = fitString(line, paddedInnerWidth)
      lines.push(
        `${theme.dim}${b.v}${theme.reset}${padStr}${fitted}${padStr}${theme.dim}${b.v}${theme.reset}`,
      )
    }
  }
  lines.push(bottomBar)
  return lines
}
