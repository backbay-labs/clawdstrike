/**
 * Split pane component - renders two panes side by side with a divider.
 */

import type { ThemeColors } from "./types"
import { fitString } from "./types"

export function renderSplit(
  leftLines: string[],
  rightLines: string[],
  width: number,
  height: number,
  theme: ThemeColors,
  ratio = 0.5,
): string[] {
  if (width < 3 || height <= 0) return []

  const useGutter = width >= 48
  const gutterWidth = useGutter ? 2 : 0
  const dividerWidth = 1
  const contentWidth = Math.max(2, width - dividerWidth - gutterWidth)
  const leftWidth = Math.max(1, Math.floor(contentWidth * ratio))
  const rightWidth = Math.max(1, contentWidth - leftWidth)
  const leftGap = useGutter ? " " : ""
  const rightGap = useGutter ? " " : ""

  const lines: string[] = []

  for (let i = 0; i < height; i++) {
    const leftContent = i < leftLines.length ? leftLines[i] : ""
    const rightContent = i < rightLines.length ? rightLines[i] : ""

    const left = fitString(leftContent, leftWidth)
    const right = fitString(rightContent, rightWidth)
    const divider = `${theme.dim}\u2502${theme.reset}`

    lines.push(`${left}${leftGap}${divider}${rightGap}${right}`)
  }

  return lines
}
