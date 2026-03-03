/**
 * Scrollable list component with selection highlight and scroll indicators.
 */

import type { ThemeColors } from "./types"
import { fitString } from "./types"

export interface ListItem {
  label: string
  plainLength: number
  key?: string
}

export interface ListViewport {
  offset: number
  selected: number
}

export function renderList(
  items: ListItem[],
  viewport: ListViewport,
  height: number,
  width: number,
  theme: ThemeColors,
): string[] {
  if (height <= 0 || width <= 0) return []
  if (items.length === 0) {
    const empty = fitString(`${theme.muted}  (empty)${theme.reset}`, width)
    const lines: string[] = [empty]
    for (let i = 1; i < height; i++) lines.push(" ".repeat(width))
    return lines
  }

  const hasMoreAbove = viewport.offset > 0
  const hasMoreBelow = viewport.offset + height < items.length

  // Reserve lines for scroll indicators
  const indicatorLines = (hasMoreAbove ? 1 : 0) + (hasMoreBelow ? 1 : 0)
  const visibleHeight = height - indicatorLines

  const lines: string[] = []

  if (hasMoreAbove) {
    lines.push(fitString(`${theme.dim}  \u25B2 more${theme.reset}`, width))
  }

  for (let i = 0; i < visibleHeight; i++) {
    const idx = viewport.offset + i
    if (idx >= items.length) {
      lines.push(" ".repeat(width))
      continue
    }
    const item = items[idx]
    const isSelected = idx === viewport.selected
    if (isSelected) {
      const marker = `${theme.accent}${theme.bold} \u25B8 ${theme.reset}`
      const label = `${theme.white}${theme.bold}${item.label}${theme.reset}`
      lines.push(fitString(`${marker}${label}`, width))
    } else {
      lines.push(fitString(`   ${item.label}`, width))
    }
  }

  if (hasMoreBelow) {
    lines.push(fitString(`${theme.dim}  \u25BC more${theme.reset}`, width))
  }

  // Pad to fill height
  while (lines.length < height) {
    lines.push(" ".repeat(width))
  }

  return lines
}

export function scrollUp(viewport: ListViewport): ListViewport {
  const newSelected = Math.max(0, viewport.selected - 1)
  const newOffset = newSelected < viewport.offset ? newSelected : viewport.offset
  return { offset: newOffset, selected: newSelected }
}

export function scrollDown(
  viewport: ListViewport,
  itemCount: number,
  viewportHeight: number,
): ListViewport {
  const newSelected = Math.min(itemCount - 1, viewport.selected + 1)
  // Account for scroll indicator taking a line
  const effectiveHeight = viewportHeight - (viewport.offset > 0 ? 1 : 0) - 1 // reserve for bottom indicator
  const maxVisible = viewport.offset + Math.max(1, effectiveHeight) - 1
  const newOffset = newSelected > maxVisible ? viewport.offset + 1 : viewport.offset
  return { offset: newOffset, selected: newSelected }
}
