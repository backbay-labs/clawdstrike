/**
 * Grid / heatmap component - renders a grid with color-intensity cells.
 */

import type { ThemeColors } from "./types"
import { fitString } from "./types"

export interface GridCell {
  value: number
  label?: string
}

export interface GridSelection {
  row: number
  col: number
}

const BLOCKS = [" ", "\u2591", "\u2592", "\u2593", "\u2588"]

function valueToBlock(value: number, maxValue: number): string {
  if (maxValue <= 0 || value <= 0) return BLOCKS[0]
  const normalized = Math.min(value / maxValue, 1)
  const idx = Math.min(Math.floor(normalized * (BLOCKS.length - 1)) + 1, BLOCKS.length - 1)
  return BLOCKS[idx]
}

function valueToColor(value: number, maxValue: number, theme: ThemeColors): string {
  if (value <= 0) return theme.dim
  const ratio = maxValue > 0 ? Math.min(value / maxValue, 1) : 0
  if (ratio < 0.25) return theme.dim
  if (ratio < 0.5) return theme.muted
  if (ratio < 0.75) return theme.warning
  return theme.accent
}

export function renderGrid(
  columns: string[],
  rows: string[],
  cells: GridCell[][],
  selected: GridSelection | null,
  width: number,
  height: number,
  theme: ThemeColors,
): string[] {
  if (width <= 0 || height <= 0 || columns.length === 0 || rows.length === 0) return []

  // Find max value for color scaling
  let maxValue = 0
  for (const row of cells) {
    for (const cell of row) {
      if (cell.value > maxValue) maxValue = cell.value
    }
  }

  // Calculate column widths
  const rowHeaderWidth = Math.min(
    Math.max(...rows.map((r) => r.length), 4) + 1,
    Math.floor(width * 0.3),
  )
  const remainingWidth = width - rowHeaderWidth
  const cellWidth = Math.max(3, Math.floor(remainingWidth / columns.length))

  const lines: string[] = []

  // Column headers
  let headerLine = " ".repeat(rowHeaderWidth)
  for (const col of columns) {
    const truncCol = col.length > cellWidth - 1 ? col.slice(0, cellWidth - 1) : col
    headerLine += fitString(`${theme.muted}${truncCol}${theme.reset}`, cellWidth)
  }
  lines.push(fitString(headerLine, width))

  // Separator
  lines.push(fitString(`${theme.dim}${"\u2500".repeat(width)}${theme.reset}`, width))

  // Rows
  for (let r = 0; r < rows.length && lines.length < height; r++) {
    const rowLabel = rows[r].length > rowHeaderWidth - 1
      ? rows[r].slice(0, rowHeaderWidth - 2) + "\u2026"
      : rows[r]
    let line = fitString(`${theme.muted}${rowLabel}${theme.reset}`, rowHeaderWidth)

    for (let c = 0; c < columns.length; c++) {
      const cell = cells[r]?.[c] ?? { value: 0 }
      const block = valueToBlock(cell.value, maxValue)
      const color = valueToColor(cell.value, maxValue, theme)
      const isSelected = selected !== null && selected.row === r && selected.col === c

      let cellStr: string
      if (cell.label) {
        cellStr = `${color}${block}${cell.label}${theme.reset}`
      } else {
        cellStr = `${color}${block.repeat(Math.max(1, cellWidth - 1))}${theme.reset}`
      }

      if (isSelected) {
        cellStr = `${theme.bold}${theme.accent}[${theme.reset}${cellStr}${theme.bold}${theme.accent}]${theme.reset}`
      }

      line += fitString(cellStr, cellWidth)
    }

    lines.push(fitString(line, width))
  }

  // Pad to height
  while (lines.length < height) {
    lines.push(" ".repeat(width))
  }

  return lines
}

export function moveSelection(
  sel: GridSelection,
  direction: "up" | "down" | "left" | "right",
  rowCount: number,
  colCount: number,
): GridSelection {
  switch (direction) {
    case "up":
      return { ...sel, row: Math.max(0, sel.row - 1) }
    case "down":
      return { ...sel, row: Math.min(rowCount - 1, sel.row + 1) }
    case "left":
      return { ...sel, col: Math.max(0, sel.col - 1) }
    case "right":
      return { ...sel, col: Math.min(colCount - 1, sel.col + 1) }
  }
}
