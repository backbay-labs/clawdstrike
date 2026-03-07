import { fitString, visibleLength } from "./types"

export function centerLine(line: string, width: number): string {
  const padding = Math.max(0, Math.floor((width - visibleLength(line)) / 2))
  return `${" ".repeat(padding)}${line}`
}

export function centerBlock(lines: string[], width: number): string[] {
  if (lines.length === 0) {
    return []
  }

  const blockWidth = Math.max(...lines.map((line) => visibleLength(line)))
  const padding = Math.max(0, Math.floor((width - blockWidth) / 2))
  return lines.map((line) => `${" ".repeat(padding)}${line}`)
}

export function joinColumns(left: string, right: string, width: number): string {
  const rightWidth = visibleLength(right)
  if (rightWidth >= width) {
    return fitString(right, width)
  }

  return `${fitString(left, width - rightWidth)}${right}`
}

export function wrapText(text: string, width: number): string[] {
  if (width <= 0) {
    return [""]
  }

  const words = text.trim().split(/\s+/).filter(Boolean)
  if (words.length === 0) {
    return [""]
  }

  const lines: string[] = []
  let current = ""

  for (const word of words) {
    if (!current) {
      current = word
      continue
    }

    if (visibleLength(`${current} ${word}`) <= width) {
      current = `${current} ${word}`
      continue
    }

    lines.push(current)
    current = word
  }

  if (current) {
    lines.push(current)
  }

  return lines
}
