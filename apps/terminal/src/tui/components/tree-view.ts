/**
 * Tree view component with expandable nodes and tree-drawing characters.
 */

import type { ThemeColors } from "./types"
import { fitString } from "./types"

export interface TreeNode {
  label: string
  plainLength: number
  key: string
  children?: TreeNode[]
  expanded?: boolean
  icon?: string
  color?: string
}

export interface TreeViewport {
  offset: number
  selected: number
  expandedKeys: Set<string>
}

interface FlatEntry {
  node: TreeNode
  depth: number
}

export function flattenTree(
  nodes: TreeNode[],
  expandedKeys: Set<string>,
): FlatEntry[] {
  const result: FlatEntry[] = []
  function walk(list: TreeNode[], depth: number) {
    for (const node of list) {
      result.push({ node, depth })
      if (node.children && node.children.length > 0 && expandedKeys.has(node.key)) {
        walk(node.children, depth + 1)
      }
    }
  }
  walk(nodes, 0)
  return result
}

export function renderTree(
  nodes: TreeNode[],
  viewport: TreeViewport,
  height: number,
  width: number,
  theme: ThemeColors,
): string[] {
  if (height <= 0 || width <= 0) return []
  const flat = flattenTree(nodes, viewport.expandedKeys)
  if (flat.length === 0) {
    const lines = [fitString(`${theme.muted}  (empty)${theme.reset}`, width)]
    for (let i = 1; i < height; i++) lines.push(" ".repeat(width))
    return lines
  }

  const hasMoreAbove = viewport.offset > 0
  const hasMoreBelow = viewport.offset + height < flat.length
  const indicatorLines = (hasMoreAbove ? 1 : 0) + (hasMoreBelow ? 1 : 0)
  const visibleHeight = height - indicatorLines

  const lines: string[] = []

  if (hasMoreAbove) {
    lines.push(fitString(`${theme.dim}  \u25B2 more${theme.reset}`, width))
  }

  for (let i = 0; i < visibleHeight; i++) {
    const idx = viewport.offset + i
    if (idx >= flat.length) {
      lines.push(" ".repeat(width))
      continue
    }
    const { node, depth } = flat[idx]
    const isSelected = idx === viewport.selected
    const hasChildren = node.children && node.children.length > 0
    const isExpanded = viewport.expandedKeys.has(node.key)

    // Build indent with tree characters
    const indent = depth > 0 ? "  ".repeat(depth - 1) + "\u251C\u2500\u2500 " : ""

    // Expand/collapse indicator
    let indicator = "  "
    if (hasChildren) {
      indicator = isExpanded ? `${theme.secondary}\u25BE ${theme.reset}` : `${theme.muted}\u25B8 ${theme.reset}`
    }

    // Icon
    const icon = node.icon ? `${node.icon} ` : ""

    // Color
    const labelColor = node.color ?? theme.white

    // Selection highlight
    const prefix = isSelected
      ? `${theme.accent}${theme.bold}\u25B8${theme.reset} `
      : "  "

    const line = `${prefix}${theme.dim}${indent}${theme.reset}${indicator}${labelColor}${icon}${node.label}${theme.reset}`
    lines.push(fitString(line, width))
  }

  if (hasMoreBelow) {
    lines.push(fitString(`${theme.dim}  \u25BC more${theme.reset}`, width))
  }

  while (lines.length < height) {
    lines.push(" ".repeat(width))
  }

  return lines
}

export function toggleExpand(viewport: TreeViewport, key: string): TreeViewport {
  const newExpanded = new Set(viewport.expandedKeys)
  if (newExpanded.has(key)) {
    newExpanded.delete(key)
  } else {
    newExpanded.add(key)
  }
  return { ...viewport, expandedKeys: newExpanded }
}

export function moveUp(viewport: TreeViewport): TreeViewport {
  const newSelected = Math.max(0, viewport.selected - 1)
  const newOffset = newSelected < viewport.offset ? newSelected : viewport.offset
  return { ...viewport, offset: newOffset, selected: newSelected }
}

export function moveDown(
  viewport: TreeViewport,
  visibleCount: number,
  viewportHeight: number,
): TreeViewport {
  const newSelected = Math.min(visibleCount - 1, viewport.selected + 1)
  const maxVisible = viewport.offset + viewportHeight - 1
  const newOffset = newSelected > maxVisible ? viewport.offset + 1 : viewport.offset
  return { ...viewport, offset: newOffset, selected: newSelected }
}
