/**
 * Hunt Diff Screen - Scan change detection between current and previous scans.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { ScanPathResult, ServerScanResult, ServerChange, ScanDiff, ChangeKind } from "../../hunt/types"
import { runScan } from "../../hunt/bridge-scan"
import { renderList, scrollUp, scrollDown, type ListItem } from "../components/scrollable-list"
import { renderSplit } from "../components/split-pane"
import { renderBox } from "../components/box"
import { fitString } from "../components/types"
import { readFile, writeFile, mkdir } from "node:fs/promises"
import { homedir } from "node:os"
import { join } from "node:path"

const HISTORY_PATH = join(homedir(), ".clawdstrike", "scan_history.json")

const CHANGE_COLORS: Record<ChangeKind, string> = {
  added: THEME.success,
  removed: THEME.error,
  modified: THEME.warning,
}

const CHANGE_ICONS: Record<ChangeKind, string> = {
  added: "+",
  removed: "-",
  modified: "~",
}

async function loadPreviousScan(): Promise<ScanPathResult[]> {
  try {
    const raw = await readFile(HISTORY_PATH, "utf-8")
    const data = JSON.parse(raw)
    return Array.isArray(data) ? data : []
  } catch {
    return []
  }
}

async function saveScanHistory(results: ScanPathResult[]): Promise<void> {
  try {
    const dir = join(homedir(), ".clawdstrike")
    await mkdir(dir, { recursive: true })
    await writeFile(HISTORY_PATH, JSON.stringify(results, null, 2), "utf-8")
  } catch {
    // Best-effort save
  }
}

function computeDiff(previous: ScanPathResult[], current: ScanPathResult[]): ScanDiff {
  const prevServers = new Map<string, ServerScanResult>()
  const currServers = new Map<string, ServerScanResult>()

  for (const p of previous) {
    for (const s of p.servers) prevServers.set(s.name, s)
  }
  for (const c of current) {
    for (const s of c.servers) currServers.set(s.name, s)
  }

  const changes: ServerChange[] = []
  let added = 0
  let removed = 0
  let modified = 0

  // Find added and modified
  for (const [name, curr] of currServers) {
    const prev = prevServers.get(name)
    if (!prev) {
      changes.push({ server_name: name, kind: "added", new: curr })
      added++
    } else {
      const prevTools = new Set((prev.signature?.tools ?? []).map((t: { name: string }) => t.name))
      const currTools = new Set((curr.signature?.tools ?? []).map((t: { name: string }) => t.name))
      const addedTools = [...currTools].filter((t): t is string => !prevTools.has(t as string)) as string[]
      const removedTools = [...prevTools].filter((t): t is string => !currTools.has(t as string)) as string[]
      if (addedTools.length > 0 || removedTools.length > 0) {
        changes.push({
          server_name: name,
          kind: "modified",
          old: prev,
          new: curr,
          tool_changes: { added: addedTools, removed: removedTools },
        })
        modified++
      }
    }
  }

  // Find removed
  for (const [name, prev] of prevServers) {
    if (!currServers.has(name)) {
      changes.push({ server_name: name, kind: "removed", old: prev })
      removed++
    }
  }

  return {
    timestamp: new Date().toISOString(),
    changes,
    summary: { added, removed, modified },
  }
}

function buildChangeItems(diff: ScanDiff): ListItem[] {
  return diff.changes.map((c) => {
    const color = CHANGE_COLORS[c.kind]
    const icon = CHANGE_ICONS[c.kind]
    const label = `${color}[${icon}]${THEME.reset} ${THEME.white}${c.server_name}${THEME.reset} ${THEME.dim}(${c.kind})${THEME.reset}`
    const plainLength = `[${icon}] ${c.server_name} (${c.kind})`.length
    return { label, plainLength }
  })
}

function renderScanSummary(label: string, results: ScanPathResult[], theme: typeof THEME): string[] {
  const lines: string[] = []
  lines.push(`${theme.secondary}${theme.bold}${label}${theme.reset}`)
  lines.push("")

  if (results.length === 0) {
    lines.push(`${theme.muted}  No scan data${theme.reset}`)
    return lines
  }

  let totalServers = 0
  let totalTools = 0
  let totalIssues = 0

  for (const r of results) {
    for (const s of r.servers) {
      totalServers++
      totalTools += s.signature?.tools.length ?? 0
      totalIssues += s.issues.length
    }
  }

  lines.push(`${theme.muted}Servers:${theme.reset} ${theme.white}${totalServers}${theme.reset}`)
  lines.push(`${theme.muted}Tools:${theme.reset}   ${theme.white}${totalTools}${theme.reset}`)
  lines.push(`${theme.muted}Issues:${theme.reset}  ${theme.white}${totalIssues}${theme.reset}`)
  lines.push("")

  for (const r of results) {
    for (const s of r.servers) {
      const toolCount = s.signature?.tools.length ?? 0
      lines.push(`  ${theme.white}${s.name}${theme.reset} ${theme.dim}(${toolCount} tools)${theme.reset}`)
    }
  }

  return lines
}

async function performScan(ctx: ScreenContext): Promise<void> {
  const d = ctx.state.hunt.diff
  ctx.state.hunt.diff = { ...d, loading: true, error: null }
  ctx.app.render()

  try {
    const previous = await loadPreviousScan()
    const current = await runScan()
    const diff = computeDiff(previous, current)

    ctx.state.hunt.diff = {
      ...ctx.state.hunt.diff,
      current,
      previous,
      diff,
      loading: false,
      list: { offset: 0, selected: 0 },
      expandedServer: null,
    }

    // Save current for next diff
    await saveScanHistory(current)
    ctx.app.render()
  } catch (err) {
    ctx.state.hunt.diff = {
      ...ctx.state.hunt.diff,
      loading: false,
      error: err instanceof Error ? err.message : String(err),
    }
    ctx.app.render()
  }
}

export const huntDiffScreen: Screen = {
  onEnter(ctx: ScreenContext): void {
    const d = ctx.state.hunt.diff
    if (d.loading) return
    performScan(ctx)
  },

  render(ctx: ScreenContext): string {
    const { state, width, height } = ctx
    const d = state.hunt.diff
    const lines: string[] = []

    // Title bar
    const title = `${THEME.accent}${THEME.bold} HUNT ${THEME.reset}${THEME.dim} // ${THEME.reset}${THEME.secondary}Scan Diff${THEME.reset}`
    lines.push(fitString(title, width))
    lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))

    // Loading state
    if (d.loading) {
      const spinChars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
      const spinner = spinChars[state.animationFrame % spinChars.length]
      const msgY = Math.floor(height / 2) - 2
      for (let i = lines.length; i < msgY; i++) lines.push(" ".repeat(width))
      lines.push(fitString(`${THEME.secondary}  ${spinner} Scanning MCP servers...${THEME.reset}`, width))
      for (let i = lines.length; i < height - 1; i++) lines.push(" ".repeat(width))
      lines.push(renderHelpBar(width))
      return lines.join("\n")
    }

    // Error state
    if (d.error) {
      const msgY = Math.floor(height / 2) - 2
      for (let i = lines.length; i < msgY; i++) lines.push(" ".repeat(width))
      lines.push(fitString(`${THEME.error}  Error: ${d.error}${THEME.reset}`, width))
      lines.push(fitString(`${THEME.dim}  Press r to retry.${THEME.reset}`, width))
      for (let i = lines.length; i < height - 1; i++) lines.push(" ".repeat(width))
      lines.push(renderHelpBar(width))
      return lines.join("\n")
    }

    // No previous scan
    if (d.previous.length === 0 && d.diff) {
      lines.push(fitString(`${THEME.muted}  First scan recorded. No previous data to compare.${THEME.reset}`, width))
      lines.push(fitString(`${THEME.dim}  Run again later to detect changes.${THEME.reset}`, width))
      lines.push("")

      // Show current scan summary
      const summaryLines = renderScanSummary("Current Scan", d.current, THEME)
      for (const sl of summaryLines) {
        lines.push(fitString(`  ${sl}`, width))
      }

      for (let i = lines.length; i < height - 1; i++) lines.push(" ".repeat(width))
      lines.push(renderHelpBar(width))
      return lines.join("\n")
    }

    if (!d.diff) {
      for (let i = lines.length; i < height - 1; i++) lines.push(" ".repeat(width))
      lines.push(renderHelpBar(width))
      return lines.join("\n")
    }

    // Summary line
    const s = d.diff.summary
    const summaryText =
      `${THEME.muted}Changes:${THEME.reset} ` +
      `${THEME.success}+${s.added}${THEME.reset} ` +
      `${THEME.error}-${s.removed}${THEME.reset} ` +
      `${THEME.warning}~${s.modified}${THEME.reset}`
    lines.push(fitString(`  ${summaryText}`, width))
    lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))

    const helpLines = 1
    const headerLines = lines.length
    const availableHeight = height - headerLines - helpLines

    if (d.expandedServer !== null) {
      // Show expanded server detail
      const change = d.diff.changes.find((c) => c.server_name === d.expandedServer)
      if (change) {
        // Split: left=previous, right=current summaries, bottom=tool diff
        const splitHeight = Math.min(8, Math.floor(availableHeight * 0.35))
        const leftLines: string[] = []
        const rightLines: string[] = []

        leftLines.push(`${THEME.muted}Previous${THEME.reset}`)
        rightLines.push(`${THEME.muted}Current${THEME.reset}`)

        if (change.old) {
          const toolCount = change.old.signature?.tools.length ?? 0
          leftLines.push(`${THEME.white}${change.old.name}${THEME.reset}`)
          leftLines.push(`${THEME.dim}Tools: ${toolCount}${THEME.reset}`)
          leftLines.push(`${THEME.dim}Command: ${change.old.command}${THEME.reset}`)
        } else {
          leftLines.push(`${THEME.dim}(not present)${THEME.reset}`)
        }

        if (change.new) {
          const toolCount = change.new.signature?.tools.length ?? 0
          rightLines.push(`${THEME.white}${change.new.name}${THEME.reset}`)
          rightLines.push(`${THEME.dim}Tools: ${toolCount}${THEME.reset}`)
          rightLines.push(`${THEME.dim}Command: ${change.new.command}${THEME.reset}`)
        } else {
          rightLines.push(`${THEME.dim}(not present)${THEME.reset}`)
        }

        const splitLines = renderSplit(leftLines, rightLines, width, splitHeight, THEME)
        for (const sl of splitLines) lines.push(sl)

        // Tool changes detail
        if (change.tool_changes) {
          const detailContent: string[] = []
          if (change.tool_changes.added.length > 0) {
            detailContent.push(`${THEME.success}Added tools:${THEME.reset}`)
            for (const t of change.tool_changes.added) {
              detailContent.push(`  ${THEME.success}+ ${t}${THEME.reset}`)
            }
          }
          if (change.tool_changes.removed.length > 0) {
            detailContent.push(`${THEME.error}Removed tools:${THEME.reset}`)
            for (const t of change.tool_changes.removed) {
              detailContent.push(`  ${THEME.error}- ${t}${THEME.reset}`)
            }
          }
          const boxLines = renderBox("Tool Changes", detailContent, width, THEME, { style: "rounded" })
          for (const bl of boxLines) lines.push(bl)
        }
      }
    } else {
      // Change list
      if (d.diff.changes.length === 0) {
        const msgY = Math.floor(availableHeight / 2)
        for (let i = 0; i < msgY; i++) lines.push(" ".repeat(width))
        lines.push(fitString(`${THEME.muted}  No changes detected between scans.${THEME.reset}`, width))
      } else {
        const items = buildChangeItems(d.diff)
        const listLines = renderList(items, d.list, availableHeight, width, THEME)
        for (const l of listLines) lines.push(l)
      }
    }

    // Help bar
    lines.push(renderHelpBar(width))

    // Pad to fill
    while (lines.length < height) lines.push(" ".repeat(width))

    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const d = ctx.state.hunt.diff
    if (d.loading) {
      if (key === "\x1b" || key === "\x1b\x1b" || key === "q") {
        ctx.app.setScreen("main")
        return true
      }
      return false
    }

    // Navigation
    if (key === "\x1b" || key === "\x1b\x1b" || key === "q") {
      if (d.expandedServer !== null) {
        ctx.state.hunt.diff = { ...d, expandedServer: null }
        return true
      }
      ctx.app.setScreen("main")
      return true
    }

    if (!d.diff) return false
    const changeCount = d.diff.changes.length

    // Scroll
    if (key === "j" || key === "down") {
      if (changeCount > 0 && d.expandedServer === null) {
        ctx.state.hunt.diff = {
          ...d,
          list: scrollDown(d.list, changeCount, ctx.height - 8),
        }
      }
      return true
    }
    if (key === "k" || key === "up") {
      if (changeCount > 0 && d.expandedServer === null) {
        ctx.state.hunt.diff = {
          ...d,
          list: scrollUp(d.list),
        }
      }
      return true
    }

    // Expand/collapse server
    if (key === "\r" || key === "return") {
      if (changeCount > 0) {
        if (d.expandedServer !== null) {
          ctx.state.hunt.diff = { ...d, expandedServer: null }
        } else {
          const change = d.diff.changes[d.list.selected]
          if (change) {
            ctx.state.hunt.diff = { ...d, expandedServer: change.server_name }
          }
        }
      }
      return true
    }

    // Rescan
    if (key === "r") {
      performScan(ctx)
      return true
    }

    return false
  },
}

function renderHelpBar(width: number): string {
  const help =
    `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}  ` +
    `${THEME.dim}j/k${THEME.reset}${THEME.muted} navigate${THEME.reset}  ` +
    `${THEME.dim}enter${THEME.reset}${THEME.muted} expand${THEME.reset}  ` +
    `${THEME.dim}r${THEME.reset}${THEME.muted} rescan${THEME.reset}`
  return fitString(help, width)
}
