/**
 * Hunt Scan Screen - MCP Scan Explorer
 *
 * Tree view (left 60%) showing scanned paths/clients/servers/tools,
 * with a detail pane (right 40%) for selected node info.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { TreeNode } from "../components/tree-view"
import {
  renderTree,
  flattenTree,
  toggleExpand,
  moveUp,
  moveDown,
} from "../components/tree-view"
import { renderSplit } from "../components/split-pane"
import { fitString } from "../components/types"
import { runScan } from "../../hunt/bridge-scan"
import type { ScanPathResult, ServerScanResult } from "../../hunt/types"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function serverStatusColor(srv: ServerScanResult): string {
  if (srv.violations.length > 0) return THEME.error
  if (srv.issues.length > 0) return THEME.warning
  return THEME.success
}

function buildTreeNodes(results: ScanPathResult[]): TreeNode[] {
  return results.map((r) => {
    const serverNodes: TreeNode[] = r.servers.map((srv) => {
      const children: TreeNode[] = []

      if (srv.signature) {
        if (srv.signature.tools.length > 0) {
          children.push({
            label: `Tools (${srv.signature.tools.length})`,
            plainLength: `Tools (${srv.signature.tools.length})`.length,
            key: `${r.path}:${srv.name}:tools`,
            icon: "\u2699",
            color: THEME.muted,
            children: srv.signature.tools.map((t) => ({
              label: t.name,
              plainLength: t.name.length,
              key: `${r.path}:${srv.name}:tool:${t.name}`,
              color: THEME.white,
            })),
          })
        }
        if (srv.signature.prompts.length > 0) {
          children.push({
            label: `Prompts (${srv.signature.prompts.length})`,
            plainLength: `Prompts (${srv.signature.prompts.length})`.length,
            key: `${r.path}:${srv.name}:prompts`,
            icon: "\u270E",
            color: THEME.muted,
            children: srv.signature.prompts.map((p) => ({
              label: p,
              plainLength: p.length,
              key: `${r.path}:${srv.name}:prompt:${p}`,
              color: THEME.white,
            })),
          })
        }
        if (srv.signature.resources.length > 0) {
          children.push({
            label: `Resources (${srv.signature.resources.length})`,
            plainLength: `Resources (${srv.signature.resources.length})`.length,
            key: `${r.path}:${srv.name}:resources`,
            icon: "\u2691",
            color: THEME.muted,
            children: srv.signature.resources.map((res) => ({
              label: res,
              plainLength: res.length,
              key: `${r.path}:${srv.name}:resource:${res}`,
              color: THEME.white,
            })),
          })
        }
      }

      if (srv.violations.length > 0) {
        children.push({
          label: `Violations (${srv.violations.length})`,
          plainLength: `Violations (${srv.violations.length})`.length,
          key: `${r.path}:${srv.name}:violations`,
          icon: "\u2716",
          color: THEME.error,
          children: srv.violations.map((v, vi) => ({
            label: `${v.guard}: ${v.target}`,
            plainLength: `${v.guard}: ${v.target}`.length,
            key: `${r.path}:${srv.name}:violation:${vi}`,
            color: THEME.error,
          })),
        })
      }

      if (srv.issues.length > 0) {
        children.push({
          label: `Issues (${srv.issues.length})`,
          plainLength: `Issues (${srv.issues.length})`.length,
          key: `${r.path}:${srv.name}:issues`,
          icon: "\u26A0",
          color: THEME.warning,
          children: srv.issues.map((iss, ii) => ({
            label: `[${iss.severity}] ${iss.message}`,
            plainLength: `[${iss.severity}] ${iss.message}`.length,
            key: `${r.path}:${srv.name}:issue:${ii}`,
            color: iss.severity === "critical" || iss.severity === "error"
              ? THEME.error
              : THEME.warning,
          })),
        })
      }

      return {
        label: srv.name,
        plainLength: srv.name.length,
        key: `${r.path}:${srv.name}`,
        icon: "\u25CF",
        color: serverStatusColor(srv),
        children,
      }
    })

    return {
      label: `${r.client} \u2014 ${r.path}`,
      plainLength: `${r.client} \u2014 ${r.path}`.length,
      key: r.path,
      icon: "\u229A",
      color: THEME.secondary,
      children: serverNodes,
    }
  })
}

function findServerForKey(
  results: ScanPathResult[],
  key: string,
): { path: ScanPathResult; server: ServerScanResult } | null {
  for (const r of results) {
    for (const srv of r.servers) {
      if (key.startsWith(`${r.path}:${srv.name}`)) {
        return { path: r, server: srv }
      }
    }
  }
  return null
}

function renderDetail(
  results: ScanPathResult[],
  selectedKey: string | null,
  height: number,
  width: number,
): string[] {
  const lines: string[] = []

  if (!selectedKey) {
    lines.push(fitString(`${THEME.muted}  Select a node to view details${THEME.reset}`, width))
    while (lines.length < height) lines.push(" ".repeat(width))
    return lines
  }

  const match = findServerForKey(results, selectedKey)
  if (!match) {
    // It's a path-level node
    const pathResult = results.find((r) => r.path === selectedKey)
    if (pathResult) {
      lines.push(fitString(`${THEME.secondary}${THEME.bold}  ${pathResult.client}${THEME.reset}`, width))
      lines.push(fitString(`${THEME.muted}  Path: ${pathResult.path}${THEME.reset}`, width))
      lines.push(fitString(`${THEME.muted}  Servers: ${pathResult.servers.length}${THEME.reset}`, width))
      if (pathResult.errors.length > 0) {
        lines.push(fitString("", width))
        lines.push(fitString(`${THEME.error}  Errors:${THEME.reset}`, width))
        for (const e of pathResult.errors) {
          lines.push(fitString(`${THEME.error}    ${e.path}: ${e.error}${THEME.reset}`, width))
        }
      }
    } else {
      lines.push(fitString(`${THEME.muted}  No details for selection${THEME.reset}`, width))
    }
    while (lines.length < height) lines.push(" ".repeat(width))
    return lines
  }

  const { server: srv } = match
  lines.push(fitString(`${THEME.secondary}${THEME.bold}  ${srv.name}${THEME.reset}`, width))
  lines.push(fitString(`${THEME.muted}  Command: ${srv.command}${srv.args ? " " + srv.args.join(" ") : ""}${THEME.reset}`, width))

  if (srv.signature) {
    lines.push(fitString("", width))
    lines.push(fitString(`${THEME.white}  Signature${THEME.reset}`, width))
    if (srv.signature.version) {
      lines.push(fitString(`${THEME.muted}    Version: ${srv.signature.version}${THEME.reset}`, width))
    }
    lines.push(fitString(`${THEME.muted}    Tools: ${srv.signature.tools.length}  Prompts: ${srv.signature.prompts.length}  Resources: ${srv.signature.resources.length}${THEME.reset}`, width))
  }

  if (srv.violations.length > 0) {
    lines.push(fitString("", width))
    lines.push(fitString(`${THEME.error}${THEME.bold}  Violations (${srv.violations.length})${THEME.reset}`, width))
    for (const v of srv.violations) {
      lines.push(fitString(`${THEME.error}    ${v.guard} \u2192 ${v.action_type} ${v.target}${THEME.reset}`, width))
      if (v.reason) {
        lines.push(fitString(`${THEME.dim}      ${v.reason}${THEME.reset}`, width))
      }
    }
  }

  if (srv.issues.length > 0) {
    lines.push(fitString("", width))
    lines.push(fitString(`${THEME.warning}${THEME.bold}  Issues (${srv.issues.length})${THEME.reset}`, width))
    for (const iss of srv.issues) {
      lines.push(fitString(`${THEME.warning}    [${iss.severity}] ${iss.code}: ${iss.message}${THEME.reset}`, width))
      if (iss.detail) {
        lines.push(fitString(`${THEME.dim}      ${iss.detail}${THEME.reset}`, width))
      }
    }
  }

  if (srv.error) {
    lines.push(fitString("", width))
    lines.push(fitString(`${THEME.error}  Error: ${srv.error}${THEME.reset}`, width))
  }

  while (lines.length < height) lines.push(" ".repeat(width))
  return lines
}

// ---------------------------------------------------------------------------
// Screen
// ---------------------------------------------------------------------------

export const huntScanScreen: Screen = {
  onEnter(ctx: ScreenContext) {
    const scan = ctx.state.hunt.scan
    if (scan.results.length === 0 && !scan.loading) {
      doScan(ctx)
    }
  },

  render(ctx: ScreenContext): string {
    const { state, width, height } = ctx
    const scan = state.hunt.scan
    const lines: string[] = []

    // Header
    const title = `${THEME.secondary}${THEME.bold} MCP Scan Explorer ${THEME.reset}`
    lines.push(fitString(title, width))
    lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))

    if (scan.loading) {
      lines.push(fitString(`${THEME.muted}  Scanning MCP configurations...${THEME.reset}`, width))
      const spinChars = ["\u2847", "\u2846", "\u2834", "\u2831", "\u2839", "\u283B", "\u283F", "\u2857"]
      const frame = ctx.state.animationFrame % spinChars.length
      lines.push(fitString(`${THEME.accent}  ${spinChars[frame]}${THEME.reset}`, width))
      while (lines.length < height - 1) lines.push(" ".repeat(width))
      lines.push(fitString(`${THEME.dim}  ESC back${THEME.reset}`, width))
      return lines.join("\n")
    }

    if (scan.error) {
      lines.push(fitString(`${THEME.error}  Error: ${scan.error}${THEME.reset}`, width))
      lines.push(fitString("", width))
      lines.push(fitString(`${THEME.muted}  r rescan  ESC back${THEME.reset}`, width))
      while (lines.length < height - 1) lines.push(" ".repeat(width))
      return lines.join("\n")
    }

    if (scan.results.length === 0) {
      lines.push(fitString(`${THEME.muted}  No MCP configurations found.${THEME.reset}`, width))
      lines.push(fitString(`${THEME.dim}  Run with MCP servers configured to see scan results.${THEME.reset}`, width))
      lines.push(fitString("", width))
      lines.push(fitString(`${THEME.muted}  r rescan  ESC back${THEME.reset}`, width))
      while (lines.length < height - 1) lines.push(" ".repeat(width))
      return lines.join("\n")
    }

    // Build tree
    const treeNodes = buildTreeNodes(scan.results)
    const contentHeight = height - 4 // header(2) + footer(1) + spacing(1)

    // Determine selected node key
    const flat = flattenTree(treeNodes, scan.tree.expandedKeys)
    const selectedNode = flat[scan.tree.selected]
    const selectedKey = selectedNode?.node.key ?? null

    // Split: tree left 60%, detail right 40%
    const leftLines = renderTree(treeNodes, scan.tree, contentHeight, Math.floor(width * 0.58), THEME)
    const rightLines = renderDetail(scan.results, selectedKey, contentHeight, Math.floor(width * 0.4))

    const splitLines = renderSplit(leftLines, rightLines, width, contentHeight, THEME, 0.6)
    lines.push(...splitLines)

    // Footer
    lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))
    const footer = `${THEME.muted}  j/k navigate  Enter expand/collapse  r rescan  ESC back${THEME.reset}`
    lines.push(fitString(footer, width))

    while (lines.length < height) lines.push(" ".repeat(width))
    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const scan = ctx.state.hunt.scan

    if (key === "\x1b" || key === "\x1b\x1b" || key === "q") {
      ctx.app.setScreen("main")
      return true
    }

    if (scan.loading) return false

    if (key === "j" || key === "down") {
      const treeNodes = buildTreeNodes(scan.results)
      const flat = flattenTree(treeNodes, scan.tree.expandedKeys)
      ctx.state.hunt.scan.tree = moveDown(scan.tree, flat.length, ctx.height - 4)
      ctx.app.render()
      return true
    }

    if (key === "k" || key === "up") {
      ctx.state.hunt.scan.tree = moveUp(scan.tree)
      ctx.app.render()
      return true
    }

    if (key === "\r" || key === "enter") {
      const treeNodes = buildTreeNodes(scan.results)
      const flat = flattenTree(treeNodes, scan.tree.expandedKeys)
      const selected = flat[scan.tree.selected]
      if (selected?.node.children && selected.node.children.length > 0) {
        ctx.state.hunt.scan.tree = toggleExpand(scan.tree, selected.node.key)
        ctx.app.render()
      }
      return true
    }

    if (key === "r") {
      doScan(ctx)
      return true
    }

    return false
  },
}

async function doScan(ctx: ScreenContext) {
  ctx.state.hunt.scan.loading = true
  ctx.state.hunt.scan.error = null
  ctx.app.render()
  try {
    const results = await runScan()
    ctx.state.hunt.scan.results = results
    ctx.state.hunt.scan.tree = { offset: 0, selected: 0, expandedKeys: new Set() }
    ctx.state.hunt.scan.loading = false
  } catch (err) {
    ctx.state.hunt.scan.error = err instanceof Error ? err.message : String(err)
    ctx.state.hunt.scan.loading = false
  }
  ctx.app.render()
}
