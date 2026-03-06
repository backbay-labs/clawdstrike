/**
 * Hunt Scan Screen - MCP Scan Explorer
 *
 * Tree view (left 60%) showing scanned paths/clients/servers/tools,
 * with a detail pane (right 40%) for selected node info.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { TreeNode } from "../components/tree-view"
import { basename } from "path"
import {
  renderTree,
  flattenTree,
  toggleExpand,
  moveUp,
  moveDown,
} from "../components/tree-view"
import { renderBox } from "../components/box"
import { renderSplit } from "../components/split-pane"
import { centerBlock, centerLine, wrapText } from "../components/layout"
import { fitString } from "../components/types"
import { renderSurfaceHeader } from "../components/surface-header"
import { runScan } from "../../hunt/bridge-scan"
import type { ScanPathResult, ServerScanResult } from "../../hunt/types"
import { updateInvestigation } from "../investigation"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function serverStatusColor(srv: ServerScanResult): string {
  if (srv.violations.length > 0) return THEME.error
  if (srv.error) return THEME.error
  if (srv.issues.length > 0) return THEME.warning
  return THEME.success
}

function summarizePath(result: ScanPathResult): string {
  const serverCount = result.servers.length
  const issueCount =
    result.issues.length +
    result.servers.reduce((sum, srv) => sum + srv.issues.length, 0)
  const violationCount = result.servers.reduce((sum, srv) => sum + srv.violations.length, 0)
  const pathErrors = result.errors.length + result.servers.filter((srv) => !!srv.error).length
  const summary: string[] = []

  if (serverCount > 0) summary.push(`${serverCount}s`)
  if (issueCount > 0) summary.push(`${issueCount}i`)
  if (violationCount > 0) summary.push(`${violationCount}v`)
  if (pathErrors > 0) summary.push(`${pathErrors}e`)

  return summary.length > 0 ? ` ${THEME.dim}${summary.join(" ")}${THEME.reset}` : ""
}

function summarizeServer(srv: ServerScanResult): string {
  const summary: string[] = []

  if (srv.violations.length > 0) summary.push(`${srv.violations.length}v`)
  if (srv.issues.length > 0) summary.push(`${srv.issues.length}i`)
  if (srv.error) summary.push("err")

  return summary.length > 0 ? ` ${THEME.dim}${summary.join(" ")}${THEME.reset}` : ""
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
        label: `${srv.name}${summarizeServer(srv)}`,
        plainLength: srv.name.length + summarizeServer(srv).replace(/\x1b\[[0-9;]*m/g, "").length,
        key: `${r.path}:${srv.name}`,
        icon: "\u25CF",
        color: serverStatusColor(srv),
        children,
      }
    })

    const pathLabel = basename(r.path) || r.path
    const summary = summarizePath(r)
    const label = `${r.client} \u00B7 ${pathLabel}${summary}`
    const plainLength = `${r.client} \u00B7 ${pathLabel}${summary.replace(/\x1b\[[0-9;]*m/g, "")}`.length

    return {
      label,
      plainLength,
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

function collectFindings(results: ScanPathResult[]): string[] {
  const findings: string[] = []

  for (const result of results) {
    for (const issue of result.issues) {
      findings.push(`${basename(result.path) || result.path}: [${issue.severity}] ${issue.message}`)
    }
    for (const server of result.servers) {
      for (const violation of server.violations) {
        findings.push(`${server.name}: ${violation.guard} blocked ${violation.target}`)
      }
      for (const issue of server.issues) {
        findings.push(`${server.name}: [${issue.severity}] ${issue.message}`)
      }
    }
  }

  return findings.slice(0, 12)
}

function renderScanStateCard(
  title: string,
  body: string[],
  width: number,
  bodyHeight: number,
  footer: string,
): string[] {
  const boxWidth = Math.min(96, width - 6)
  const innerWidth = boxWidth - 4
  const content = body.flatMap((line) => wrapText(line, innerWidth))
  const card = renderBox(title, content, boxWidth, THEME, {
    style: "rounded",
    titleAlign: "left",
    padding: 1,
  })
  const lines: string[] = []
  const startY = Math.max(1, Math.floor((bodyHeight - card.length - 2) / 2))
  while (lines.length < startY) lines.push(" ".repeat(width))
  lines.push(...centerBlock(card, width))
  while (lines.length < bodyHeight - 1) lines.push(" ".repeat(width))
  lines.push(centerLine(footer, width))
  return lines
}

function renderDetail(
  results: ScanPathResult[],
  selectedKey: string | null,
  height: number,
  width: number,
): string[] {
  const lines: string[] = []
  const valueWidth = Math.max(16, width - 4)

  function pushField(label: string, value: string, color = THEME.muted) {
    const wrapped = wrapText(value, Math.max(12, valueWidth - label.length - 2))
    const head = wrapped.shift() ?? ""
    lines.push(fitString(`${color}  ${label}:${THEME.reset} ${head}`, width))
    for (const line of wrapped) {
      lines.push(fitString(`${" ".repeat(label.length + 4)}${THEME.white}${line}${THEME.reset}`, width))
    }
  }

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
      pushField("Path", pathResult.path)
      lines.push(fitString(
        `${THEME.muted}  Servers:${THEME.reset} ${pathResult.servers.length}  ` +
          `${THEME.muted}Issues:${THEME.reset} ${pathResult.issues.length + pathResult.servers.reduce((sum, srv) => sum + srv.issues.length, 0)}  ` +
          `${THEME.muted}Violations:${THEME.reset} ${pathResult.servers.reduce((sum, srv) => sum + srv.violations.length, 0)}`,
        width,
      ))
      if (pathResult.issues.length > 0) {
        lines.push(fitString("", width))
        lines.push(fitString(`${THEME.warning}  Path Issues:${THEME.reset}`, width))
        for (const issue of pathResult.issues) {
          pushField("Issue", `[${issue.severity}] ${issue.message}`, THEME.warning)
        }
      }
      if (pathResult.errors.length > 0) {
        lines.push(fitString("", width))
        lines.push(fitString(`${THEME.error}  Errors:${THEME.reset}`, width))
        for (const e of pathResult.errors) {
          pushField("File", e.path, THEME.error)
          pushField("Reason", e.error, THEME.dim)
        }
      }
    } else {
      lines.push(fitString(`${THEME.muted}  No details for selection${THEME.reset}`, width))
    }
    while (lines.length < height) lines.push(" ".repeat(width))
    return lines
  }

  const { path, server: srv } = match
  lines.push(fitString(`${THEME.secondary}${THEME.bold}  ${srv.name}${THEME.reset}`, width))
  pushField("Config", path.path)
  pushField("Command", `${srv.command}${srv.args ? ` ${srv.args.join(" ")}` : ""}`)

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
      lines.push(fitString(`${THEME.warning}    [${iss.severity}] ${iss.code}${THEME.reset}`, width))
      pushField("Message", iss.message, THEME.warning)
      if (iss.detail) {
        pushField("Detail", iss.detail, THEME.dim)
      }
    }
  }

  if (srv.error) {
    lines.push(fitString("", width))
    pushField("Error", srv.error, THEME.error)
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

    lines.push(...renderSurfaceHeader("hunt-scan", "MCP Scan Explorer", width, THEME))

    if (scan.loading) {
      const spinChars = ["\u2847", "\u2846", "\u2834", "\u2831", "\u2839", "\u283B", "\u283F", "\u2857"]
      const frame = ctx.state.animationFrame % spinChars.length
      const bodyHeight = Math.max(6, height - lines.length)
      lines.push(...renderScanStateCard(
        "Scan In Progress",
        [
          `Scanning MCP configurations from the current workstation.`,
          `${spinChars[frame]} collecting clients, servers, signatures, issues, and violations`,
        ],
        width,
        bodyHeight,
        `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`,
      ))
      return lines.join("\n")
    }

    if (scan.error) {
      const bodyHeight = Math.max(6, height - lines.length)
      lines.push(...renderScanStateCard(
        "Scan Failed",
        [
          `${THEME.error}The MCP scan did not complete.${THEME.reset}`,
          scan.error,
        ],
        width,
        bodyHeight,
        `${THEME.dim}r${THEME.reset}${THEME.muted} rescan${THEME.reset}  ${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`,
      ))
      return lines.join("\n")
    }

    if (scan.results.length === 0) {
      const bodyHeight = Math.max(6, height - lines.length)
      lines.push(...renderScanStateCard(
        "No Scan Results",
        [
          `No MCP configurations were discovered from the current working directory.`,
          `Run the scan from a machine with MCP clients configured, or rescan after starting the local agent runtime.`,
        ],
        width,
        bodyHeight,
        `${THEME.dim}r${THEME.reset}${THEME.muted} rescan${THEME.reset}  ${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}`,
      ))
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
    const footer = `${THEME.muted}  j/k navigate  Enter expand/collapse  e report  r rescan  ESC back${THEME.reset}`
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

    if (key === "e") {
      ctx.state.hunt.report.returnScreen = "hunt-scan"
      ctx.app.setScreen("hunt-report")
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
    updateInvestigation(ctx.state, {
      origin: "scan",
      title: "MCP Scan Explorer",
      summary: `${results.length} path(s) scanned for MCP exposure and policy drift.`,
      findings: collectFindings(results),
      events: [],
      query: null,
    })
  } catch (err) {
    ctx.state.hunt.scan.error = err instanceof Error ? err.message : String(err)
    ctx.state.hunt.scan.loading = false
  }
  ctx.app.render()
}
