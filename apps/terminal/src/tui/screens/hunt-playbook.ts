/**
 * Hunt Playbook Screen - Automated playbook runner with step-by-step execution.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext } from "../types"
import type { PlaybookStep, PlaybookStepStatus } from "../../hunt/types"
import { buildDefaultPlaybook, executePlaybook, type PlaybookConfig } from "../../hunt/playbook"
import { resolveDefaultWatchRules } from "../../hunt/bridge"
import { renderList, type ListItem } from "../components/scrollable-list"
import { renderSplit } from "../components/split-pane"
import { renderBox } from "../components/box"
import { fitString } from "../components/types"
import { renderSurfaceHeader } from "../components/surface-header"

const STATUS_ICONS: Record<PlaybookStepStatus, string> = {
  pending: "\u25C7",   // ◇
  running: "\u25C8",   // ◈
  passed: "\u25C6",    // ◆
  failed: "\u2717",    // ✗
  skipped: "\u25CB",   // ○
}

function getStatusColor(status: PlaybookStepStatus): string {
  switch (status) {
    case "pending": return THEME.dim
    case "running": return THEME.secondary
    case "passed": return THEME.success
    case "failed": return THEME.error
    case "skipped": return THEME.dim
  }
}

function buildStepItems(steps: PlaybookStep[], animationFrame: number): ListItem[] {
  return steps.map((step) => {
    const color = getStatusColor(step.status)
    let icon = STATUS_ICONS[step.status]
    // Animate running icon
    if (step.status === "running") {
      const spinChars = ["\u25C8", "\u25C9", "\u25CE", "\u25C9"]
      icon = spinChars[animationFrame % spinChars.length]
    }
    const duration = step.duration_ms != null ? ` ${THEME.dim}(${step.duration_ms}ms)${THEME.reset}` : ""
    const label = `${color}${icon}${THEME.reset} ${THEME.white}${step.name}${THEME.reset}${duration}`
    const plainLength = `${icon} ${step.name}${step.duration_ms != null ? ` (${step.duration_ms}ms)` : ""}`.length
    return { label, plainLength }
  })
}

function renderStepDetail(step: PlaybookStep, _width: number): string[] {
  const content: string[] = []

  content.push(`${THEME.muted}Name:${THEME.reset}        ${THEME.white}${step.name}${THEME.reset}`)
  content.push(`${THEME.muted}Description:${THEME.reset} ${THEME.white}${step.description}${THEME.reset}`)
  content.push(`${THEME.muted}Command:${THEME.reset}     ${THEME.dim}${step.command} ${step.args.join(" ")}${THEME.reset}`)

  const statusColor = getStatusColor(step.status)
  content.push(`${THEME.muted}Status:${THEME.reset}      ${statusColor}${step.status}${THEME.reset}`)

  if (step.duration_ms != null) {
    content.push(`${THEME.muted}Duration:${THEME.reset}    ${THEME.white}${step.duration_ms}ms${THEME.reset}`)
  }

  if (step.error) {
    content.push("")
    content.push(`${THEME.error}Error:${THEME.reset}`)
    content.push(`  ${THEME.error}${step.error}${THEME.reset}`)
  }

  if (step.output) {
    content.push("")
    content.push(`${THEME.muted}Output:${THEME.reset}`)
    const json = JSON.stringify(step.output, null, 2)
    const jsonLines = json.split("\n")
    for (const jl of jsonLines) {
      content.push(`  ${THEME.dim}${jl}${THEME.reset}`)
    }
  }

  return content
}

const DEFAULT_CONFIG: PlaybookConfig = {
  name: "Default Hunt Playbook",
  description: "Standard threat hunting workflow",
  timeRange: "24h",
  rules: [],
  iocFeeds: [],
}

export const huntPlaybookScreen: Screen = {
  onEnter(ctx: ScreenContext): void {
    const pb = ctx.state.hunt.playbook
    if (pb.steps.length > 0) return

    const steps = buildDefaultPlaybook({
      ...DEFAULT_CONFIG,
      rules: resolveDefaultWatchRules(ctx.app.getCwd()),
    })
    ctx.state.hunt.playbook = {
      ...pb,
      steps,
      selectedStep: 0,
      running: false,
      error: null,
      report: null,
    }
  },

  render(ctx: ScreenContext): string {
    const { state, width, height } = ctx
    const pb = state.hunt.playbook
    const lines: string[] = []

    lines.push(...renderSurfaceHeader("hunt-playbook", "Playbook Runner", width, THEME))

    // Progress indicator
    const totalSteps = pb.steps.length
    const completedSteps = pb.steps.filter((s) => s.status === "passed" || s.status === "failed" || s.status === "skipped").length
    const runningStep = pb.steps.findIndex((s) => s.status === "running")

    let progressText: string
    if (pb.running) {
      const stepLabel = runningStep >= 0 ? pb.steps[runningStep].name : "..."
      progressText =
        `${THEME.secondary}Running${THEME.reset} ` +
        `${THEME.white}Step ${completedSteps + 1}/${totalSteps}${THEME.reset} ` +
        `${THEME.dim}(${stepLabel})${THEME.reset}`
    } else if (completedSteps === totalSteps && totalSteps > 0) {
      const allPassed = pb.steps.every((s) => s.status === "passed" || s.status === "skipped")
      if (allPassed) {
        progressText = `${THEME.success}Completed${THEME.reset} ${THEME.white}${totalSteps}/${totalSteps} steps passed${THEME.reset}`
      } else {
        const failed = pb.steps.filter((s) => s.status === "failed").length
        progressText = `${THEME.error}Finished${THEME.reset} ${THEME.white}${failed} step(s) failed${THEME.reset}`
      }
    } else {
      progressText = `${THEME.muted}Ready${THEME.reset} ${THEME.dim}${totalSteps} steps${THEME.reset} ${THEME.dim}// press r to run${THEME.reset}`
    }

    lines.push(fitString(`  ${progressText}`, width))
    lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))

    // Error
    if (pb.error) {
      lines.push(fitString(`${THEME.error}  Error: ${pb.error}${THEME.reset}`, width))
      lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))
    }

    const helpLines = 1
    const headerLines = lines.length
    const availableHeight = height - headerLines - helpLines

    if (pb.steps.length === 0) {
      const msgY = Math.floor(availableHeight / 2)
      for (let i = 0; i < msgY; i++) lines.push(" ".repeat(width))
      lines.push(fitString(`${THEME.muted}  No playbook steps configured.${THEME.reset}`, width))
      for (let i = lines.length; i < height - 1; i++) lines.push(" ".repeat(width))
      lines.push(renderHelpBar(width, pb.running))
      return lines.join("\n")
    }

    // Split: step list (left) | step detail (right)
    const stepItems = buildStepItems(pb.steps, state.animationFrame)

    // Use a viewport for step selection
    const stepViewport = { offset: 0, selected: pb.selectedStep }
    const leftLines = renderList(stepItems, stepViewport, availableHeight, Math.floor(width * 0.4), THEME)

    // Detail for selected step
    const selectedStep = pb.steps[pb.selectedStep]
    let rightLines: string[]
    if (selectedStep) {
      const detailContent = renderStepDetail(selectedStep, Math.floor(width * 0.6) - 2)
      rightLines = renderBox(selectedStep.name, detailContent, Math.floor(width * 0.6) - 1, THEME, { style: "rounded" })
      // Pad right lines to fill available height
      while (rightLines.length < availableHeight) {
        rightLines.push(" ".repeat(Math.floor(width * 0.6) - 1))
      }
    } else {
      rightLines = []
      for (let i = 0; i < availableHeight; i++) {
        rightLines.push(" ".repeat(Math.floor(width * 0.6) - 1))
      }
    }

    const splitLines = renderSplit(leftLines, rightLines, width, availableHeight, THEME, 0.4)
    for (const sl of splitLines) lines.push(sl)

    // Help bar
    lines.push(renderHelpBar(width, pb.running))

    // Pad to fill
    while (lines.length < height) lines.push(" ".repeat(width))

    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const pb = ctx.state.hunt.playbook

    // Always allow ESC
    if (key === "\x1b" || key === "\x1b\x1b" || key === "q") {
      ctx.app.setScreen("main")
      return true
    }

    // When running, only allow ESC
    if (pb.running) return false

    // Navigate steps
    if (key === "j" || key === "down") {
      if (pb.steps.length > 0) {
        const next = Math.min(pb.steps.length - 1, pb.selectedStep + 1)
        ctx.state.hunt.playbook = { ...pb, selectedStep: next }
      }
      return true
    }
    if (key === "k" || key === "up") {
      if (pb.steps.length > 0) {
        const prev = Math.max(0, pb.selectedStep - 1)
        ctx.state.hunt.playbook = { ...pb, selectedStep: prev }
      }
      return true
    }

    // View step detail (enter)
    if (key === "\r" || key === "return") {
      // Already showing detail in split view, this is a no-op
      return true
    }

    // Run playbook
    if (key === "r") {
      // Reset all steps to pending
      const resetSteps = pb.steps.map((s) => ({ ...s, status: "pending" as const, output: undefined, error: undefined, duration_ms: undefined }))
      ctx.state.hunt.playbook = { ...pb, steps: resetSteps, running: true, error: null, report: null }
      ctx.app.render()

      executePlaybook(
        {
          ...DEFAULT_CONFIG,
          rules: resolveDefaultWatchRules(ctx.app.getCwd()),
        },
        resetSteps,
        (index: number, step: PlaybookStep) => {
          const current = ctx.state.hunt.playbook
          const updatedSteps = [...current.steps]
          updatedSteps[index] = step
          ctx.state.hunt.playbook = { ...current, steps: updatedSteps }
          ctx.app.render()
        },
      )
        .then((result) => {
          ctx.state.hunt.playbook = {
            ...ctx.state.hunt.playbook,
            steps: result.steps,
            running: false,
            report: result.report ?? null,
          }
          ctx.app.render()
        })
        .catch((err) => {
          ctx.state.hunt.playbook = {
            ...ctx.state.hunt.playbook,
            running: false,
            error: err instanceof Error ? err.message : String(err),
          }
          ctx.app.render()
        })

      return true
    }

    return false
  },
}

function renderHelpBar(width: number, running: boolean): string {
  if (running) {
    const help = `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}  ${THEME.secondary}running...${THEME.reset}`
    return fitString(help, width)
  }
  const help =
    `${THEME.dim}esc${THEME.reset}${THEME.muted} back${THEME.reset}  ` +
    `${THEME.dim}j/k${THEME.reset}${THEME.muted} select${THEME.reset}  ` +
    `${THEME.dim}r${THEME.reset}${THEME.muted} run${THEME.reset}`
  return fitString(help, width)
}
