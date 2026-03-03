/**
 * Hunt Rule Builder Screen - Correlation rule creation with dry run.
 */

import { THEME } from "../theme"
import type { Screen, ScreenContext, HuntRuleBuilderState } from "../types"
import type { RuleCondition, RuleSeverity, CorrelationRule, Alert } from "../../hunt/types"
import { runCorrelate } from "../../hunt/bridge-correlate"
import { renderForm, focusNext, focusPrev, handleFieldInput, type FormState } from "../components/form"
import { renderList, scrollUp, scrollDown, type ListItem } from "../components/scrollable-list"
import { renderBox } from "../components/box"
import { fitString } from "../components/types"

type Section = "form" | "conditions" | "actions"
const SECTIONS: Section[] = ["form", "conditions", "actions"]

let activeSection: Section = "form"

function getFormValues(form: FormState): { name: string; severity: RuleSeverity; windowSeconds: number; description: string } {
  const nameField = form.fields[0]
  const severityField = form.fields[1]
  const windowField = form.fields[2]
  const descField = form.fields[3]

  const name = nameField.type === "text" ? nameField.value : ""
  const severity = (severityField.type === "select"
    ? severityField.options[severityField.selectedIndex]
    : "medium") as RuleSeverity
  const windowSeconds = windowField.type === "text" ? parseInt(windowField.value, 10) || 300 : 300
  const description = descField.type === "text" ? descField.value : ""

  return { name, severity, windowSeconds, description }
}

function buildRuleYaml(rb: HuntRuleBuilderState): string {
  const { name, severity, windowSeconds, description } = getFormValues(rb.form)

  const rule: CorrelationRule = {
    name: name || "untitled-rule",
    severity,
    window_seconds: windowSeconds,
    description: description || undefined,
    conditions: rb.conditions.length > 0 ? rb.conditions : [{ source: "tetragon", verdict: "deny" }],
    output: {
      title: name || "Untitled Rule",
      severity,
      description: description || undefined,
    },
  }

  // Simple YAML serialization
  let yaml = `name: ${rule.name}\n`
  yaml += `severity: ${rule.severity}\n`
  yaml += `window_seconds: ${rule.window_seconds}\n`
  if (rule.description) yaml += `description: ${rule.description}\n`
  yaml += `conditions:\n`
  for (const c of rule.conditions) {
    yaml += `  - `
    const parts: string[] = []
    if (c.source) parts.push(`source: ${c.source}`)
    if (c.kind) parts.push(`kind: ${c.kind}`)
    if (c.verdict) parts.push(`verdict: ${c.verdict}`)
    if (c.pattern) parts.push(`pattern: "${c.pattern}"`)
    if (c.field) parts.push(`field: ${c.field}`)
    if (c.value) parts.push(`value: "${c.value}"`)
    yaml += `{ ${parts.join(", ")} }\n`
  }
  yaml += `output:\n`
  yaml += `  title: ${rule.output.title}\n`
  yaml += `  severity: ${rule.output.severity}\n`
  if (rule.output.description) yaml += `  description: ${rule.output.description}\n`

  return yaml
}

function conditionToListItem(c: RuleCondition, idx: number): ListItem {
  const parts: string[] = []
  if (c.source) parts.push(`src:${c.source}`)
  if (c.kind) parts.push(`kind:${c.kind}`)
  if (c.verdict) parts.push(`verdict:${c.verdict}`)
  if (c.pattern) parts.push(`pat:"${c.pattern}"`)
  if (c.field) parts.push(`${c.field}=${c.value ?? "*"}`)
  const label = parts.length > 0
    ? `${THEME.muted}${idx + 1}.${THEME.reset} ${THEME.white}${parts.join(" ")}${THEME.reset}`
    : `${THEME.muted}${idx + 1}.${THEME.reset} ${THEME.dim}(empty condition)${THEME.reset}`
  return { label, plainLength: `${idx + 1}. ${parts.join(" ")}`.length }
}

function alertToListItem(a: Alert, _idx: number): ListItem {
  const severityColor = a.severity === "critical" ? THEME.error
    : a.severity === "high" ? THEME.warning
    : THEME.muted
  const label =
    `${severityColor}[${a.severity}]${THEME.reset} ` +
    `${THEME.white}${a.title}${THEME.reset} ` +
    `${THEME.dim}(${a.matched_events.length} events)${THEME.reset}`
  return { label, plainLength: `[${a.severity}] ${a.title} (${a.matched_events.length} events)`.length }
}

export const huntRuleBuilderScreen: Screen = {
  onEnter(_ctx: ScreenContext): void {
    activeSection = "form"
  },

  render(ctx: ScreenContext): string {
    const { state, width, height } = ctx
    const rb = state.hunt.ruleBuilder
    const lines: string[] = []

    // Title
    const title = `${THEME.accent}${THEME.bold} HUNT ${THEME.reset}${THEME.dim} // ${THEME.reset}${THEME.secondary}Rule Builder${THEME.reset}`
    lines.push(fitString(title, width))
    lines.push(fitString(`${THEME.dim}${"─".repeat(width)}${THEME.reset}`, width))

    // Error / status
    if (rb.error) {
      lines.push(fitString(`${THEME.error} Error: ${rb.error}${THEME.reset}`, width))
    } else if (rb.statusMessage) {
      lines.push(fitString(`${THEME.success} ${rb.statusMessage}${THEME.reset}`, width))
    }

    const innerWidth = Math.min(74, width - 4)

    // -- Form section --
    const formHighlight = activeSection === "form" ? THEME.secondary : THEME.dim
    const formTitle = `${formHighlight}Rule Metadata${THEME.reset}`
    const formLines = renderForm(rb.form, innerWidth - 2, THEME)
    const formBox = renderBox(formTitle, formLines, innerWidth, THEME, { style: "rounded", padding: 1 })
    for (const l of formBox) lines.push(fitString(`  ${l}`, width))

    // -- Conditions section --
    const condHighlight = activeSection === "conditions" ? THEME.secondary : THEME.dim
    const condTitle = `${condHighlight}Conditions${THEME.reset}`
    const condItems = rb.conditions.map((c, i) => conditionToListItem(c, i))
    const condListHeight = Math.min(6, Math.max(2, rb.conditions.length + 1))
    const condLines = renderList(condItems, rb.conditionList, condListHeight, innerWidth - 2, THEME)
    const condBox = renderBox(condTitle, condLines, innerWidth, THEME, { style: "rounded", padding: 1 })
    for (const l of condBox) lines.push(fitString(`  ${l}`, width))

    // -- Dry run results (if any) --
    if (rb.dryRunResults.length > 0 || rb.dryRunning) {
      const drTitle = rb.dryRunning
        ? `${THEME.warning}Dry Run (running...)${THEME.reset}`
        : `${THEME.success}Dry Run Results (${rb.dryRunResults.length})${THEME.reset}`
      const drItems = rb.dryRunResults.map((a, i) => alertToListItem(a, i))
      const drListHeight = Math.min(5, Math.max(1, rb.dryRunResults.length))
      const drLines = renderList(drItems, { offset: 0, selected: 0 }, drListHeight, innerWidth - 2, THEME)
      const drBox = renderBox(drTitle, drLines, innerWidth, THEME, { style: "single", padding: 1 })
      for (const l of drBox) lines.push(fitString(`  ${l}`, width))
    }

    // -- Actions bar --
    const actHighlight = activeSection === "actions" ? THEME.secondary : THEME.dim
    const actionBar =
      `  ${actHighlight}Actions:${THEME.reset}  ` +
      `${THEME.dim}[D]${THEME.reset}${THEME.muted} Dry Run${THEME.reset}  ` +
      `${THEME.dim}[W]${THEME.reset}${THEME.muted} Save Rule${THEME.reset}  ` +
      `${THEME.dim}[a]${THEME.reset}${THEME.muted} Add Condition${THEME.reset}  ` +
      `${THEME.dim}[x]${THEME.reset}${THEME.muted} Delete Condition${THEME.reset}`
    lines.push(fitString(actionBar, width))

    // Fill to bottom
    while (lines.length < height - 1) lines.push(" ".repeat(width))

    // Help bar
    lines.push(renderHelpBar(width))

    return lines.join("\n")
  },

  handleInput(key: string, ctx: ScreenContext): boolean {
    const rb = ctx.state.hunt.ruleBuilder

    // Navigation: back
    if (key === "\x1b" || key === "\x1b\x1b") {
      if (activeSection !== "form") {
        activeSection = "form"
        return true
      }
      ctx.app.setScreen("main")
      return true
    }

    // Tab: cycle sections
    if (key === "\t") {
      const idx = SECTIONS.indexOf(activeSection)
      activeSection = SECTIONS[(idx + 1) % SECTIONS.length]
      return true
    }

    // Section-specific input
    if (activeSection === "form") {
      const focusedField = rb.form.fields[rb.form.focusedIndex]
      const isTextField = focusedField?.type === "text"

      // When a text field is focused, send printable chars and backspace to the form first
      if (isTextField) {
        if (key === "\x7f" || key === "\b" || key === "backspace" || (key.length === 1 && key >= " ")) {
          const newForm = handleFieldInput(rb.form, key)
          if (newForm !== rb.form) {
            ctx.state.hunt.ruleBuilder = { ...rb, form: newForm }
            return true
          }
          return false
        }
      }

      // j/k or arrow keys navigate form fields (only when not typing in a text field)
      if (key === "j" || key === "down" || key === "\x1b[B") {
        ctx.state.hunt.ruleBuilder = { ...rb, form: focusNext(rb.form) }
        return true
      }
      if (key === "k" || key === "up" || key === "\x1b[A") {
        ctx.state.hunt.ruleBuilder = { ...rb, form: focusPrev(rb.form) }
        return true
      }
      // Pass remaining input to form (for select left/right, toggle space, etc.)
      const newForm = handleFieldInput(rb.form, key)
      if (newForm !== rb.form) {
        ctx.state.hunt.ruleBuilder = { ...rb, form: newForm }
        return true
      }
      return false
    }

    if (activeSection === "conditions") {
      if (key === "j" || key === "down") {
        if (rb.conditions.length > 0) {
          ctx.state.hunt.ruleBuilder = { ...rb, conditionList: scrollDown(rb.conditionList, rb.conditions.length, 6) }
        }
        return true
      }
      if (key === "k" || key === "up") {
        if (rb.conditions.length > 0) {
          ctx.state.hunt.ruleBuilder = { ...rb, conditionList: scrollUp(rb.conditionList) }
        }
        return true
      }
      // Add condition
      if (key === "a") {
        const newCondition: RuleCondition = { source: "tetragon", verdict: "deny" }
        ctx.state.hunt.ruleBuilder = {
          ...rb,
          conditions: [...rb.conditions, newCondition],
        }
        return true
      }
      // Delete condition
      if (key === "x") {
        if (rb.conditions.length > 0) {
          const idx = rb.conditionList.selected
          const newConditions = rb.conditions.filter((_, i) => i !== idx)
          const newSelected = Math.min(rb.conditionList.selected, Math.max(0, newConditions.length - 1))
          ctx.state.hunt.ruleBuilder = {
            ...rb,
            conditions: newConditions,
            conditionList: { ...rb.conditionList, selected: newSelected },
          }
        }
        return true
      }
      return false
    }

    // Actions section
    if (activeSection === "actions") {
      // Dry run
      if (key === "D" || key === "d") {
        if (rb.dryRunning) return true
        ctx.state.hunt.ruleBuilder = { ...rb, dryRunning: true, dryRunResults: [], error: null, statusMessage: null }
        ctx.app.render()

        const yaml = buildRuleYaml(rb)
        const tmpPath = `/tmp/clawdstrike-rule-${Date.now()}.yaml`

        // Write temp file and run correlate
        void (async () => {
          try {
            await Bun.write(tmpPath, yaml)
            const alerts = await runCorrelate({ rules: [tmpPath] })
            ctx.state.hunt.ruleBuilder = {
              ...ctx.state.hunt.ruleBuilder,
              dryRunning: false,
              dryRunResults: alerts,
              statusMessage: `Dry run complete: ${alerts.length} alert(s)`,
            }
          } catch (err) {
            ctx.state.hunt.ruleBuilder = {
              ...ctx.state.hunt.ruleBuilder,
              dryRunning: false,
              error: err instanceof Error ? err.message : String(err),
            }
          }
          ctx.app.render()
        })()
        return true
      }

      // Save rule
      if (key === "W" || key === "w") {
        if (rb.saving) return true
        const { name } = getFormValues(rb.form)
        if (!name) {
          ctx.state.hunt.ruleBuilder = { ...rb, error: "Rule name is required" }
          return true
        }

        ctx.state.hunt.ruleBuilder = { ...rb, saving: true, error: null, statusMessage: null }
        ctx.app.render()

        const yaml = buildRuleYaml(rb)
        const home = process.env.HOME ?? "~"
        const rulePath = `${home}/.clawdstrike/rules/${name}.yaml`

        void (async () => {
          try {
            await Bun.write(rulePath, yaml)
            ctx.state.hunt.ruleBuilder = {
              ...ctx.state.hunt.ruleBuilder,
              saving: false,
              statusMessage: `Rule saved to ${rulePath}`,
            }
          } catch (err) {
            ctx.state.hunt.ruleBuilder = {
              ...ctx.state.hunt.ruleBuilder,
              saving: false,
              error: err instanceof Error ? err.message : String(err),
            }
          }
          ctx.app.render()
        })()
        return true
      }

      // Also allow add/delete from actions section
      if (key === "a") {
        const newCondition: RuleCondition = { source: "tetragon", verdict: "deny" }
        ctx.state.hunt.ruleBuilder = { ...rb, conditions: [...rb.conditions, newCondition] }
        return true
      }
      if (key === "x") {
        if (rb.conditions.length > 0) {
          const idx = rb.conditionList.selected
          const newConditions = rb.conditions.filter((_, i) => i !== idx)
          const newSelected = Math.min(rb.conditionList.selected, Math.max(0, newConditions.length - 1))
          ctx.state.hunt.ruleBuilder = {
            ...rb,
            conditions: newConditions,
            conditionList: { ...rb.conditionList, selected: newSelected },
          }
        }
        return true
      }

      return false
    }

    return false
  },
}

function renderHelpBar(width: number): string {
  const help =
    `${THEME.dim}Tab${THEME.reset}${THEME.muted} section${THEME.reset}  ` +
    `${THEME.dim}j/k${THEME.reset}${THEME.muted} navigate${THEME.reset}  ` +
    `${THEME.dim}D${THEME.reset}${THEME.muted} dry run${THEME.reset}  ` +
    `${THEME.dim}W${THEME.reset}${THEME.muted} save${THEME.reset}  ` +
    `${THEME.dim}ESC${THEME.reset}${THEME.muted} back${THEME.reset}`
  return fitString(help, width)
}
