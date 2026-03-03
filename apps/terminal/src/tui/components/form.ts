/**
 * Form component - renders a vertical form with labeled fields.
 */

import type { ThemeColors } from "./types"
import { fitString } from "./types"

export type FormFieldType = "text" | "select" | "toggle"

export interface TextField {
  type: "text"
  label: string
  value: string
  placeholder?: string
}

export interface SelectField {
  type: "select"
  label: string
  options: string[]
  selectedIndex: number
}

export interface ToggleField {
  type: "toggle"
  label: string
  value: boolean
}

export type FormField = TextField | SelectField | ToggleField

export interface FormState {
  fields: FormField[]
  focusedIndex: number
}

export function renderForm(
  state: FormState,
  width: number,
  theme: ThemeColors,
): string[] {
  if (width <= 0) return []
  const lines: string[] = []

  for (let i = 0; i < state.fields.length; i++) {
    const field = state.fields[i]
    const isFocused = i === state.focusedIndex
    const focusIndicator = isFocused
      ? `${theme.accent}${theme.bold}\u25B8${theme.reset} `
      : "  "

    // Label line
    const labelColor = isFocused ? theme.secondary : theme.muted
    lines.push(fitString(`${focusIndicator}${labelColor}${field.label}${theme.reset}`, width))

    // Value line
    switch (field.type) {
      case "text": {
        const displayValue = field.value || field.placeholder || ""
        const valueColor = field.value
          ? theme.white
          : `${theme.dim}${theme.italic}`
        const cursor = isFocused ? `${theme.accent}\u2588${theme.reset}` : ""
        const bracket = isFocused ? theme.accent : theme.dim
        lines.push(
          fitString(
            `   ${bracket}[${theme.reset} ${valueColor}${displayValue}${theme.reset}${cursor} ${bracket}]${theme.reset}`,
            width,
          ),
        )
        break
      }
      case "select": {
        const selected = field.options[field.selectedIndex] ?? ""
        const leftArrow = isFocused ? `${theme.accent}\u25C0${theme.reset}` : " "
        const rightArrow = isFocused ? `${theme.accent}\u25B6${theme.reset}` : " "
        lines.push(
          fitString(
            `   ${leftArrow} ${theme.white}${selected}${theme.reset} ${rightArrow}`,
            width,
          ),
        )
        break
      }
      case "toggle": {
        const indicator = field.value
          ? `${theme.success}[\u2713]${theme.reset}`
          : `${theme.dim}[ ]${theme.reset}`
        const label = field.value ? "On" : "Off"
        lines.push(fitString(`   ${indicator} ${theme.white}${label}${theme.reset}`, width))
        break
      }
    }

    // Spacing between fields
    if (i < state.fields.length - 1) {
      lines.push(" ".repeat(width))
    }
  }

  return lines
}

export function focusNext(state: FormState): FormState {
  if (state.fields.length === 0) return state
  return {
    ...state,
    focusedIndex: (state.focusedIndex + 1) % state.fields.length,
  }
}

export function focusPrev(state: FormState): FormState {
  if (state.fields.length === 0) return state
  return {
    ...state,
    focusedIndex: (state.focusedIndex - 1 + state.fields.length) % state.fields.length,
  }
}

export function handleFieldInput(state: FormState, key: string): FormState {
  if (state.fields.length === 0) return state
  const field = state.fields[state.focusedIndex]
  const newFields = [...state.fields]

  switch (field.type) {
    case "text": {
      let newValue = field.value
      if (key === "backspace" || key === "\x7f" || key === "\b") {
        newValue = newValue.slice(0, -1)
      } else if (key.length === 1 && key >= " ") {
        newValue = newValue + key
      } else {
        return state // no change for unrecognized keys
      }
      newFields[state.focusedIndex] = { ...field, value: newValue }
      break
    }
    case "select": {
      if (key === "left" || key === "h") {
        const newIdx = (field.selectedIndex - 1 + field.options.length) % field.options.length
        newFields[state.focusedIndex] = { ...field, selectedIndex: newIdx }
      } else if (key === "right" || key === "l") {
        const newIdx = (field.selectedIndex + 1) % field.options.length
        newFields[state.focusedIndex] = { ...field, selectedIndex: newIdx }
      }
      break
    }
    case "toggle": {
      if (key === " " || key === "enter") {
        newFields[state.focusedIndex] = { ...field, value: !field.value }
      }
      break
    }
  }

  return { ...state, fields: newFields }
}
