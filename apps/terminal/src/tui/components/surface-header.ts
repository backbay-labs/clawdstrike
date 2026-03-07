import type { ThemeColors } from "./types"
import { fitString } from "./types"
import { getSurfaceMeta } from "../surfaces"
import type { InputMode, ScreenStage } from "../types"

export function renderSurfaceStageBadge(stage: ScreenStage, theme: ThemeColors): string {
  if (stage === "experimental") {
    return `${theme.warning}[exp]${theme.reset}`
  }

  return `${theme.success}[beta]${theme.reset}`
}

export function renderSurfaceHeader(
  mode: InputMode,
  title: string,
  width: number,
  theme: ThemeColors,
  detail?: string,
): string[] {
  const meta = getSurfaceMeta(mode)
  const groupLabel = meta.group === "hunt"
    ? "HUNT"
    : meta.group === "core"
      ? "OPS"
      : "SETUP"
  const badge = renderSurfaceStageBadge(meta.stage, theme)
  const header =
    `${theme.accent}${theme.bold} ${groupLabel} ${theme.reset}` +
    `${theme.dim}//${theme.reset} ` +
    `${theme.secondary}${title}${theme.reset} ` +
    `${badge}`

  return [
    fitString(
      detail ? `${header} ${theme.dim}${detail}${theme.reset}` : header,
      width,
    ),
    fitString(`${theme.dim}${"─".repeat(width)}${theme.reset}`, width),
  ]
}
