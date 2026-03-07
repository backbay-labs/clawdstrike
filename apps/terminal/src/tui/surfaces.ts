import type { InputMode, ScreenStage } from "./types"

export interface SurfaceMeta {
  label: string
  stage: ScreenStage
  group: "core" | "hunt" | "setup"
}

const SURFACE_META: Record<InputMode, SurfaceMeta> = {
  main: { label: "main", stage: "supported", group: "core" },
  commands: { label: "commands", stage: "supported", group: "core" },
  "dispatch-sheet": { label: "dispatch-sheet", stage: "supported", group: "core" },
  runs: { label: "runs", stage: "supported", group: "core" },
  "interactive-run": { label: "interactive-run", stage: "experimental", group: "core" },
  integrations: { label: "integrations", stage: "supported", group: "core" },
  security: { label: "security", stage: "supported", group: "core" },
  audit: { label: "audit", stage: "supported", group: "core" },
  policy: { label: "policy", stage: "supported", group: "core" },
  "run-detail": { label: "run-detail", stage: "supported", group: "core" },
  result: { label: "result", stage: "supported", group: "core" },
  setup: { label: "setup", stage: "supported", group: "setup" },
  "hunt-watch": { label: "watch", stage: "supported", group: "hunt" },
  "hunt-scan": { label: "scan", stage: "supported", group: "hunt" },
  "hunt-timeline": { label: "timeline", stage: "supported", group: "hunt" },
  "hunt-rule-builder": { label: "rules", stage: "experimental", group: "hunt" },
  "hunt-query": { label: "query", stage: "supported", group: "hunt" },
  "hunt-diff": { label: "diff", stage: "experimental", group: "hunt" },
  "hunt-report": { label: "report", stage: "supported", group: "hunt" },
  "hunt-report-history": { label: "history", stage: "supported", group: "hunt" },
  "hunt-mitre": { label: "mitre", stage: "experimental", group: "hunt" },
  "hunt-playbook": { label: "playbook", stage: "experimental", group: "hunt" },
}

export function getSurfaceMeta(mode: InputMode): SurfaceMeta {
  return SURFACE_META[mode]
}
