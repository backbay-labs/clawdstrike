import type { WorkcellInfo } from "../../types"

export interface ExternalTerminalAdapterOption {
  id: string
  label: string
  description: string
}

export interface ExternalTerminalLaunchResult {
  ref: string | null
}

export interface ExternalRunStatusPayload {
  state?: "starting" | "running" | "finished"
  startedAt?: string
  heartbeatAt?: string
  finishedAt?: string
  exitCode?: number
  reason?: string
}

export interface ExternalRunSessionPlan {
  ptySessionId: string
  workcell: WorkcellInfo
  routing: { toolchain: string; strategy: string; gates: string[] }
  scriptPath: string
  statusPath: string
  startupTimeoutMs: number
  livenessTimeoutMs: number
  cleanup: () => Promise<void>
}

export interface ExternalTerminalAdapter extends ExternalTerminalAdapterOption {
  isAvailable(): Promise<boolean>
  launch(plan: ExternalRunSessionPlan): Promise<ExternalTerminalLaunchResult>
  focus?(ref: string): Promise<void>
  isAlive?(ref: string): Promise<boolean>
}

export interface ExternalRunState {
  kind: string
  adapterId: string | null
  ref: string | null
  status: "idle" | "launching" | "running" | "failed"
  error: string | null
}
