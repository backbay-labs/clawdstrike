import type { RunRecord } from "../types"
import { updateRunRecord } from "../runs"

export class ExternalLaunchStartupTimeoutError extends Error {
  constructor(message = "External terminal opened, but the launch script never started.") {
    super(message)
    this.name = "ExternalLaunchStartupTimeoutError"
  }
}

export class ExternalRunHeartbeatTimeoutError extends Error {
  constructor(message = "External terminal stopped reporting liveness after startup.") {
    super(message)
    this.name = "ExternalRunHeartbeatTimeoutError"
  }
}

export function isRecoverableExternalLaunchError(
  error: unknown,
): error is ExternalLaunchStartupTimeoutError | ExternalRunHeartbeatTimeoutError {
  return error instanceof ExternalLaunchStartupTimeoutError || error instanceof ExternalRunHeartbeatTimeoutError
}

export function createRecoverableExternalFailureRun(
  run: RunRecord,
  adapterId: string,
  message: string,
): RunRecord {
  return updateRunRecord(
    run,
    {
      phase: "failed",
      routing: null,
      workcellId: null,
      worktreePath: null,
      ptySessionId: null,
      execution: null,
      verification: null,
      result: null,
      error: message,
      completedAt: new Date().toISOString(),
      external: {
        kind: adapterId,
        adapterId,
        ref: null,
        status: "failed",
        error: message,
      },
    },
    { kind: "error", message: `External launch failed: ${message}` },
  )
}
