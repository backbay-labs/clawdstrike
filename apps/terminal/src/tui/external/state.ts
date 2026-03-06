import type { RunRecord } from "../types"
import { updateRunRecord } from "../runs"

export class ExternalLaunchStartupTimeoutError extends Error {
  constructor(message = "External terminal opened, but the launch script never started.") {
    super(message)
    this.name = "ExternalLaunchStartupTimeoutError"
  }
}

export function isRecoverableExternalLaunchError(
  error: unknown,
): error is ExternalLaunchStartupTimeoutError {
  return error instanceof ExternalLaunchStartupTimeoutError
}

export function createRecoverableExternalFailureRun(
  run: RunRecord,
  adapterId: string,
  message: string,
): RunRecord {
  return updateRunRecord(
    run,
    {
      phase: "launching",
      routing: null,
      workcellId: null,
      worktreePath: null,
      ptySessionId: null,
      execution: null,
      verification: null,
      result: null,
      error: message,
      completedAt: null,
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
