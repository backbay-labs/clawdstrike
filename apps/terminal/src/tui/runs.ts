import type {
  DispatchResultInfo,
  DispatchExecutionMode,
  RunAttachState,
  RunEvent,
  RunListFilter,
  RunPhase,
  RunRecord,
} from "./types"
import { getExternalAdapter } from "./external/registry"

export interface ManagedRunContext {
  cwd: string
  projectId: string
}

export type ExecuteToolFn = (
  name: string,
  params: unknown,
  context: ManagedRunContext,
) => Promise<unknown>

export interface ManagedRunLaunchOptions {
  cwd: string
  projectId: string
  executeTool: ExecuteToolFn
  shouldAbort?: () => boolean
  onUpdate?: (run: RunRecord) => void
}

export interface ManagedRunInit {
  prompt: string
  action: "dispatch" | "speculate"
  agentId: string
  agentLabel: string
}

const TERMINAL_PHASES = new Set<RunPhase>(["review_ready", "completed", "failed", "canceled"])
const ATTACHABLE_TOOLCHAINS = new Set(["claude", "codex"])

function nowIso(): string {
  return new Date().toISOString()
}

function makeRunId(): string {
  return `run_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`
}

function truncateTitle(prompt: string, maxLength = 72): string {
  const normalized = prompt.replace(/\s+/g, " ").trim()
  if (normalized.length <= maxLength) {
    return normalized
  }

  return `${normalized.slice(0, Math.max(0, maxLength - 1)).trimEnd()}…`
}

function createEvent(kind: RunEvent["kind"], message: string, timestamp = nowIso()): RunEvent {
  return { timestamp, kind, message }
}

function applyUpdate(
  run: RunRecord,
  patch: Partial<RunRecord>,
  event?: { kind: RunEvent["kind"]; message: string },
): RunRecord {
  const timestamp = nowIso()
  return {
    ...run,
    ...patch,
    updatedAt: timestamp,
    events: event ? [...run.events, createEvent(event.kind, event.message, timestamp)] : run.events,
  }
}

export function supportsAttachToolchain(agentId: string): boolean {
  return ATTACHABLE_TOOLCHAINS.has(agentId)
}

function mapDispatchResult(
  raw: Record<string, unknown>,
  run: RunRecord,
  duration: number,
): DispatchResultInfo {
  if (run.action === "speculate") {
    const winner = raw.winner as Record<string, unknown> | undefined
    const error = raw.success ? undefined : "No passing result from speculation"

    return {
      success: Boolean(raw.success),
      taskId: "",
      agent: winner?.toolchain ? String(winner.toolchain) : "multi",
      action: run.action,
      execution: {
        success: Boolean(raw.success),
        error,
      },
      error,
      duration,
      routing: winner?.toolchain
        ? {
            toolchain: String(winner.toolchain),
            strategy: "parallel speculation",
            gates: [],
          }
        : undefined,
    }
  }

  const routing = raw.routing as Record<string, unknown> | undefined
  const result = raw.result as Record<string, unknown> | undefined
  const verification = raw.verification as Record<string, unknown> | undefined
  const telemetry = result?.telemetry as Record<string, unknown> | undefined
  const executionSuccess = result ? Boolean(result.success) : Boolean(raw.success)
  const verificationInfo = verification
    ? {
        allPassed: Boolean(verification.allPassed),
        criticalPassed:
          typeof verification.criticalPassed === "boolean"
            ? verification.criticalPassed
            : Boolean(verification.allPassed),
        score: typeof verification.score === "number" ? verification.score : 0,
        summary: typeof verification.summary === "string" ? verification.summary : "",
        results: Array.isArray(verification.results)
          ? verification.results.map((entry) => {
              const gate = entry as Record<string, unknown>
              return {
                gate: String(gate.gate),
                passed: Boolean(gate.passed),
              }
            })
          : [],
      }
    : undefined
  const verificationPassed = verificationInfo?.criticalPassed ?? true

  return {
    success: executionSuccess && verificationPassed,
    taskId: typeof raw.taskId === "string" ? raw.taskId : "",
    agent: run.agentLabel,
    action: run.action,
    routing: routing
      ? {
          toolchain: String(routing.toolchain),
          strategy: String(routing.strategy),
          gates: Array.isArray(routing.gates) ? routing.gates.map(String) : [],
        }
      : undefined,
    execution: result
      ? {
          success: executionSuccess,
          error: typeof result.error === "string" ? result.error : undefined,
          model: typeof telemetry?.model === "string" ? telemetry.model : undefined,
          tokens:
            telemetry?.tokens &&
            typeof telemetry.tokens === "object" &&
            telemetry.tokens !== null &&
            typeof (telemetry.tokens as Record<string, unknown>).input === "number" &&
            typeof (telemetry.tokens as Record<string, unknown>).output === "number"
              ? {
                  input: (telemetry.tokens as Record<string, number>).input,
                  output: (telemetry.tokens as Record<string, number>).output,
                }
              : undefined,
          cost: typeof telemetry?.cost === "number" ? telemetry.cost : undefined,
        }
      : undefined,
    verification: verificationInfo,
    error: typeof raw.error === "string" ? raw.error : undefined,
    duration,
  }
}

export function getFailureMessage(result: DispatchResultInfo): string {
  if (result.error) {
    return result.error
  }
  if (result.execution?.error) {
    return result.execution.error
  }
  if (result.verification && !result.verification.criticalPassed) {
    return result.verification.summary || "verification failed"
  }
  return "execution failed"
}

export function isRunTerminal(phase: RunPhase): boolean {
  return TERMINAL_PHASES.has(phase)
}

export function formatRunPhase(phase: RunPhase): string {
  switch (phase) {
    case "review_ready":
      return "review ready"
    default:
      return phase.replace(/_/g, " ")
  }
}

export function isRunReviewReady(run: RunRecord): boolean {
  return run.phase === "review_ready"
}

export function getRunReviewRoute(run: RunRecord): "result" | "diff" | "report" | null {
  if (run.result) {
    return "result"
  }

  return null
}

export function filterRuns(entries: RunRecord[], filter: RunListFilter): RunRecord[] {
  switch (filter) {
    case "active":
      return entries.filter((entry) => !isRunTerminal(entry.phase))
    case "review_ready":
      return entries.filter((entry) => isRunReviewReady(entry))
    case "all":
    default:
      return entries
  }
}

export function canRunAttach(run: Pick<RunRecord, "action" | "mode" | "phase" | "agentId" | "attachState">): boolean {
  return getRunAttachDisabledReason(run) === null
}

export function canRelaunchRunInMode(
  run: Pick<RunRecord, "action" | "mode" | "phase" | "agentId">,
  _mode: "attach" | "external",
): boolean {
  return (
    run.action === "dispatch" &&
    run.mode === "managed" &&
    isRunTerminal(run.phase) &&
    supportsAttachToolchain(run.agentId)
  )
}

export function canRunExternal(
  run: Pick<RunRecord, "action" | "mode" | "phase" | "agentId" | "external" | "result">,
): boolean {
  return getRunExternalDisabledReason(run) === null
}

export function isRecoverableExternalFailure(
  run: Pick<RunRecord, "action" | "mode" | "phase" | "external" | "result">,
): boolean {
  return (
    run.action === "dispatch" &&
    run.mode === "external" &&
    run.phase === "failed" &&
    run.external.status === "failed" &&
    run.result === null
  )
}

export function getRunAttachDisabledReason(
  run: Pick<RunRecord, "action" | "mode" | "phase" | "agentId" | "attachState">,
): string | null {
  if (run.action !== "dispatch") {
    return "Attach is only available for dispatch runs."
  }

  if (run.mode !== "attach") {
    return "Attach is only available for runs launched in attach mode."
  }

  if (!supportsAttachToolchain(run.agentId)) {
    return "This agent does not expose an interactive attach session yet."
  }

  if (isRunTerminal(run.phase)) {
    return "This run has already finished."
  }

  if (run.attachState === "attaching") {
    return "Attach handoff is preparing."
  }

  if (run.attachState === "attached") {
    return "This run already owns the terminal."
  }

  if (run.attachState === "returning") {
    return "ClawdStrike is restoring the run detail surface."
  }

  return null
}

export function getRunExternalDisabledReason(
  run: Pick<RunRecord, "action" | "mode" | "phase" | "agentId" | "external" | "result">,
): string | null {
  if (run.action !== "dispatch") {
    return "External execution is only available for dispatch runs."
  }

  if (run.mode !== "external") {
    return "External execution is only available for runs launched in external mode."
  }

  if (!supportsAttachToolchain(run.agentId)) {
    return "This agent does not expose an interactive external session yet."
  }

  if (isRecoverableExternalFailure(run)) {
    return null
  }

  if (isRunTerminal(run.phase)) {
    return "This run has already finished."
  }

  if (run.external.status === "launching") {
    return "External launch is in progress."
  }

  if (run.external.status === "running") {
    return "This run is already active in an external terminal."
  }

  return null
}

export function getExternalAdapterLabel(adapterId: string | null): string {
  if (!adapterId) {
    return "none"
  }

  return getExternalAdapter(adapterId)?.label ?? adapterId
}

export function getRunExternalSurfaceSummary(
  run: Pick<RunRecord, "external" | "phase">,
): string | null {
  const adapterLabel = getExternalAdapterLabel(run.external.adapterId)
  switch (run.external.status) {
    case "launching":
      return `${adapterLabel} launching`
    case "running":
      return `${adapterLabel} live`
    case "failed":
      return `${adapterLabel} failed`
    case "idle":
      return run.external.adapterId && isRunTerminal(run.phase) ? `${adapterLabel} completed` : null
    default:
      return null
  }
}

export function updateRunRecord(
  run: RunRecord,
  patch: Partial<RunRecord>,
  event?: { kind: RunEvent["kind"]; message: string },
): RunRecord {
  return applyUpdate(run, patch, event)
}

export function createManagedRun(
  init: ManagedRunInit & { mode?: DispatchExecutionMode; attachState?: RunAttachState },
): RunRecord {
  const timestamp = nowIso()
  const mode = init.mode ?? "managed"
  const attachState = init.attachState ?? "detached"
  return {
    id: makeRunId(),
    title: truncateTitle(init.prompt),
    prompt: init.prompt.trim(),
    action: init.action,
    agentId: init.agentId,
    agentLabel: init.agentLabel,
    mode,
    phase: "launching",
    createdAt: timestamp,
    updatedAt: timestamp,
    workcellId: null,
    worktreePath: null,
    routing: null,
    execution: null,
    verification: null,
    result: null,
    error: null,
    completedAt: null,
    attached: false,
    attachState,
    ptySessionId: null,
    canAttach: mode === "attach" && init.action === "dispatch" && supportsAttachToolchain(init.agentId),
    interactiveSessionId: null,
    interactiveSurface: "none",
    interactivePhase: null,
    external: {
      kind: "none",
      adapterId: null,
      ref: null,
      status: "idle",
      error: null,
    },
    ptyTail: [],
    events: [
      createEvent(
        "status",
        init.action === "dispatch"
          ? mode === "attach"
            ? "Attach run requested"
            : mode === "external"
              ? "External run requested"
            : "Dispatch requested"
          : "Speculation requested",
        timestamp,
      ),
    ],
  }
}

export function appendRunEvent(
  run: RunRecord,
  kind: RunEvent["kind"],
  message: string,
): RunRecord {
  return applyUpdate(run, {}, { kind, message })
}

export function cancelManagedRun(run: RunRecord, message = "Run canceled from the TUI"): RunRecord {
  if (run.phase === "canceled") {
    return run
  }

  return applyUpdate(run, { phase: "canceled", completedAt: nowIso() }, { kind: "warning", message })
}

export async function executeManagedRun(
  initialRun: RunRecord,
  options: ManagedRunLaunchOptions,
): Promise<RunRecord> {
  let run = initialRun
  const emit = (nextRun: RunRecord): RunRecord => {
    run = nextRun
    options.onUpdate?.(run)
    return run
  }
  const shouldAbort = () => options.shouldAbort?.() === true
  const start = Date.now()

  const cancelIfNeeded = (message: string): RunRecord | null => {
    if (!shouldAbort()) {
      return null
    }

    return emit(cancelManagedRun(run, message))
  }

  if (cancelIfNeeded("Run canceled before launch")) {
    return run
  }

  try {
    if (run.action === "dispatch") {
      emit(applyUpdate(run, { phase: "routing" }, { kind: "status", message: "Routing task" }))
      emit(applyUpdate(run, { phase: "executing" }, { kind: "log", message: "Running agent" }))

      const raw = await options.executeTool(
        "dispatch",
        { prompt: run.prompt, toolchain: run.agentId },
        { cwd: options.cwd, projectId: options.projectId },
      ) as Record<string, unknown>

      if (cancelIfNeeded("Run canceled before result framing")) {
        return run
      }

      const mapped = mapDispatchResult(raw, run, Date.now() - start)

      if (mapped.verification) {
        emit(applyUpdate(run, { phase: "verifying" }, { kind: "status", message: "Running verification" }))
      }

      const finalPhase: RunPhase = mapped.success
        ? mapped.verification
          ? "review_ready"
          : "completed"
        : "failed"

      emit(
        applyUpdate(
          run,
          {
            phase: finalPhase,
            routing: mapped.routing ?? null,
            execution: mapped.execution ?? null,
            verification: mapped.verification ?? null,
            result: mapped,
            error: mapped.success ? null : getFailureMessage(mapped),
            completedAt: isRunTerminal(finalPhase) ? nowIso() : null,
          },
          {
            kind: mapped.success ? "status" : "error",
            message: mapped.success
              ? finalPhase === "review_ready"
                ? "Run ready for review"
                : "Run completed"
              : `Run failed: ${getFailureMessage(mapped)}`,
          },
        ),
      )

      return run
    }

    emit(applyUpdate(run, { phase: "executing" }, { kind: "log", message: "Running speculation" }))

    const raw = await options.executeTool(
      "speculate",
      { prompt: run.prompt },
      { cwd: options.cwd, projectId: options.projectId },
    ) as Record<string, unknown>

    if (cancelIfNeeded("Run canceled before result framing")) {
      return run
    }

    const mapped = mapDispatchResult(raw, run, Date.now() - start)
    emit(
      applyUpdate(
        run,
        {
          phase: mapped.success ? "completed" : "failed",
          routing: mapped.routing ?? null,
          execution: mapped.execution ?? null,
          verification: null,
          result: mapped,
          error: mapped.success ? null : getFailureMessage(mapped),
          completedAt: nowIso(),
        },
        {
          kind: mapped.success ? "status" : "error",
          message: mapped.success ? "Speculation completed" : `Run failed: ${getFailureMessage(mapped)}`,
        },
      ),
    )
    return run
  } catch (error) {
    if (cancelIfNeeded("Run canceled after execution detached")) {
      return run
    }

    emit(
      applyUpdate(
        run,
        {
          phase: "failed",
          error: error instanceof Error ? error.message : String(error),
          execution: { success: false, error: error instanceof Error ? error.message : String(error) },
          completedAt: nowIso(),
          result: {
            success: false,
            taskId: "",
            agent: run.agentLabel,
            action: run.action,
            error: error instanceof Error ? error.message : String(error),
            duration: Date.now() - start,
          },
        },
        {
          kind: "error",
          message: `Run failed: ${error instanceof Error ? error.message : String(error)}`,
        },
      ),
    )
    return run
  }
}
