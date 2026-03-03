/**
 * ClawdStrike Canonical Type Definitions
 *
 * All types are defined using Zod schemas for runtime validation.
 * This is the single source of truth for all ClawdStrike data structures.
 */

import { z } from "zod"

// ============================================================================
// IDENTIFIERS
// ============================================================================

export const TaskId = z.string().uuid()
export const WorkcellId = z.string().uuid()
export const BeadId = z.string().regex(/^[A-Z]+-\d+$/) // e.g., "PROJ-123"

// ============================================================================
// TOOLCHAINS
// ============================================================================

export const Toolchain = z.enum([
  "codex", // OpenAI Codex CLI
  "claude", // Anthropic Claude Code
  "opencode", // Local OpenCode
  "crush", // Multi-provider fallback
])

export const ToolchainConfig = z.object({
  id: Toolchain,
  enabled: z.boolean().default(true),
  priority: z.number().int().default(0),
  authType: z.enum(["oauth", "api_key", "none"]),
  settings: z.record(z.string(), z.any()).optional(),
})

// ============================================================================
// TASKS
// ============================================================================

export const TaskInput = z.object({
  id: TaskId.optional(),
  prompt: z.string().min(1).max(100000),
  context: z.object({
    cwd: z.string(),
    projectId: z.string(),
    branch: z.string().optional(),
    files: z.array(z.string()).optional(),
    env: z.record(z.string(), z.string()).optional(),
  }),
  labels: z.array(z.string()).optional(),
  hint: Toolchain.optional(),
  gates: z.array(z.string()).optional(),
  beadId: BeadId.optional(),
  timeout: z.number().int().positive().optional(),
})

export const TaskStatus = z.enum([
  "pending",
  "routing",
  "executing",
  "verifying",
  "completed",
  "failed",
  "cancelled",
])

// ============================================================================
// EXECUTION
// ============================================================================

export const ExecutionResult = z.object({
  taskId: TaskId,
  workcellId: WorkcellId,
  toolchain: Toolchain,
  success: z.boolean(),
  patch: z.string().optional(),
  output: z.string(),
  error: z.string().optional(),
  telemetry: z.object({
    startedAt: z.number(),
    completedAt: z.number(),
    model: z.string().optional(),
    tokens: z
      .object({
        input: z.number(),
        output: z.number(),
      })
      .optional(),
    cost: z.number().optional(),
  }),
})

// ============================================================================
// VERIFICATION
// ============================================================================

export const Severity = z.enum(["error", "warning", "info"])

export const Diagnostic = z.object({
  file: z.string().optional(),
  line: z.number().int().positive().optional(),
  column: z.number().int().positive().optional(),
  severity: Severity,
  message: z.string(),
  code: z.string().optional(),
  source: z.string().optional(), // e.g., "mypy", "ruff"
})

export const GateResult = z.object({
  gate: z.string(),
  passed: z.boolean(),
  critical: z.boolean(),
  output: z.string(),
  diagnostics: z.array(Diagnostic).optional(),
  timing: z.object({
    startedAt: z.number(),
    completedAt: z.number(),
  }),
})

export const GateResults = z.object({
  allPassed: z.boolean(),
  criticalPassed: z.boolean(),
  results: z.array(GateResult),
  score: z.number().int().min(0).max(100),
  summary: z.string(),
})

// ============================================================================
// WORKCELLS
// ============================================================================

export const WorkcellStatus = z.enum([
  "creating",
  "warm",
  "in_use",
  "cleaning",
  "destroyed",
])

export const SandboxMode = z.enum(["inplace", "worktree", "tmpdir"])

export const WorkcellInfo = z.object({
  id: WorkcellId,
  name: z.string(),
  directory: z.string(),
  branch: z.string(),
  status: WorkcellStatus,
  toolchain: Toolchain.optional(),
  projectId: z.string(),
  createdAt: z.number(),
  lastUsedAt: z.number().optional(),
  useCount: z.number().int().default(0),
})

// ============================================================================
// SPECULATION
// ============================================================================

export const VoteStrategy = z.enum([
  "first_pass", // First passing result wins
  "best_score", // Highest gate score wins
  "consensus", // Most similar patch wins
])

export const SpeculationConfig = z.object({
  count: z.number().int().min(2).max(5),
  toolchains: z.array(Toolchain),
  voteStrategy: VoteStrategy,
  timeout: z.number().int().positive().default(300000),
})

export const SpeculationResult = z.object({
  winner: z
    .object({
      workcellId: WorkcellId,
      toolchain: Toolchain,
      result: ExecutionResult,
      gateResults: GateResults,
    })
    .optional(),
  allResults: z.array(
    z.object({
      workcellId: WorkcellId,
      toolchain: Toolchain,
      result: ExecutionResult.optional(),
      gateResults: GateResults.optional(),
      error: z.string().optional(),
    })
  ),
  timing: z.object({
    startedAt: z.number(),
    completedAt: z.number(),
  }),
  votes: z.record(z.string(), z.number()).optional(),
})

// ============================================================================
// ROUTING
// ============================================================================

export const RoutingStrategy = z.enum(["single", "speculate"])

export const RoutingDecision = z.object({
  taskId: TaskId,
  toolchain: Toolchain,
  strategy: RoutingStrategy,
  speculation: SpeculationConfig.optional(),
  gates: z.array(z.string()),
  retries: z.number().int().min(0).max(3).default(1),
  priority: z.number().int().min(0).max(100).default(50),
  reasoning: z.string().optional(),
})

// ============================================================================
// PATCHES
// ============================================================================

export const PatchStatus = z.enum([
  "captured", // Diff extracted from workcell
  "validating", // Gates running
  "validated", // Gates passed
  "rejected", // Gates failed or user rejected
  "staged", // Awaiting user review
  "approved", // User approved
  "merging", // Applying to main repo
  "merged", // Successfully applied
  "failed", // Merge failed (conflicts, etc.)
])

export const Patch = z.object({
  id: z.string().uuid(),
  workcellId: WorkcellId,
  taskId: TaskId,
  diff: z.string(), // Unified diff format
  stats: z.object({
    filesChanged: z.number().int().nonnegative(),
    insertions: z.number().int().nonnegative(),
    deletions: z.number().int().nonnegative(),
  }),
  files: z.array(z.string()), // List of changed files
  status: PatchStatus,
  createdAt: z.number(),
  validatedAt: z.number().optional(),
  mergedAt: z.number().optional(),
})

// ============================================================================
// BEADS (Work Graph)
// ============================================================================

export const BeadStatus = z.enum([
  "open",
  "in_progress",
  "blocked",
  "completed",
  "cancelled",
])

export const BeadPriority = z.enum(["p0", "p1", "p2", "p3"])

export const Bead = z.object({
  id: BeadId,
  title: z.string(),
  description: z.string().optional(),
  status: BeadStatus,
  priority: BeadPriority.optional(),
  labels: z.array(z.string()).optional(),
  assignee: z.string().optional(),
  createdAt: z.number(),
  updatedAt: z.number(),
  closedAt: z.number().optional(),
})

// ============================================================================
// TELEMETRY
// ============================================================================

export const TelemetryEvent = z.object({
  timestamp: z.number(),
  type: z.string(),
  taskId: TaskId.optional(),
  workcellId: WorkcellId.optional(),
  data: z.record(z.string(), z.any()).optional(),
})

export const Rollout = z.object({
  id: z.string().uuid(),
  taskId: TaskId,
  startedAt: z.number(),
  completedAt: z.number().optional(),
  status: TaskStatus,
  routing: RoutingDecision.optional(),
  execution: ExecutionResult.optional(),
  verification: GateResults.optional(),
  events: z.array(TelemetryEvent),
})

// ============================================================================
// TYPE EXPORTS (inferred types for TypeScript usage)
// ============================================================================

export type TaskId = z.infer<typeof TaskId>
export type WorkcellId = z.infer<typeof WorkcellId>
export type BeadId = z.infer<typeof BeadId>
export type Toolchain = z.infer<typeof Toolchain>
export type ToolchainConfig = z.infer<typeof ToolchainConfig>
export type TaskInput = z.infer<typeof TaskInput>
export type TaskStatus = z.infer<typeof TaskStatus>
export type ExecutionResult = z.infer<typeof ExecutionResult>
export type Severity = z.infer<typeof Severity>
export type Diagnostic = z.infer<typeof Diagnostic>
export type GateResult = z.infer<typeof GateResult>
export type GateResults = z.infer<typeof GateResults>
export type WorkcellStatus = z.infer<typeof WorkcellStatus>
export type SandboxMode = z.infer<typeof SandboxMode>
export type WorkcellInfo = z.infer<typeof WorkcellInfo>
export type VoteStrategy = z.infer<typeof VoteStrategy>
export type SpeculationConfig = z.infer<typeof SpeculationConfig>
export type SpeculationResult = z.infer<typeof SpeculationResult>
export type RoutingStrategy = z.infer<typeof RoutingStrategy>
export type RoutingDecision = z.infer<typeof RoutingDecision>
export type PatchStatus = z.infer<typeof PatchStatus>
export type Patch = z.infer<typeof Patch>
export type BeadStatus = z.infer<typeof BeadStatus>
export type BeadPriority = z.infer<typeof BeadPriority>
export type Bead = z.infer<typeof Bead>
export type TelemetryEvent = z.infer<typeof TelemetryEvent>
export type Rollout = z.infer<typeof Rollout>
