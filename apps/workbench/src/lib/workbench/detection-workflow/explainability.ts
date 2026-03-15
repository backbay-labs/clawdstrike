/**
 * Explainability engine — processes lab run results into structured
 * explainability output for UI rendering.
 *
 * Provides trace extraction, run comparison, grouping, and source line
 * resolution for the explainability panel.
 */

import type {
  LabRun,
  LabCaseResult,
  ExplainabilityTrace,
  EvidenceDatasetKind,
} from "./shared-types";

// ---- Types ----

export type TraceOutcome =
  | "pass"
  | "fail"
  | "expected_match"
  | "unexpected_match"
  | "missed";

export interface EnrichedTrace {
  trace: ExplainabilityTrace;
  caseResult: LabCaseResult | null;
  dataset: EvidenceDatasetKind | "unknown";
  outcome: TraceOutcome;
}

export interface RunComparisonDelta {
  casesFlipped: Array<{
    caseId: string;
    previousStatus: "pass" | "fail";
    currentStatus: "pass" | "fail";
    previousVerdict?: string;
    currentVerdict?: string;
  }>;
  newMatches: string[];
  newFalsePositives: string[];
  techniquesAdded: string[];
  techniquesLost: string[];
  summaryDelta: {
    passedDelta: number;
    failedDelta: number;
    matchedDelta: number;
    missedDelta: number;
    falsePositivesDelta: number;
  };
}

export interface TraceGroups {
  matches: EnrichedTrace[];
  misses: EnrichedTrace[];
  falsePositives: EnrichedTrace[];
  passes: EnrichedTrace[];
  failures: EnrichedTrace[];
}

// ---- Helpers ----

function resolveCaseResult(
  run: LabRun,
  caseId: string,
): LabCaseResult | null {
  return run.results.find((r) => r.caseId === caseId) ?? null;
}

function resolveOutcome(
  caseResult: LabCaseResult | null,
  trace: ExplainabilityTrace,
): TraceOutcome {
  if (!caseResult) {
    // No case result linked; infer from trace kind
    if (trace.kind === "sigma_match" || trace.kind === "yara_match") {
      return "expected_match";
    }
    return "pass";
  }

  const { status, dataset } = caseResult;

  // For match-oriented traces
  if (trace.kind === "sigma_match" || trace.kind === "yara_match") {
    if (dataset === "positive" || dataset === "regression") {
      return status === "pass" ? "expected_match" : "missed";
    }
    if (dataset === "negative" || dataset === "false_positive") {
      return status === "pass" ? "pass" : "unexpected_match";
    }
  }

  // For validation and policy traces
  return status === "pass" ? "pass" : "fail";
}

// ---- Public API ----

/**
 * Extract all explainability traces from a lab run, enriched with
 * case result context and computed outcomes.
 */
export function extractTraces(run: LabRun): EnrichedTrace[] {
  if (!run.explainability || run.explainability.length === 0) {
    return [];
  }

  return run.explainability.map((trace) => {
    const caseResult = resolveCaseResult(run, trace.caseId);
    const dataset: EvidenceDatasetKind | "unknown" =
      caseResult?.dataset ?? "unknown";
    const outcome = resolveOutcome(caseResult, trace);

    return { trace, caseResult, dataset, outcome };
  });
}

/**
 * Compare two lab runs to produce a delta summary showing what changed.
 */
export function compareRuns(
  current: LabRun,
  baseline: LabRun,
): RunComparisonDelta {
  const baselineMap = new Map<string, LabCaseResult>();
  for (const r of baseline.results) {
    baselineMap.set(r.caseId, r);
  }

  const currentMap = new Map<string, LabCaseResult>();
  for (const r of current.results) {
    currentMap.set(r.caseId, r);
  }

  // Cases that flipped status
  const casesFlipped: RunComparisonDelta["casesFlipped"] = [];
  const newMatches: string[] = [];
  const newFalsePositives: string[] = [];

  for (const [caseId, currentResult] of currentMap) {
    const baselineResult = baselineMap.get(caseId);
    if (!baselineResult) continue;

    if (baselineResult.status !== currentResult.status) {
      casesFlipped.push({
        caseId,
        previousStatus: baselineResult.status,
        currentStatus: currentResult.status,
        previousVerdict: baselineResult.actual,
        currentVerdict: currentResult.actual,
      });
    }
  }

  // Detect new matches and false positives from traces
  const baselineTraceIds = new Set(baseline.explainability.map((t) => t.caseId));
  for (const trace of current.explainability) {
    if (!baselineTraceIds.has(trace.caseId)) {
      const caseResult = currentMap.get(trace.caseId);
      if (
        (trace.kind === "sigma_match" || trace.kind === "yara_match") &&
        caseResult
      ) {
        if (
          caseResult.dataset === "negative" ||
          caseResult.dataset === "false_positive"
        ) {
          newFalsePositives.push(trace.caseId);
        } else {
          newMatches.push(trace.caseId);
        }
      }
    }
  }

  // Technique delta from coverageDelta
  const techniquesAdded = current.coverageDelta?.techniquesAdded ?? [];
  const techniquesLost = current.coverageDelta?.techniquesLost ?? [];

  // Summary delta
  const summaryDelta = {
    passedDelta: current.summary.passed - baseline.summary.passed,
    failedDelta: current.summary.failed - baseline.summary.failed,
    matchedDelta: current.summary.matched - baseline.summary.matched,
    missedDelta: current.summary.missed - baseline.summary.missed,
    falsePositivesDelta:
      current.summary.falsePositives - baseline.summary.falsePositives,
  };

  return {
    casesFlipped,
    newMatches,
    newFalsePositives,
    techniquesAdded,
    techniquesLost,
    summaryDelta,
  };
}

/**
 * Group enriched traces by outcome for UI rendering.
 */
export function groupTracesByOutcome(traces: EnrichedTrace[]): TraceGroups {
  const groups: TraceGroups = {
    matches: [],
    misses: [],
    falsePositives: [],
    passes: [],
    failures: [],
  };

  for (const t of traces) {
    switch (t.outcome) {
      case "expected_match":
        groups.matches.push(t);
        break;
      case "missed":
        groups.misses.push(t);
        break;
      case "unexpected_match":
        groups.falsePositives.push(t);
        break;
      case "pass":
        groups.passes.push(t);
        break;
      case "fail":
        groups.failures.push(t);
        break;
    }
  }

  return groups;
}

/**
 * Find the source line range for a trace (for editor jump-to).
 * Returns null if the trace does not carry source line hints.
 */
export function getSourceLineRange(
  trace: ExplainabilityTrace,
): { start: number; end: number } | null {
  if (trace.kind === "policy_evaluation") {
    // Policy evaluations don't have source line hints
    return null;
  }

  const hints = trace.sourceLineHints;
  if (!hints || hints.length === 0) {
    return null;
  }

  const sorted = [...hints].sort((a, b) => a - b);
  return { start: sorted[0], end: sorted[sorted.length - 1] };
}
