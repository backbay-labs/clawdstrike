/**
 * Shared phase detection logic — used by useAnticipation, usePredictiveLayout,
 * useAdaptiveSidebar, and useConfidence to avoid duplicate computation.
 */
import type { ShellMode, LensId } from "../workbenchState";
import type { WorkPhase } from "./types";
import { PHASE_SIGNALS, confidenceLevel } from "./types";
import type { ConfidenceLevel } from "./types";

export interface PhaseDetectionResult {
  phase: WorkPhase;
  score: number;
  confidence: ConfidenceLevel;
}

export function detectPhase(
  shell: ShellMode,
  lens: LensId,
  hasActiveRun: boolean,
  hasActiveCase: boolean,
): PhaseDetectionResult {
  let bestPhase: WorkPhase = "discovery";
  let bestScore = 0;

  for (const [phase, signals] of Object.entries(PHASE_SIGNALS) as [WorkPhase, typeof PHASE_SIGNALS[WorkPhase]][]) {
    let score = 0;
    if (signals.shells.includes(shell)) score += 30;
    if (signals.lenses.includes(lens)) score += 20;
    if (signals.hasRun === null || signals.hasRun === hasActiveRun) score += 25;
    if (signals.hasCase === null || signals.hasCase === hasActiveCase) score += 25;
    if (score > bestScore) {
      bestScore = score;
      bestPhase = phase;
    }
  }

  return {
    phase: bestPhase,
    score: bestScore,
    confidence: confidenceLevel(bestScore),
  };
}
