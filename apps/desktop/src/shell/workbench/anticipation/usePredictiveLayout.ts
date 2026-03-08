/**
 * Predictive Layout — infers likely open/split behavior, sidebar section
 * ordering, and adaptive lens defaults from the current work phase.
 *
 * Phase detection scores each WorkPhase against the current shell, lens,
 * run presence, and case presence. The highest-scoring phase drives the
 * sidebar ordering and open-mode prediction.
 *
 * All state is derived (useMemo); no side effects.
 */
import { useMemo, useRef } from "react";
import { useShell, useLens, useActiveTab, useActiveHunt, useHuntStore } from "../WorkbenchStateProvider";
import type { LensId } from "../workbenchState";
import type { OpenTabMode, TabKind } from "../workbenchState";
import type { WorkPhase } from "./types";
import { PHASE_SIGNALS, SHELL_DEFAULT_LENS, confidenceLevel } from "./types";

// ── Public types ─────────────────────────────────────────────────

export interface PredictiveLayoutState {
  /** How a new item should open relative to the current tab. */
  suggestedOpenMode: OpenTabMode;
  openModeReason: string;

  /** Phase-aware sidebar section ordering. */
  sidebarSectionOrder: string[];
  phase: WorkPhase;
  phaseConfidence: number;

  /** Adaptive lens suggestion when the shell changes. */
  suggestedLens: LensId | null;
  lensChangeReason: string | null;
  shouldChangeLens: boolean;
}

// ── Phase detection ──────────────────────────────────────────────

interface PhaseScore {
  phase: WorkPhase;
  score: number;
}

function scorePhases(
  currentShell: string,
  currentLens: string,
  hasRun: boolean,
  hasCase: boolean,
): PhaseScore[] {
  const phases = Object.keys(PHASE_SIGNALS) as WorkPhase[];
  return phases.map((phase) => {
    const sig = PHASE_SIGNALS[phase];
    let score = 0;
    if (sig.shells.includes(currentShell as never)) score += 30;
    if (sig.lenses.includes(currentLens as never)) score += 20;
    if (sig.hasRun === null || sig.hasRun === hasRun) score += 25;
    if (sig.hasCase === null || sig.hasCase === hasCase) score += 25;
    return { phase, score };
  });
}

// ── Open mode prediction ─────────────────────────────────────────

interface OpenModePrediction {
  mode: OpenTabMode;
  reason: string;
}

function predictOpenMode(activeTabKind: TabKind | null): OpenModePrediction {
  if (!activeTabKind) {
    return { mode: "replace", reason: "no active tab" };
  }

  // Pattern: active "signal-thread" + opening a "hunt" → split right
  // (signal thread is still useful context while reviewing the hunt)
  if (activeTabKind === "signal-thread") {
    return { mode: "split-right", reason: "source thread still active" };
  }

  // Pattern: active "receipt" + opening another receipt → split right for comparison
  if (activeTabKind === "receipt") {
    return { mode: "compare", reason: "compare similar receipt type" };
  }

  // Pattern: active "case" + opening a note → new tab to keep case visible
  if (activeTabKind === "case") {
    return { mode: "new-tab", reason: "keep case visible" };
  }

  // Pattern: active "hunt" + opening a file → split right for preview
  if (activeTabKind === "hunt") {
    return { mode: "split-right", reason: "preview alongside hunt" };
  }

  return { mode: "replace", reason: "default behavior" };
}

// ── Sidebar section ordering ─────────────────────────────────────

const SIDEBAR_SECTIONS_BY_PHASE: Record<WorkPhase, string[]> = {
  discovery:     ["Suggested Targets", "Watchlists", "Quick Actions"],
  investigation: ["Active Run", "Inputs", "Recent Receipts", "Suggested Related", "Watchlists"],
  triage:        ["Current Hunt", "Suggested Targets", "Watchlists", "Quick Actions"],
  reporting:     ["Case Link", "Citations", "Related Notes", "Recent Receipts"],
};

// ── Lens change suppression ──────────────────────────────────────

/** Number of manual lens changes after which we stop suggesting. */
const MANUAL_OVERRIDE_THRESHOLD = 2;

// ── Hook ─────────────────────────────────────────────────────────

export function usePredictiveLayout(): PredictiveLayoutState {
  const shell = useShell();
  const { lens: currentLens } = useLens();
  const activeTab = useActiveTab();
  const activeHunt = useActiveHunt();
  const huntStore = useHuntStore();

  // Track previous shell to detect transitions
  const previousShellRef = useRef(shell);
  // Count how many times the user has manually changed the lens since the
  // last shell transition (used to suppress adaptive lens suggestions).
  const manualLensChangesRef = useRef(0);
  // Track the previous lens so we can detect manual changes
  const previousLensRef = useRef(currentLens);

  return useMemo(() => {
    // ── Detect shell transition ────────────────────────────────
    const shellChanged = previousShellRef.current !== shell;
    if (shellChanged) {
      previousShellRef.current = shell;
      manualLensChangesRef.current = 0;
    }

    // Detect manual lens change (lens changed without a shell transition)
    if (!shellChanged && previousLensRef.current !== currentLens) {
      manualLensChangesRef.current += 1;
    }
    previousLensRef.current = currentLens;

    // ── Derive run / case presence ─────────────────────────────
    const hasRun = activeHunt
      ? activeHunt.runIds.some((id) => huntStore.runs[id]?.status === "running")
      : false;
    const hasCase = activeHunt?.caseId != null;

    // ── Phase detection ────────────────────────────────────────
    const scores = scorePhases(shell, currentLens, hasRun, hasCase);
    scores.sort((a, b) => b.score - a.score);
    const bestPhase = scores[0];
    const phase = bestPhase.phase;
    const phaseConfidence = bestPhase.score;

    // ── Open mode prediction ───────────────────────────────────
    const activeTabKind = activeTab?.kind ?? null;
    const { mode: suggestedOpenMode, reason: openModeReason } =
      predictOpenMode(activeTabKind);

    // ── Sidebar section ordering ───────────────────────────────
    const sidebarSectionOrder = SIDEBAR_SECTIONS_BY_PHASE[phase];

    // ── Adaptive lens suggestion ───────────────────────────────
    let suggestedLens: LensId | null = null;
    let lensChangeReason: string | null = null;
    let shouldChangeLens = false;

    const shellDefaults = SHELL_DEFAULT_LENS[shell];
    if (shellDefaults && !shellDefaults.includes(currentLens)) {
      suggestedLens = shellDefaults[0];
      lensChangeReason = `${shell} shell prefers ${shellDefaults[0]} lens`;

      // Only auto-suggest if confidence is high AND user hasn't overridden recently
      const confidenceTier = confidenceLevel(phaseConfidence);
      shouldChangeLens =
        confidenceTier === "high" &&
        manualLensChangesRef.current < MANUAL_OVERRIDE_THRESHOLD;
    }

    return {
      suggestedOpenMode,
      openModeReason,
      sidebarSectionOrder,
      phase,
      phaseConfidence,
      suggestedLens,
      lensChangeReason,
      shouldChangeLens,
    };
  }, [shell, currentLens, activeTab, activeHunt, huntStore.runs]);
}
