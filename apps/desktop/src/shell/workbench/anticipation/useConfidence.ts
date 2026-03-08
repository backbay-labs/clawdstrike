/**
 * Confidence Tiers — computes an overall anticipation confidence score
 * from four independent signals: phase clarity, selection relevance,
 * pattern strength, and context completeness.
 *
 * The weighted average feeds into `confidenceLevel()` from types.ts to
 * produce a "low" | "medium" | "high" tier that other hooks can gate
 * proactive behavior on.
 */
import { useMemo } from "react";
import {
  useShell,
  useLens,
  useSelection,
  useActiveHunt,
  useHuntStore,
  useWorkbench,
} from "../WorkbenchStateProvider";
import type { ConfidenceLevel } from "./types";
import { PHASE_SIGNALS, confidenceLevel } from "./types";
import type { WorkPhase } from "./types";

// ── Public types ─────────────────────────────────────────────────

export interface ConfidenceState {
  overall: ConfidenceLevel;
  score: number;
  breakdown: {
    /** 0-100: how clearly the current shell/lens/run/case maps to a single phase. */
    phaseClarity: number;
    /** 0-100: how relevant the current selection is to the active hunt context. */
    selectionRelevance: number;
    /** 0-100: how strong the tab-visit pattern signal is. */
    patternStrength: number;
    /** 0-100: how much context (hunt, run, selection, tabs) is available. */
    contextCompleteness: number;
  };
}

// ── Weights ──────────────────────────────────────────────────────

const WEIGHTS = {
  phaseClarity: 0.3,
  selectionRelevance: 0.2,
  patternStrength: 0.2,
  contextCompleteness: 0.3,
} as const;

// ── Hook ─────────────────────────────────────────────────────────

export function useConfidence(): ConfidenceState {
  const shell = useShell();
  const { lens: currentLens } = useLens();
  const selection = useSelection();
  const activeHunt = useActiveHunt();
  const huntStore = useHuntStore();
  const { state: workbenchState } = useWorkbench();

  return useMemo(() => {
    // ── Phase clarity ────────────────────────────────────────
    const hasRun = activeHunt
      ? activeHunt.runIds.some((id) => huntStore.runs[id]?.status === "running")
      : false;
    const hasCase = activeHunt?.caseId != null;

    // Score the best-matching phase — a perfect match is 100
    const phases = Object.keys(PHASE_SIGNALS) as WorkPhase[];
    let bestPhaseScore = 0;
    for (const phase of phases) {
      const sig = PHASE_SIGNALS[phase];
      let s = 0;
      if (sig.shells.includes(shell as never)) s += 30;
      if (sig.lenses.includes(currentLens as never)) s += 20;
      if (sig.hasRun === null || sig.hasRun === hasRun) s += 25;
      if (sig.hasCase === null || sig.hasCase === hasCase) s += 25;
      if (s > bestPhaseScore) bestPhaseScore = s;
    }
    const phaseClarity = bestPhaseScore;

    // ── Selection relevance ──────────────────────────────────
    let selectionRelevance = 20; // baseline — no selection
    if (selection.entityType && selection.entityId) {
      // Check if the selected entity matches any artifact in the active hunt
      if (activeHunt) {
        const artifactKinds = new Set(
          activeHunt.artifactIds
            .map((id) => huntStore.artifacts[id]?.kind)
            .filter(Boolean),
        );
        if (artifactKinds.has(selection.entityType as never)) {
          selectionRelevance = 85;
        } else {
          selectionRelevance = 40;
        }
      } else {
        selectionRelevance = 40;
      }
    }

    // ── Pattern strength ─────────────────────────────────────
    // Derived from tab history: more tabs visited = stronger signal,
    // repetition of similar kinds = even stronger.
    const mainGroup = workbenchState.tabGroups.find((g) => g.id === "main");
    const tabHistory = mainGroup?.tabHistory ?? [];
    const tabs = mainGroup?.tabs ?? [];

    let patternStrength = 10; // baseline
    const historyLen = tabHistory.length;
    if (historyLen >= 10) {
      patternStrength = 60;
    } else if (historyLen >= 5) {
      patternStrength = 40;
    } else if (historyLen >= 2) {
      patternStrength = 25;
    }

    // Boost for repeated kinds in last 5 history entries
    const recentIds = tabHistory.slice(-5);
    const recentKinds = recentIds
      .map((id) => tabs.find((t) => t.id === id)?.kind)
      .filter(Boolean);
    const kindCounts: Record<string, number> = {};
    for (const k of recentKinds) {
      if (k) kindCounts[k] = (kindCounts[k] ?? 0) + 1;
    }
    const maxRepeat = Math.max(0, ...Object.values(kindCounts));
    if (maxRepeat >= 3) patternStrength = Math.min(100, patternStrength + 30);
    else if (maxRepeat >= 2) patternStrength = Math.min(100, patternStrength + 15);

    // ── Context completeness ─────────────────────────────────
    let contextCompleteness = 0;
    if (activeHunt) contextCompleteness += 25;
    if (hasRun) contextCompleteness += 25;
    if (selection.entityType && selection.entityId) contextCompleteness += 25;
    if (tabs.length > 1) contextCompleteness += 25;

    // ── Overall ──────────────────────────────────────────────
    const score = Math.round(
      phaseClarity * WEIGHTS.phaseClarity +
      selectionRelevance * WEIGHTS.selectionRelevance +
      patternStrength * WEIGHTS.patternStrength +
      contextCompleteness * WEIGHTS.contextCompleteness,
    );
    const overall = confidenceLevel(score);

    return {
      overall,
      score,
      breakdown: {
        phaseClarity,
        selectionRelevance,
        patternStrength,
        contextCompleteness,
      },
    };
  }, [shell, currentLens, selection, activeHunt, huntStore, workbenchState.tabGroups]);
}
