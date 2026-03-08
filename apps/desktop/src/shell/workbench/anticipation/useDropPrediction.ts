/**
 * useDropPrediction — predicts the most likely drop action and explains it.
 *
 * Reads the operator's current context (shell mode, active lens, hunt state)
 * and ranks possible drop intents by score. The top-ranked intent becomes the
 * default action; lower-ranked intents appear as alternates with explanations.
 */
import { useMemo } from "react";
import { useShell, useLens, useActiveHunt, useHuntStore } from "../WorkbenchStateProvider";
import type { ArtifactKind } from "../huntTypes";
import type { IntentType, IntentExplanation } from "./types";

export interface DropPrediction {
  defaultAction: IntentType;
  defaultLabel: string;
  explanation: IntentExplanation;
  alternateActions: Array<{ intent: IntentType; label: string; confidence: number }>;
}

interface ScoredIntent {
  intent: IntentType;
  label: string;
  score: number;
  reason: string;
}

// ── Scoring tables ──────────────────────────────────────────────

function scoreEntity(
  shell: string,
  lens: string,
  hasRun: boolean,
): ScoredIntent[] {
  const results: ScoredIntent[] = [];
  if (shell === "hunt" && lens === "entities" && !hasRun) {
    results.push({ intent: "attach-target", label: "Attach as target", score: 90, reason: "current hunt + entity type" });
  } else if (shell === "hunt" && hasRun) {
    results.push({ intent: "run-input", label: "Use as run input", score: 85, reason: "active run context" });
    results.push({ intent: "attach-target", label: "Attach as target", score: 70, reason: "hunt context fallback" });
  } else {
    results.push({ intent: "attach-target", label: "Attach as target", score: 70, reason: "default entity action" });
  }
  if (shell === "case" || lens === "notes") {
    results.push({ intent: "cite", label: "Cite in case note", score: 80, reason: "case reporting phase" });
  }
  if (shell === "hunt" && lens === "entities" && hasRun) {
    results.push({ intent: "attach-target", label: "Attach as target", score: 75, reason: "hunt context" });
  }
  if (!results.some((r) => r.intent === "watch")) {
    results.push({ intent: "watch", label: "Add to watchlist", score: 60, reason: "general monitoring" });
  }
  return results;
}

function scoreReceipt(
  shell: string,
  lens: string,
  hasCase: boolean,
): ScoredIntent[] {
  const results: ScoredIntent[] = [];
  if (hasCase || shell === "case") {
    results.push({ intent: "attach-evidence", label: "Add to case evidence", score: 90, reason: "case evidence collection" });
  }
  if (shell === "hunt") {
    results.push({ intent: "attach-evidence", label: "Attach as evidence", score: 80, reason: "hunt evidence context" });
  }
  if (lens === "notes") {
    results.push({ intent: "cite", label: "Cite in note", score: 75, reason: "notes lens active" });
  }
  results.push({ intent: "compare", label: "Compare", score: 85, reason: "receipt comparison" });
  return results;
}

function scoreFile(
  shell: string,
  lens: string,
  hasRun: boolean,
  hasSandbox: boolean,
): ScoredIntent[] {
  const results: ScoredIntent[] = [];
  if (hasRun) {
    results.push({ intent: "mount", label: "Mount to active run", score: 90, reason: "active run context" });
  }
  if (shell === "hunt") {
    results.push({ intent: "attach-evidence", label: "Attach as evidence", score: 80, reason: "hunt evidence context" });
  }
  if (hasSandbox || lens === "sandboxes") {
    results.push({ intent: "mount", label: "Mount to sandbox", score: 85, reason: "sandbox environment" });
  }
  if (lens === "notes") {
    results.push({ intent: "cite", label: "Attach to note", score: 70, reason: "notes lens active" });
  }
  if (!results.some((r) => r.intent === "mount")) {
    results.push({ intent: "mount", label: "Mount file", score: 65, reason: "default file action" });
  }
  return results;
}

function scoreSignal(
  shell: string,
  lens: string,
  hasHunt: boolean,
): ScoredIntent[] {
  const results: ScoredIntent[] = [];
  if (!hasHunt) {
    results.push({ intent: "promote", label: "Create new hunt", score: 85, reason: "no active hunt" });
  }
  if (hasHunt) {
    results.push({ intent: "attach-target", label: "Add to hunt", score: 80, reason: "active hunt context" });
  }
  if (shell === "case") {
    results.push({ intent: "cite", label: "Cite in case", score: 75, reason: "case reporting phase" });
  }
  if (lens === "scopes") {
    results.push({ intent: "watch", label: "Add to watchlist", score: 80, reason: "scopes lens active" });
  }
  return results;
}

// ── Hook ────────────────────────────────────────────────────────

export function useDropPrediction(
  draggedKind: ArtifactKind | null,
): DropPrediction | null {
  const shell = useShell();
  const { lens } = useLens();
  const activeHunt = useActiveHunt();
  const huntStore = useHuntStore();

  return useMemo(() => {
    if (!draggedKind) return null;

    const hasHunt = activeHunt !== null;
    const hasRun = hasHunt
      ? activeHunt.runIds.some((id) => huntStore.runs[id]?.status === "running")
      : false;
    const hasCase = hasHunt ? activeHunt.caseId !== null : false;
    const hasSandbox = lens === "sandboxes";

    let scored: ScoredIntent[];
    switch (draggedKind) {
      case "entity":
        scored = scoreEntity(shell, lens, hasRun);
        break;
      case "receipt":
        scored = scoreReceipt(shell, lens, hasCase);
        break;
      case "file":
        scored = scoreFile(shell, lens, hasRun, hasSandbox);
        break;
      case "signal":
        scored = scoreSignal(shell, lens, hasHunt);
        break;
      default:
        // Fallback for note, query, snapshot, evidence
        scored = [
          { intent: "attach-evidence", label: "Attach as evidence", score: 70, reason: "default attachment" },
          { intent: "cite", label: "Cite", score: 60, reason: "general citation" },
        ];
        break;
    }

    // Deduplicate by intent, keeping the highest score
    const deduped = new Map<IntentType, ScoredIntent>();
    for (const entry of scored) {
      const existing = deduped.get(entry.intent);
      if (!existing || entry.score > existing.score) {
        deduped.set(entry.intent, entry);
      }
    }

    const sorted = Array.from(deduped.values()).sort((a, b) => b.score - a.score);
    if (sorted.length === 0) return null;

    const top = sorted[0];
    const alternates = sorted.slice(1);

    const explanation: IntentExplanation = {
      shortLabel: top.label,
      reason: top.reason,
      alternates: alternates.map((a) => a.label),
    };

    return {
      defaultAction: top.intent,
      defaultLabel: top.label,
      explanation,
      alternateActions: alternates.map((a) => ({
        intent: a.intent,
        label: a.label,
        confidence: a.score,
      })),
    };
  }, [draggedKind, shell, lens, activeHunt, huntStore]);
}
