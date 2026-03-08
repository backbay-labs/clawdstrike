/**
 * Path Memory — tracks pivot chains and suggests related next actions.
 *
 * Every tab change is a "pivot". Consecutive pivots form a chain that resets
 * on shell change or a 15-minute gap. The hook exposes breadcrumbs (the last
 * 5 pivots formatted for display) and a suggested next action computed by
 * matching the current chain against common investigation patterns.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { useActiveTab, useShell, useActiveHunt } from "../WorkbenchStateProvider";
import type { PivotStep, PivotChain } from "./types";

// ── Public Types ─────────────────────────────────────────────────

export interface PathSuggestion {
  label: string;
  action: string;
  fromStep: PivotStep;
  confidence: number;
}

export interface Breadcrumb {
  label: string;
  objectId: string;
  objectType: string;
}

export interface PathMemoryState {
  currentChain: PivotChain;
  chainLength: number;
  lastPivotAge: string;
  suggestedAction: PathSuggestion | null;
  breadcrumbs: Breadcrumb[];
}

// ── Constants ────────────────────────────────────────────────────

const MAX_STEPS = 20;
const CHAIN_GAP_MS = 15 * 60 * 1000; // 15 minutes

// ── Time Formatting ──────────────────────────────────────────────

function formatTimeAgo(timestamp: number): string {
  const delta = Date.now() - timestamp;
  if (delta < 60_000) return `${Math.max(1, Math.floor(delta / 1000))}s ago`;
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`;
  return `${Math.floor(delta / 3_600_000)}h ago`;
}

// ── Pattern Matching ─────────────────────────────────────────────

// Common investigation patterns: ordered sequences of objectType values.
// When the tail of the current chain matches a prefix, we suggest the next step.
const PATTERNS: { sequence: string[]; nextLabel: string; nextAction: string; confidence: number }[] = [
  { sequence: ["signal-thread", "hunt", "entity", "receipt"], nextLabel: "Open linked note",    nextAction: "open-note",      confidence: 75 },
  { sequence: ["entity", "file"],                             nextLabel: "Return to entity",    nextAction: "navigate-back",  confidence: 70 },
  { sequence: ["hunt", "entity", "file"],                     nextLabel: "Return to entity",    nextAction: "navigate-back",  confidence: 65 },
  { sequence: ["receipt", "entity"],                           nextLabel: "Open hunt summary",   nextAction: "open-hunt",      confidence: 60 },
];

function matchPattern(chain: PivotStep[]): PathSuggestion | null {
  if (chain.length < 2) return null;

  const types = chain.map((s) => s.objectType);

  for (const pattern of PATTERNS) {
    const seq = pattern.sequence;
    if (types.length < seq.length) continue;
    const tail = types.slice(types.length - seq.length);
    if (tail.every((t, i) => t === seq[i])) {
      return {
        label: pattern.nextLabel,
        action: pattern.nextAction,
        fromStep: chain[chain.length - 1],
        confidence: pattern.confidence,
      };
    }
  }

  // Fallback: if many recent chain steps are hunt artifacts, suggest summary
  const huntArtifactTypes = new Set(["entity", "receipt", "note", "file", "evidence"]);
  const recent = chain.slice(-5);
  const huntArtifactCount = recent.filter((s) => huntArtifactTypes.has(s.objectType)).length;
  if (huntArtifactCount >= 3) {
    return {
      label: "Open hunt summary",
      action: "open-hunt",
      fromStep: chain[chain.length - 1],
      confidence: 55,
    };
  }

  return null;
}

// ── Hook ─────────────────────────────────────────────────────────

export function usePathMemory(): PathMemoryState {
  const activeTab = useActiveTab();
  const shell = useShell();
  const activeHunt = useActiveHunt();

  const stepsRef = useRef<PivotStep[]>([]);
  const lastShellRef = useRef(shell);
  const [revision, setRevision] = useState(0);

  // Push new pivot on tab change
  useEffect(() => {
    if (!activeTab) return;

    const now = Date.now();
    const steps = stepsRef.current;

    // Reset chain on shell change
    if (shell !== lastShellRef.current) {
      stepsRef.current = [];
      lastShellRef.current = shell;
    }

    // Reset chain if gap exceeds threshold
    if (steps.length > 0 && now - steps[steps.length - 1].timestamp > CHAIN_GAP_MS) {
      stepsRef.current = [];
    }

    // Deduplicate consecutive same-objectId pivots
    const lastStep = stepsRef.current[stepsRef.current.length - 1];
    if (lastStep && lastStep.objectId === activeTab.id) return;

    const step: PivotStep = {
      objectType: activeTab.kind,
      objectId: activeTab.id,
      objectTitle: activeTab.title,
      timestamp: now,
    };

    stepsRef.current = [...stepsRef.current.slice(-(MAX_STEPS - 1)), step];
    setRevision((r) => r + 1);
  }, [activeTab?.id, activeTab?.kind, activeTab?.title, shell]);

  return useMemo(() => {
    // Suppress unused-var lint — revision drives recalculation
    void revision;

    const steps = stepsRef.current;
    const chain: PivotChain = {
      steps,
      huntId: activeHunt?.id,
    };

    const breadcrumbs: Breadcrumb[] = steps.slice(-5).map((s) => ({
      label: `${s.objectType}: ${s.objectTitle}`,
      objectId: s.objectId,
      objectType: s.objectType,
    }));

    const lastPivotAge = steps.length > 0
      ? formatTimeAgo(steps[steps.length - 1].timestamp)
      : "";

    const suggestedAction = matchPattern(steps);

    return {
      currentChain: chain,
      chainLength: steps.length,
      lastPivotAge,
      suggestedAction,
      breadcrumbs,
    };
  }, [revision, activeHunt?.id]);
}
