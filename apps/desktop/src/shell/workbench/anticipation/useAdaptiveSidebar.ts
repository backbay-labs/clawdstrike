/**
 * Adaptive Sidebar — phase-aware section visibility, ordering, and promotion.
 *
 * Each sidebar section has a visibility set (which phases it appears in),
 * a per-phase priority (lower = higher on screen), and an optional "promoted"
 * flag that gives it stronger visual weight in a specific phase.
 *
 * The hook reuses the same phase-detection logic as usePredictiveLayout so
 * the two always agree on the current WorkPhase.
 */
import { useMemo } from "react";
import { useShell, useLens, useActiveHunt, useHuntStore } from "../WorkbenchStateProvider";
import type { WorkPhase } from "./types";
import { PHASE_SIGNALS } from "./types";

// ── Public types ─────────────────────────────────────────────────

export interface AdaptiveSidebarSection {
  id: string;
  title: string;
  /** Whether this section should be rendered in the current phase. */
  visible: boolean;
  /** Sort key — lower values appear higher in the sidebar. */
  priority: number;
  /** If true, the section should receive stronger visual weight. */
  promoted: boolean;
}

export interface AdaptiveSidebarState {
  phase: WorkPhase;
  sections: AdaptiveSidebarSection[];
}

// ── Section definitions ──────────────────────────────────────────

interface SectionDef {
  id: string;
  title: string;
  /** Phases in which this section is visible. Empty = always visible. */
  visibleIn: WorkPhase[] | "always";
  /** Per-phase priority (lower = higher on screen). */
  priorities: Record<WorkPhase, number>;
  /** Phase in which this section is promoted (if any). */
  promotedIn: WorkPhase | null;
  /** When true, requires an active hunt to be visible. */
  requiresHunt?: boolean;
}

const SECTION_DEFS: SectionDef[] = [
  {
    id: "active-run",
    title: "Active Run",
    visibleIn: ["investigation"],
    priorities: { discovery: 99, investigation: 1, triage: 99, reporting: 99 },
    promotedIn: "investigation",
  },
  {
    id: "suggested-targets",
    title: "Suggested Targets",
    visibleIn: ["discovery", "triage"],
    priorities: { discovery: 1, investigation: 99, triage: 2, reporting: 99 },
    promotedIn: "discovery",
  },
  {
    id: "current-hunt",
    title: "Current Hunt",
    visibleIn: ["discovery", "investigation", "triage", "reporting"],
    priorities: { discovery: 3, investigation: 3, triage: 1, reporting: 3 },
    promotedIn: null,
    requiresHunt: true,
  },
  {
    id: "watchlists",
    title: "Watchlists",
    visibleIn: ["discovery", "investigation"],
    priorities: { discovery: 2, investigation: 5, triage: 3, reporting: 99 },
    promotedIn: null,
  },
  {
    id: "recent-receipts",
    title: "Recent Receipts",
    visibleIn: ["investigation", "reporting"],
    priorities: { discovery: 99, investigation: 4, triage: 99, reporting: 4 },
    promotedIn: null,
  },
  {
    id: "case-link",
    title: "Case Link",
    visibleIn: ["reporting"],
    priorities: { discovery: 99, investigation: 99, triage: 99, reporting: 1 },
    promotedIn: "reporting",
  },
  {
    id: "citations",
    title: "Citations",
    visibleIn: ["reporting"],
    priorities: { discovery: 99, investigation: 99, triage: 99, reporting: 2 },
    promotedIn: null,
  },
  {
    id: "related-notes",
    title: "Related Notes",
    visibleIn: ["triage", "reporting"],
    priorities: { discovery: 99, investigation: 99, triage: 4, reporting: 3 },
    promotedIn: null,
  },
  {
    id: "quick-actions",
    title: "Quick Actions",
    visibleIn: "always",
    priorities: { discovery: 4, investigation: 6, triage: 5, reporting: 5 },
    promotedIn: null,
  },
  {
    id: "inputs",
    title: "Inputs",
    visibleIn: ["investigation"],
    priorities: { discovery: 99, investigation: 2, triage: 99, reporting: 99 },
    promotedIn: null,
  },
  {
    id: "suggested-related",
    title: "Suggested Related",
    visibleIn: ["investigation"],
    priorities: { discovery: 99, investigation: 4, triage: 99, reporting: 99 },
    promotedIn: null,
  },
];

// ── Phase detection (shared logic) ───────────────────────────────

function detectPhase(
  shell: string,
  lens: string,
  hasRun: boolean,
  hasCase: boolean,
): WorkPhase {
  const phases = Object.keys(PHASE_SIGNALS) as WorkPhase[];
  let best: WorkPhase = "discovery";
  let bestScore = -1;

  for (const phase of phases) {
    const sig = PHASE_SIGNALS[phase];
    let s = 0;
    if (sig.shells.includes(shell as never)) s += 30;
    if (sig.lenses.includes(lens as never)) s += 20;
    if (sig.hasRun === null || sig.hasRun === hasRun) s += 25;
    if (sig.hasCase === null || sig.hasCase === hasCase) s += 25;
    if (s > bestScore) {
      bestScore = s;
      best = phase;
    }
  }

  return best;
}

// ── Hook ─────────────────────────────────────────────────────────

export function useAdaptiveSidebar(): AdaptiveSidebarState {
  const shell = useShell();
  const { lens: currentLens } = useLens();
  const activeHunt = useActiveHunt();
  const huntStore = useHuntStore();

  return useMemo(() => {
    const hasRun = activeHunt
      ? activeHunt.runIds.some((id) => huntStore.runs[id]?.status === "running")
      : false;
    const hasCase = activeHunt?.caseId != null;
    const hasHunt = activeHunt != null;

    const phase = detectPhase(shell, currentLens, hasRun, hasCase);

    const sections: AdaptiveSidebarSection[] = SECTION_DEFS.map((def) => {
      // Visibility: "always" means every phase; otherwise check phase list
      let visible =
        def.visibleIn === "always" || def.visibleIn.includes(phase);

      // Sections that require an active hunt are hidden if none exists
      if (def.requiresHunt && !hasHunt) {
        visible = false;
      }

      return {
        id: def.id,
        title: def.title,
        visible,
        priority: def.priorities[phase],
        promoted: def.promotedIn === phase,
      };
    });

    // Sort visible sections by priority (ascending — lower = higher on screen)
    sections.sort((a, b) => a.priority - b.priority);

    return { phase, sections };
  }, [shell, currentLens, activeHunt, huntStore.runs]);
}
