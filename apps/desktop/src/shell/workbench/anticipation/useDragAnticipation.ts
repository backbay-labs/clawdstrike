/**
 * Drag Anticipation — Attach Mode, Spring-loaded Expansion, Gesture Grammar.
 *
 * When a drag begins the hook enters "Attach Mode": it reads the dragged
 * artifact kind, computes compatible drop targets with emphasis ranking,
 * builds semantic drop roles (ranked by context), and tracks spring-loaded
 * expansion and modifier-key overrides.
 *
 * The state is fully derived — no destructive side effects.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  useActiveHunt,
  useHuntStore,
  useHuntDock,
} from "../WorkbenchStateProvider";
import type { DragPayload } from "../DragDropContext";
import type { DropRole, DropSemantic } from "./types";
import { DRAG_ROLE_MAP, TIMING } from "./types";

// ── Public types ────────────────────────────────────────────────

export interface CompatibleTarget {
  id: string;
  type: "hunt" | "run" | "case" | "lens" | "staging";
  label: string;
  emphasis: "primary" | "secondary" | "tertiary";
}

export interface AttachModeState {
  active: boolean;
  draggedKind: string | null;
  compatibleTargets: CompatibleTarget[];
  springLoadedId: string | null;
  dropRoles: DropRole[];
  defaultRole: DropRole | null;
  modifierOverride: DropSemantic | null;
}

export interface UseDragAnticipationReturn extends AttachModeState {
  onTargetHover: (targetId: string) => void;
  onTargetLeave: () => void;
}

// ── Internals ───────────────────────────────────────────────────

const EMPTY_STATE: AttachModeState = {
  active: false,
  draggedKind: null,
  compatibleTargets: [],
  springLoadedId: null,
  dropRoles: [],
  defaultRole: null,
  modifierOverride: null,
};

/** Map a list of compatible semantics to scored DropRole objects. */
function buildDropRoles(
  semantics: DropSemantic[],
  draggedKind: string,
  hasActiveRun: boolean,
  hasOpenCase: boolean,
): DropRole[] {
  if (semantics.length === 0) return [];

  // Score each semantic contextually (higher = more likely default)
  const scored = semantics.map((sem): DropRole => {
    let score = 50; // baseline
    const id = `role-${sem}`;
    const label = sem.charAt(0).toUpperCase() + sem.slice(1).replace(/-/g, " ");

    // Context-specific boosts
    if (sem === "run-input" && hasActiveRun) score = 90;
    else if (sem === "target" && draggedKind === "entity" && !hasActiveRun) score = 85;
    else if (sem === "cite" && draggedKind === "receipt" && hasOpenCase) score = 88;
    else if (sem === "mount" && draggedKind === "file" && hasActiveRun) score = 87;
    else if (sem === "evidence" && draggedKind === "file" && !hasActiveRun) score = 82;
    else if (sem === "target" && draggedKind === "signal") score = 80;
    else if (sem === "target" && draggedKind === "signal-thread") score = 80;
    else if (sem === "evidence" && draggedKind === "receipt") score = 75;
    else if (sem === "watch") score = 60;
    else if (sem === "notes") score = 45;
    else if (sem === "compare") score = 55;

    return { id, label, semantic: sem, isDefault: false, confidence: score };
  });

  // Sort descending by confidence
  scored.sort((a, b) => b.confidence - a.confidence);

  // Mark highest as default
  if (scored.length > 0) {
    scored[0] = { ...scored[0], isDefault: true };
  }

  return scored;
}

/** Build the compatible target list from current workspace state. */
function buildCompatibleTargets(
  activeHuntId: string | null,
  activeRunId: string | null,
  huntStore: ReturnType<typeof useHuntStore>,
  activeCaseId: string | null,
): CompatibleTarget[] {
  const targets: CompatibleTarget[] = [];

  // Active hunt → primary
  if (activeHuntId) {
    const hunt = huntStore.hunts[activeHuntId];
    if (hunt) {
      targets.push({
        id: hunt.id,
        type: "hunt",
        label: hunt.title,
        emphasis: "primary",
      });
    }
  }

  // Active run → primary
  if (activeRunId) {
    const run = huntStore.runs[activeRunId];
    if (run) {
      targets.push({
        id: run.id,
        type: "run",
        label: run.label,
        emphasis: "primary",
      });
    }
  }

  // Other hunts in dock → secondary
  const dockIds = new Set([
    ...Object.keys(huntStore.hunts),
  ]);
  for (const id of dockIds) {
    if (id === activeHuntId) continue;
    const hunt = huntStore.hunts[id];
    if (hunt) {
      targets.push({
        id: hunt.id,
        type: "hunt",
        label: hunt.title,
        emphasis: "secondary",
      });
    }
  }

  // Open case → secondary
  if (activeCaseId) {
    const caseObj = huntStore.cases[activeCaseId];
    if (caseObj) {
      targets.push({
        id: caseObj.id,
        type: "case",
        label: caseObj.title,
        emphasis: "secondary",
      });
    }
  }

  // Staging shelf → tertiary (always available as a conceptual target)
  targets.push({
    id: "staging-shelf",
    type: "staging",
    label: "Staging",
    emphasis: "tertiary",
  });

  return targets;
}

// ── Hook ────────────────────────────────────────────────────────

export function useDragAnticipation(
  dragActive: boolean,
  dragPayload: DragPayload | null,
): UseDragAnticipationReturn {
  const activeHunt = useActiveHunt();
  const huntStore = useHuntStore();
  const dock = useHuntDock();

  // Spring-loaded expansion
  const [springLoadedId, setSpringLoadedId] = useState<string | null>(null);
  const springTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retractTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Modifier key tracking
  const [modifierOverride, setModifierOverride] = useState<DropSemantic | null>(null);

  // ── Derive active run / case ────────────────────────────────
  const activeRunId = useMemo(() => {
    if (!activeHunt) return null;
    for (const runId of activeHunt.runIds) {
      const run = huntStore.runs[runId];
      if (run?.status === "running") return runId;
    }
    return null;
  }, [activeHunt, huntStore.runs]);

  const activeCaseId = useMemo(() => {
    return activeHunt?.caseId ?? null;
  }, [activeHunt]);

  // ── Dragged kind ────────────────────────────────────────────
  const draggedKind = useMemo(() => {
    if (!dragActive || !dragPayload) return null;
    return dragPayload.artifact.kind as string;
  }, [dragActive, dragPayload]);

  // ── Compatible targets ──────────────────────────────────────
  const compatibleTargets = useMemo(() => {
    if (!dragActive) return [];
    return buildCompatibleTargets(
      dock.activeHuntId,
      activeRunId,
      huntStore,
      activeCaseId,
    );
  }, [dragActive, dock.activeHuntId, activeRunId, huntStore, activeCaseId]);

  // ── Drop roles ──────────────────────────────────────────────
  const dropRoles = useMemo(() => {
    if (!draggedKind) return [];
    const semantics = DRAG_ROLE_MAP[draggedKind] ?? [];
    return buildDropRoles(
      semantics,
      draggedKind,
      activeRunId !== null,
      activeCaseId !== null,
    );
  }, [draggedKind, activeRunId, activeCaseId]);

  const defaultRole = useMemo(() => {
    return dropRoles.find((r) => r.isDefault) ?? null;
  }, [dropRoles]);

  // ── Spring-loaded expansion ─────────────────────────────────

  const clearTimers = useCallback(() => {
    if (springTimerRef.current) {
      clearTimeout(springTimerRef.current);
      springTimerRef.current = null;
    }
    if (retractTimerRef.current) {
      clearTimeout(retractTimerRef.current);
      retractTimerRef.current = null;
    }
  }, []);

  const onTargetHover = useCallback(
    (targetId: string) => {
      if (!dragActive) return;
      clearTimers();

      springTimerRef.current = setTimeout(() => {
        setSpringLoadedId(targetId);
        springTimerRef.current = null;
      }, TIMING.SPRING_LOAD_MS);
    },
    [dragActive, clearTimers],
  );

  const onTargetLeave = useCallback(() => {
    clearTimers();

    if (springLoadedId) {
      retractTimerRef.current = setTimeout(() => {
        setSpringLoadedId(null);
        retractTimerRef.current = null;
      }, TIMING.SPRING_RETRACT_MS);
    }
  }, [springLoadedId, clearTimers]);

  // ── Modifier key listeners ──────────────────────────────────
  useEffect(() => {
    if (!dragActive) {
      setModifierOverride(null);
      return;
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Shift") setModifierOverride("evidence");
      else if (e.key === "Alt") setModifierOverride("cite");
    };

    const onKeyUp = (e: KeyboardEvent) => {
      if (e.key === "Shift" || e.key === "Alt") {
        setModifierOverride(null);
      }
    };

    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("keyup", onKeyUp);
    };
  }, [dragActive]);

  // ── Reset on drag end ───────────────────────────────────────
  useEffect(() => {
    if (!dragActive) {
      clearTimers();
      setSpringLoadedId(null);
      setModifierOverride(null);
    }
  }, [dragActive, clearTimers]);

  // ── Assemble state ─────────────────────────────────────────

  const state: AttachModeState = useMemo(() => {
    if (!dragActive) return EMPTY_STATE;
    return {
      active: true,
      draggedKind,
      compatibleTargets,
      springLoadedId,
      dropRoles,
      defaultRole,
      modifierOverride,
    };
  }, [
    dragActive,
    draggedKind,
    compatibleTargets,
    springLoadedId,
    dropRoles,
    defaultRole,
    modifierOverride,
  ]);

  return {
    ...state,
    onTargetHover,
    onTargetLeave,
  };
}
