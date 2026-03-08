/**
 * Hover Anticipation — tracks hover intent with predictive reveal.
 *
 * After a brief dwell (HOVER_ACTIVATION_MS), the hook activates and computes
 * context-aware subtargets (ProximalAction[]) for the hovered object. The
 * subtarget list adapts to the current shell mode and active hunt.
 */
import { useCallback, useMemo, useRef, useState } from "react";
import { useShell, useActiveHunt } from "../WorkbenchStateProvider";
import type { HoverIntent, ProximalAction } from "./types";
import { TIMING } from "./types";

export interface UseHoverAnticipationReturn {
  hoverIntent: HoverIntent | null;
  onHoverStart: (targetId: string, targetType: string) => void;
  onHoverEnd: () => void;
  isActivated: boolean;
}

// ── Subtarget tables ─────────────────────────────────────────────

const HUNT_PILL_ACTIONS: ProximalAction[] = [
  { id: "attach",  label: "Attach",  action: "attach-target", promoted: false },
  { id: "open",    label: "Open",    action: "open",          promoted: false },
  { id: "split",   label: "Split",   action: "split",         promoted: false },
  { id: "run",     label: "Run",     action: "run-input",     promoted: false },
];

const ENTITY_ACTIONS: ProximalAction[] = [
  { id: "attach", label: "Attach", action: "attach-target",   promoted: false },
  { id: "watch",  label: "Watch",  action: "watch",           promoted: false },
  { id: "hunt",   label: "Hunt",   action: "open",            promoted: false },
  { id: "split",  label: "Split",  action: "split",           promoted: false },
];

const RECEIPT_ACTIONS: ProximalAction[] = [
  { id: "cite",    label: "Cite",    action: "cite",    promoted: false },
  { id: "compare", label: "Compare", action: "compare", promoted: false },
  { id: "replay",  label: "Replay",  action: "open",    promoted: false },
  { id: "promote", label: "Promote", action: "promote", promoted: false },
];

const FILE_ACTIONS: ProximalAction[] = [
  { id: "open",    label: "Open",    action: "open",          promoted: false },
  { id: "mount",   label: "Mount",   action: "mount",         promoted: false },
  { id: "attach",  label: "Attach",  action: "attach-target", promoted: false },
  { id: "preview", label: "Preview", action: "open",          promoted: false },
];

const ACTIONS_BY_TYPE: Record<string, ProximalAction[]> = {
  "hunt-pill": HUNT_PILL_ACTIONS,
  entity:      ENTITY_ACTIONS,
  receipt:     RECEIPT_ACTIONS,
  file:        FILE_ACTIONS,
};

function computeSubtargets(
  targetType: string,
  shell: string,
  hasActiveHunt: boolean,
): ProximalAction[] {
  const base = ACTIONS_BY_TYPE[targetType];
  if (!base) return [];

  // Clone so we can mutate `promoted` per-context
  const actions = base.map((a) => ({ ...a }));

  // Promote the most likely action based on context
  if (targetType === "hunt-pill") {
    // In hunt shell with an active hunt, "Attach" is most useful
    const promoId = hasActiveHunt ? "attach" : "open";
    const target = actions.find((a) => a.id === promoId);
    if (target) target.promoted = true;
  } else if (targetType === "entity") {
    // Hunt shell -> "Attach"; wire shell -> "Watch"
    const promoId = shell === "hunt" ? "attach" : "watch";
    const target = actions.find((a) => a.id === promoId);
    if (target) target.promoted = true;
  } else if (targetType === "receipt") {
    // Case shell -> "Cite"; hunt shell -> "Compare"
    const promoId = shell === "case" ? "cite" : "compare";
    const target = actions.find((a) => a.id === promoId);
    if (target) target.promoted = true;
  } else if (targetType === "file") {
    // Lab shell -> "Open"; hunt shell -> "Mount"
    const promoId = shell === "lab" ? "open" : "mount";
    const target = actions.find((a) => a.id === promoId);
    if (target) target.promoted = true;
  }

  return actions;
}

// ── Hook ─────────────────────────────────────────────────────────

export function useHoverAnticipation(): UseHoverAnticipationReturn {
  const shell = useShell();
  const activeHunt = useActiveHunt();
  const hasActiveHunt = activeHunt !== null;

  const [hoverIntent, setHoverIntent] = useState<HoverIntent | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const onHoverStart = useCallback(
    (targetId: string, targetType: string) => {
      // Clear any pending timer from a previous hover
      if (timerRef.current) {
        clearTimeout(timerRef.current);
      }

      const enteredAt = Date.now();

      // Set initial (not yet activated) intent
      setHoverIntent({
        targetId,
        targetType,
        enteredAt,
        isActivated: false,
        subtargets: [],
      });

      // After dwell, activate and compute subtargets
      timerRef.current = setTimeout(() => {
        const subtargets = computeSubtargets(targetType, shell, hasActiveHunt);
        setHoverIntent({
          targetId,
          targetType,
          enteredAt,
          isActivated: true,
          subtargets,
        });
        timerRef.current = null;
      }, TIMING.HOVER_ACTIVATION_MS);
    },
    [shell, hasActiveHunt],
  );

  const onHoverEnd = useCallback(() => {
    if (timerRef.current) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setHoverIntent(null);
  }, []);

  const isActivated = useMemo(
    () => hoverIntent?.isActivated ?? false,
    [hoverIntent],
  );

  return { hoverIntent, onHoverStart, onHoverEnd, isActivated };
}
