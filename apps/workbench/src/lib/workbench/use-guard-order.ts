import { useState, useCallback, useEffect } from "react";
import { GUARD_CATEGORIES, GUARD_REGISTRY } from "./guard-registry";

export type GuardViewMode = "category" | "custom";

const STORAGE_KEY = "clawdstrike_workbench_guard_order";

interface GuardOrderPreference {
  viewMode: GuardViewMode;
  guardOrder: string[];
}

/** Default flat order: all guard IDs in category order. */
function getDefaultGuardOrder(): string[] {
  return GUARD_CATEGORIES.flatMap((cat) => cat.guards);
}

function loadPreference(): GuardOrderPreference {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored) as Partial<GuardOrderPreference>;
      const viewMode: GuardViewMode =
        parsed.viewMode === "custom" ? "custom" : "category";
      let guardOrder = Array.isArray(parsed.guardOrder)
        ? parsed.guardOrder
        : getDefaultGuardOrder();

      // Ensure all known guards are present (in case new guards were added)
      const knownIds: Set<string> = new Set(GUARD_REGISTRY.map((g) => g.id));
      const existingIds = new Set(guardOrder.filter((id) => knownIds.has(id)));
      // Add any missing guards at the end
      for (const id of knownIds) {
        if (!existingIds.has(id)) {
          guardOrder.push(id);
        }
      }
      // Remove unknown guards
      guardOrder = guardOrder.filter((id) => knownIds.has(id));

      return { viewMode, guardOrder };
    }
  } catch {
    // ignore
  }
  return { viewMode: "category", guardOrder: getDefaultGuardOrder() };
}

function savePreference(pref: GuardOrderPreference) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(pref));
  } catch {
    // ignore
  }
}

export function useGuardOrder() {
  const [pref] = useState(loadPreference);
  const [viewMode, setViewModeRaw] = useState<GuardViewMode>(pref.viewMode);
  const [guardOrder, setGuardOrderRaw] = useState<string[]>(pref.guardOrder);

  // Persist on change
  useEffect(() => {
    savePreference({ viewMode, guardOrder });
  }, [viewMode, guardOrder]);

  const setViewMode = setViewModeRaw;
  const setGuardOrder = setGuardOrderRaw;

  /** Move a guard up by one position. */
  const moveGuardUp = useCallback((guardId: string) => {
    setGuardOrderRaw((prev) => {
      const idx = prev.indexOf(guardId);
      if (idx <= 0) return prev;
      const next = [...prev];
      next[idx] = next[idx - 1];
      next[idx - 1] = guardId;
      return next;
    });
  }, []);

  /** Move a guard down by one position. */
  const moveGuardDown = useCallback((guardId: string) => {
    setGuardOrderRaw((prev) => {
      const idx = prev.indexOf(guardId);
      if (idx < 0 || idx >= prev.length - 1) return prev;
      const next = [...prev];
      next[idx] = next[idx + 1];
      next[idx + 1] = guardId;
      return next;
    });
  }, []);

  /** Reorder: move sourceId to the position of targetId (inserts before target). */
  const reorderGuard = useCallback((sourceId: string, targetId: string) => {
    if (sourceId === targetId) return;
    setGuardOrderRaw((prev) => {
      const sourceIdx = prev.indexOf(sourceId);
      const targetIdx = prev.indexOf(targetId);
      if (sourceIdx < 0 || targetIdx < 0) return prev;
      const next = [...prev];
      // Remove source
      next.splice(sourceIdx, 1);
      // Find target's new index after removal
      const insertIdx = next.indexOf(targetId);
      // Insert before target
      next.splice(insertIdx, 0, sourceId);
      return next;
    });
  }, []);

  /** Move sourceId to a specific index in the order. */
  const moveGuardToIndex = useCallback((sourceId: string, targetIndex: number) => {
    setGuardOrderRaw((prev) => {
      const sourceIdx = prev.indexOf(sourceId);
      if (sourceIdx < 0) return prev;
      if (sourceIdx === targetIndex) return prev;
      const next = [...prev];
      next.splice(sourceIdx, 1);
      const clampedIdx = Math.max(0, Math.min(targetIndex, next.length));
      next.splice(clampedIdx, 0, sourceId);
      return next;
    });
  }, []);

  /** Reset to default category order. */
  const resetOrder = useCallback(() => {
    setGuardOrderRaw(getDefaultGuardOrder());
  }, []);

  return {
    viewMode,
    setViewMode,
    guardOrder,
    setGuardOrder,
    moveGuardUp,
    moveGuardDown,
    reorderGuard,
    moveGuardToIndex,
    resetOrder,
  };
}
