/**
 * Staging Shelf — manages a temporary holding area for items the operator
 * wants to act on together.
 *
 * Items are staged explicitly (drag, shortcut, context menu) and the hook
 * generates contextual suggestions based on what's currently staged.
 */
import { createContext, createElement, useCallback, useContext, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useActiveHunt, useHuntStore } from "../WorkbenchStateProvider";
import type { StagedItem, StagingSuggestion } from "./types";

// ── Public Types ─────────────────────────────────────────────────

export interface UseStagingShelfReturn {
  items: StagedItem[];
  suggestions: StagingSuggestion[];
  stageItem: (item: Omit<StagedItem, "stagedAt">) => void;
  unstageItem: (itemId: string) => void;
  clearStaging: () => void;
}

// ── Constants ────────────────────────────────────────────────────

const MAX_STAGED = 10;
const MAX_SUGGESTIONS = 3;

// ── Hook ─────────────────────────────────────────────────────────

function useStagingShelfState(): UseStagingShelfReturn {
  const [items, setItems] = useState<StagedItem[]>([]);
  const activeHunt = useActiveHunt();
  const huntStore = useHuntStore();

  const stageItem = useCallback((item: Omit<StagedItem, "stagedAt">) => {
    setItems((prev) => {
      // Don't add duplicates
      if (prev.some((i) => i.id === item.id)) return prev;
      const next = [...prev, { ...item, stagedAt: Date.now() }];
      // Cap at max
      return next.length > MAX_STAGED ? next.slice(-MAX_STAGED) : next;
    });
  }, []);

  const unstageItem = useCallback((itemId: string) => {
    setItems((prev) => prev.filter((i) => i.id !== itemId));
  }, []);

  const clearStaging = useCallback(() => {
    setItems([]);
  }, []);

  const suggestions = useMemo(() => {
    if (items.length === 0) return [];

    const result: StagingSuggestion[] = [];

    // Check if exactly 2 receipts → "Compare 2 receipts"
    const receiptItems = items.filter((i) => i.kind === "receipt");
    if (receiptItems.length === 2) {
      result.push({
        label: "Compare 2 receipts",
        action: "compare-receipts",
        itemIds: receiptItems.map((i) => i.id),
        confidence: 85,
      });
    }

    // All items from same hunt → "Add all to {huntTitle}"
    const sourceHuntIds = new Set(items.map((i) => i.sourceHuntId).filter(Boolean));
    if (activeHunt && sourceHuntIds.size <= 1) {
      result.push({
        label: `Add all to ${activeHunt.title}`,
        action: "add-to-hunt",
        itemIds: items.map((i) => i.id),
        confidence: 80,
      });
    }

    // Items include notes → "Create note from selected artifacts"
    const noteItems = items.filter((i) => i.kind === "note");
    if (noteItems.length > 0) {
      result.push({
        label: "Create note from selected artifacts",
        action: "create-composite-note",
        itemIds: items.map((i) => i.id),
        confidence: 70,
      });
    }

    // Any files → "Mount {n} file(s) to Run" (only if an active run exists)
    const fileItems = items.filter((i) => i.kind === "file");
    if (fileItems.length > 0 && activeHunt) {
      const activeRun = activeHunt.runIds
        .map((rid) => huntStore.runs[rid])
        .find((r) => r && r.status === "running");
      if (activeRun) {
        result.push({
          label: `Mount ${fileItems.length} file${fileItems.length > 1 ? "s" : ""} to Run`,
          action: "mount-to-run",
          itemIds: fileItems.map((i) => i.id),
          confidence: 65,
        });
      }
    }

    // Multiple items → "Start new Hunt from {n} items"
    if (items.length >= 2) {
      result.push({
        label: `Start new Hunt from ${items.length} items`,
        action: "create-hunt-from-staged",
        itemIds: items.map((i) => i.id),
        confidence: 60,
      });
    }

    // Sort by confidence descending, take top N
    result.sort((a, b) => b.confidence - a.confidence);
    return result.slice(0, MAX_SUGGESTIONS);
  }, [items, activeHunt, huntStore.runs]);

  return { items, suggestions, stageItem, unstageItem, clearStaging };
}

const StagingShelfContext = createContext<UseStagingShelfReturn | null>(null);

export function StagingShelfProvider({ children }: { children: ReactNode }) {
  const value = useStagingShelfState();

  return createElement(StagingShelfContext.Provider, { value }, children);
}

export function useStagingShelf(): UseStagingShelfReturn {
  const context = useContext(StagingShelfContext);
  if (!context) {
    throw new Error("useStagingShelf must be used within a StagingShelfProvider");
  }
  return context;
}
