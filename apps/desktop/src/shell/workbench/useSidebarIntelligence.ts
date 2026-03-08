/**
 * Intelligence hooks for sidebar Live Context and Suggested sections.
 * Pure data derivation — no UI.
 */
import { useMemo } from "react";
import type { TabState, LensId } from "./workbenchState";
import type { Artifact, ArtifactKind, HuntStore } from "./huntTypes";
import type { DragPayload } from "./DragDropContext";
import { useWorkbench, useActiveHunt } from "./WorkbenchStateProvider";

// ── Live Context ──────────────────────────────────────────────────

export interface LiveContextData {
  activeTab: TabState | null;
  recentTabs: TabState[];
  recentArtifacts: Artifact[];
  isEmpty: boolean;
}

export function useLiveContext(): LiveContextData {
  const { state } = useWorkbench();

  return useMemo(() => {
    const group = state.tabGroups[0];
    if (!group) return { activeTab: null, recentTabs: [], recentArtifacts: [], isEmpty: true };

    const activeTab = group.activeTabId
      ? group.tabs.find((t) => t.id === group.activeTabId) ?? null
      : null;

    // Walk tabHistory backwards, skip active, resolve to TabState, take 5
    const seen = new Set<string>();
    if (activeTab) seen.add(activeTab.id);
    const recentTabs: TabState[] = [];
    for (let i = group.tabHistory.length - 1; i >= 0 && recentTabs.length < 5; i--) {
      const tabId = group.tabHistory[i];
      if (seen.has(tabId)) continue;
      seen.add(tabId);
      const tab = group.tabs.find((t) => t.id === tabId);
      if (tab) recentTabs.push(tab);
    }

    // Recent artifacts across all hunts, sorted by createdAt desc, take 5
    const allArtifacts = Object.values(state.huntStore.artifacts);
    const recentArtifacts = allArtifacts
      .sort((a, b) => b.createdAt - a.createdAt)
      .slice(0, 5);

    const isEmpty = !activeTab && recentTabs.length === 0 && recentArtifacts.length === 0;

    return { activeTab, recentTabs, recentArtifacts, isEmpty };
  }, [state.tabGroups, state.huntStore.artifacts]);
}

// ── Suggested ─────────────────────────────────────────────────────

export interface SuggestedItem {
  id: string;
  kind: ArtifactKind;
  title: string;
  reason: string;
  sourceUri?: string;
  score: number;
  dragPayload?: DragPayload | null;
}

const LENS_FOCUS: Partial<Record<LensId, ArtifactKind[]>> = {
  entities: ["entity"],
  files: ["file"],
  notes: ["note"],
  scopes: ["entity", "signal"],
  history: ["query", "snapshot"],
};

export function useSuggested(lens: LensId): SuggestedItem[] {
  const { state } = useWorkbench();
  const activeHunt = useActiveHunt();
  const { huntStore } = state;

  return useMemo(() => {
    const items = new Map<string, SuggestedItem>();
    const focusKinds = LENS_FOCUS[lens];

    // Strategy 1: Same-hunt artifacts matching lens focus
    if (activeHunt && focusKinds) {
      for (const id of activeHunt.artifactIds) {
        const a = huntStore.artifacts[id];
        if (a && focusKinds.includes(a.kind)) {
          items.set(a.id, {
            id: a.id,
            kind: a.kind,
            title: a.title,
            reason: "in current hunt",
            sourceUri: a.sourceUri,
            score: 100,
            dragPayload: { kind: "artifact", artifactId: a.id, sourceHuntId: activeHunt.id, artifact: a },
          });
        }
      }
    }

    // Strategy 2: Recently added artifacts (score decays with age)
    const allArtifacts = Object.values(huntStore.artifacts);
    const now = Date.now();
    for (const a of allArtifacts) {
      if (items.has(a.id)) continue;
      const ageMs = now - a.createdAt;
      const decayScore = Math.max(10, 50 - Math.floor(ageMs / 60000)); // loses 1 point per minute
      items.set(a.id, {
        id: a.id,
        kind: a.kind,
        title: a.title,
        reason: `added ${formatTimeAgo(ageMs)}`,
        sourceUri: a.sourceUri,
        score: decayScore,
      });
    }

    // Strategy 3: Selection-related
    const { selection } = state;
    if (selection.entityId) {
      for (const a of allArtifacts) {
        if (a.sourceUri?.includes(selection.entityId) || a.id === selection.entityId) {
          const existing = items.get(a.id);
          if (existing) {
            if (75 > existing.score) {
              existing.score = 75;
              existing.reason = "related to selection";
            }
          } else {
            items.set(a.id, {
              id: a.id,
              kind: a.kind,
              title: a.title,
              reason: "related to selection",
              sourceUri: a.sourceUri,
              score: 75,
            });
          }
        }
      }
    }

    // Strategy 4: Cross-hunt overlap
    if (activeHunt) {
      const activeUris = new Set(
        activeHunt.artifactIds
          .map((id) => huntStore.artifacts[id]?.sourceUri)
          .filter(Boolean),
      );
      for (const hunt of Object.values(huntStore.hunts)) {
        if (hunt.id === activeHunt.id) continue;
        for (const id of hunt.artifactIds) {
          const a = huntStore.artifacts[id];
          if (!a || items.has(a.id)) continue;
          if (activeUris.has(a.sourceUri)) {
            items.set(a.id, {
              id: a.id,
              kind: a.kind,
              title: a.title,
              reason: "shared entity",
              sourceUri: a.sourceUri,
              score: 40,
            });
          }
        }
      }
    }

    return Array.from(items.values())
      .sort((a, b) => b.score - a.score)
      .slice(0, 8);
  }, [activeHunt, huntStore, lens, state.selection]);
}

// ── Helpers ───────────────────────────────────────────────────────

export function formatTimeAgo(ms: number): string {
  if (ms < 60000) return "just now";
  const minutes = Math.floor(ms / 60000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
