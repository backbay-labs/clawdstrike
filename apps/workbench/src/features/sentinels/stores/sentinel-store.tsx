import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/lib/create-selectors";
import type {
  Sentinel,
  SentinelMemory,
} from "@/lib/workbench/sentinel-types";
import type {
  CreateSentinelConfig,
  StatsEvent,
  SentinelMutablePatch,
} from "@/lib/workbench/sentinel-manager";
import {
  createSentinel as engineCreateSentinel,
  createDefaultRuntimeBinding,
  updateSentinel as engineUpdateSentinel,
  deleteSentinel as engineDeleteSentinel,
  activateSentinel as engineActivateSentinel,
  pauseSentinel as enginePauseSentinel,
  retireSentinel as engineRetireSentinel,
  updateStats as engineUpdateStats,
} from "@/lib/workbench/sentinel-manager";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SentinelState {
  sentinels: Sentinel[];
  activeSentinelId: string | null;
  loading: boolean;
  actions: SentinelActions;
}

interface SentinelActions {
  createSentinel: (config: CreateSentinelConfig) => Promise<Sentinel>;
  updateSentinel: (sentinelId: string, patch: SentinelMutablePatch) => void;
  deleteSentinel: (sentinelId: string) => void;
  setActiveSentinel: (sentinelId: string | null) => void;
  activateSentinel: (sentinelId: string) => void;
  pauseSentinel: (sentinelId: string) => void;
  retireSentinel: (sentinelId: string) => void;
  updateMemory: (sentinelId: string, memory: SentinelMemory) => void;
  updateStats: (sentinelId: string, event: StatsEvent) => void;
  load: (sentinels: Sentinel[]) => void;
}

// ---------------------------------------------------------------------------
// localStorage persistence helpers
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_sentinels";

let persistTimer: ReturnType<typeof setTimeout> | null = null;

function schedulePersist(state: SentinelState): void {
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    try {
      const persisted = {
        sentinels: state.sentinels,
        activeSentinelId: state.activeSentinelId,
      };
      localStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));
    } catch (e) {
      console.error("[sentinel-store] persistSentinels failed:", e);
    }
    persistTimer = null;
  }, 500);
}

function loadPersistedSentinels(): Pick<SentinelState, "sentinels" | "activeSentinelId" | "loading"> | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.sentinels)) {
      console.warn("[sentinel-store] Invalid persisted sentinel data, using defaults");
      return null;
    }

    // Validate each entry has required fields
    const validSentinels: Sentinel[] = parsed.sentinels.filter(
      (s: unknown): s is Sentinel =>
        typeof s === "object" &&
        s !== null &&
        typeof (s as Record<string, unknown>).id === "string" &&
        typeof (s as Record<string, unknown>).name === "string" &&
        typeof (s as Record<string, unknown>).mode === "string" &&
        typeof (s as Record<string, unknown>).status === "string",
    );

    if (validSentinels.length === 0) return null;

    const normalizedSentinels = validSentinels.map((sentinel) => ({
      ...sentinel,
      runtime: createDefaultRuntimeBinding(
        sentinel.mode,
        sentinel.runtime,
        sentinel.fleetAgentId,
      ),
    }));

    const activeSentinelId =
      typeof parsed.activeSentinelId === "string" &&
      normalizedSentinels.some((s) => s.id === parsed.activeSentinelId)
        ? parsed.activeSentinelId
        : normalizedSentinels[0].id;

    return {
      sentinels: normalizedSentinels,
      activeSentinelId,
      loading: false,
    };
  } catch (e) {
    console.warn("[sentinel-store] loadPersistedSentinels failed:", e);
    return null;
  }
}

function getInitialData(): Pick<SentinelState, "sentinels" | "activeSentinelId" | "loading"> {
  const restored = loadPersistedSentinels();
  if (restored) return restored;

  return {
    sentinels: [],
    activeSentinelId: null,
    loading: false,
  };
}

// ---------------------------------------------------------------------------
// Zustand store
// ---------------------------------------------------------------------------

const useSentinelStoreBase = create<SentinelState>()(
  immer((set, get) => {
    const initial = getInitialData();

    return {
      sentinels: initial.sentinels,
      activeSentinelId: initial.activeSentinelId,
      loading: initial.loading,

      actions: {
        createSentinel: async (config: CreateSentinelConfig): Promise<Sentinel> => {
          const sentinel = await engineCreateSentinel(config);
          set((state) => {
            state.sentinels.push(sentinel);
            state.activeSentinelId = sentinel.id;
          });
          schedulePersist(get());
          return sentinel;
        },

        updateSentinel: (sentinelId: string, patch: SentinelMutablePatch) => {
          set((state) => {
            const idx = state.sentinels.findIndex((s) => s.id === sentinelId);
            if (idx !== -1) {
              // engineUpdateSentinel is a pure function expecting an immutable Sentinel,
              // so we pass a snapshot and replace the result.
              const updated = engineUpdateSentinel(
                state.sentinels[idx] as Sentinel,
                patch,
              );
              state.sentinels[idx] = updated as any;
            }
          });
          schedulePersist(get());
        },

        deleteSentinel: (sentinelId: string) => {
          set((state) => {
            const remaining = engineDeleteSentinel(sentinelId, state.sentinels as Sentinel[]);
            const needNewActive = state.activeSentinelId === sentinelId;
            state.sentinels = remaining as any;
            if (needNewActive) {
              state.activeSentinelId =
                remaining.length > 0 ? remaining[0].id : null;
            }
          });
          schedulePersist(get());
        },

        setActiveSentinel: (sentinelId: string | null) => {
          set((state) => {
            if (sentinelId !== null && !state.sentinels.some((s) => s.id === sentinelId)) {
              return;
            }
            state.activeSentinelId = sentinelId;
          });
          schedulePersist(get());
        },

        activateSentinel: (sentinelId: string) => {
          set((state) => {
            const idx = state.sentinels.findIndex((s) => s.id === sentinelId);
            if (idx !== -1) {
              try {
                const activated = engineActivateSentinel(state.sentinels[idx] as Sentinel);
                state.sentinels[idx] = activated as any;
              } catch {
                // Invalid transition -- no-op
              }
            }
          });
          schedulePersist(get());
        },

        pauseSentinel: (sentinelId: string) => {
          set((state) => {
            const idx = state.sentinels.findIndex((s) => s.id === sentinelId);
            if (idx !== -1) {
              try {
                const paused = enginePauseSentinel(state.sentinels[idx] as Sentinel);
                state.sentinels[idx] = paused as any;
              } catch {
                // Invalid transition -- no-op
              }
            }
          });
          schedulePersist(get());
        },

        retireSentinel: (sentinelId: string) => {
          set((state) => {
            const idx = state.sentinels.findIndex((s) => s.id === sentinelId);
            if (idx !== -1) {
              try {
                const retired = engineRetireSentinel(state.sentinels[idx] as Sentinel);
                state.sentinels[idx] = retired as any;
              } catch {
                // Invalid transition -- no-op
              }
            }
          });
          schedulePersist(get());
        },

        updateMemory: (sentinelId: string, memory: SentinelMemory) => {
          set((state) => {
            const idx = state.sentinels.findIndex((s) => s.id === sentinelId);
            if (idx !== -1) {
              state.sentinels[idx].memory = memory;
              state.sentinels[idx].updatedAt = Date.now();
            }
          });
          schedulePersist(get());
        },

        updateStats: (sentinelId: string, event: StatsEvent) => {
          set((state) => {
            const idx = state.sentinels.findIndex((s) => s.id === sentinelId);
            if (idx !== -1) {
              const s = state.sentinels[idx] as Sentinel;
              state.sentinels[idx].stats = engineUpdateStats(s.stats, event) as any;
              state.sentinels[idx].updatedAt = Date.now();
            }
          });
          schedulePersist(get());
        },

        load: (sentinels: Sentinel[]) => {
          set((state) => {
            const activeId =
              state.activeSentinelId && sentinels.some((s) => s.id === state.activeSentinelId)
                ? state.activeSentinelId
                : sentinels.length > 0 ? sentinels[0].id : null;
            state.sentinels = sentinels as any;
            state.activeSentinelId = activeId;
            state.loading = false;
          });
          schedulePersist(get());
        },
      },
    };
  }),
);

export const useSentinelStore = createSelectors(useSentinelStoreBase);

// ---------------------------------------------------------------------------
// Backward-compatible hook -- same shape the old Context-based hook returned
// ---------------------------------------------------------------------------

interface SentinelContextValue {
  sentinels: Sentinel[];
  activeSentinel: Sentinel | undefined;
  loading: boolean;
  createSentinel: (config: CreateSentinelConfig) => Promise<Sentinel>;
  updateSentinel: (sentinelId: string, patch: SentinelMutablePatch) => void;
  deleteSentinel: (sentinelId: string) => void;
  setActiveSentinel: (sentinelId: string | null) => void;
  activateSentinel: (sentinelId: string) => void;
  pauseSentinel: (sentinelId: string) => void;
  retireSentinel: (sentinelId: string) => void;
  updateMemory: (sentinelId: string, memory: SentinelMemory) => void;
  updateStats: (sentinelId: string, event: StatsEvent) => void;
}

/** @deprecated Use useSentinelStore directly */
export function useSentinels(): SentinelContextValue {
  const sentinels = useSentinelStore((s) => s.sentinels);
  const activeSentinelId = useSentinelStore((s) => s.activeSentinelId);
  const loading = useSentinelStore((s) => s.loading);
  const actions = useSentinelStore((s) => s.actions);

  const activeSentinel = sentinels.find((s) => s.id === activeSentinelId);

  return {
    sentinels,
    activeSentinel,
    loading,
    createSentinel: actions.createSentinel,
    updateSentinel: actions.updateSentinel,
    deleteSentinel: actions.deleteSentinel,
    setActiveSentinel: actions.setActiveSentinel,
    activateSentinel: actions.activateSentinel,
    pauseSentinel: actions.pauseSentinel,
    retireSentinel: actions.retireSentinel,
    updateMemory: actions.updateMemory,
    updateStats: actions.updateStats,
  };
}
