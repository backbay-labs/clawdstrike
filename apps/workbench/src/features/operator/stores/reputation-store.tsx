// Reputation Store — Zustand + immer for reputation event tracking.
//
// Migrated from React Context + useReducer. Preserves localStorage persistence
// with debounced writes.
import type { ReactElement, ReactNode } from "react";
import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/lib/create-selectors";


export interface ReputationEvent {
  target: string;        // fingerprint of the entity being rated
  eventType: string;     // e.g. "intel_accepted", "false_positive", "vote_up"
  timestamp: number;
  artifactId: string;    // finding/intel ID this event relates to
  delta: number;         // reputation score change
  source: string;        // fingerprint of the voter/system
}


// ---------------------------------------------------------------------------
// localStorage persistence helpers
// ---------------------------------------------------------------------------

const STORAGE_KEY = "clawdstrike_workbench_reputation";

let persistTimer: ReturnType<typeof setTimeout> | null = null;

function schedulePersist(events: Record<string, ReputationEvent[]>): void {
  if (persistTimer) clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(events));
    } catch (e) {
      console.error("[reputation-store] persistReputation failed:", e);
    }
    persistTimer = null;
  }, 500);
}

function loadPersistedReputation(): Record<string, ReputationEvent[]> | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    return parsed as Record<string, ReputationEvent[]>;
  } catch (e) {
    console.warn("[reputation-store] loadPersistedReputation failed:", e);
    return null;
  }
}


function eventKey(e: ReputationEvent): string {
  return `${e.target}:${e.eventType}:${e.timestamp}:${e.artifactId}:${e.source}`;
}


// ---------------------------------------------------------------------------
// Zustand store
// ---------------------------------------------------------------------------

export interface ReputationState {
  events: Record<string, ReputationEvent[]>;
  loading: boolean;
  actions: ReputationActions;
}

interface ReputationActions {
  addEvent: (event: ReputationEvent) => void;
  getScore: (fingerprint: string) => number;
  getHistory: (fingerprint: string) => ReputationEvent[];
}

const useReputationStoreBase = create<ReputationState>()(
  immer((set, get) => {
    const restored = loadPersistedReputation();

    return {
      events: restored ?? {},
      loading: false,

      actions: {
        addEvent: (event: ReputationEvent) => {
          const existing = get().events[event.target] ?? [];
          // Dedup by (target, eventType, timestamp, artifactId, source)
          const key = eventKey(event);
          if (existing.some((e) => eventKey(e) === key)) {
            return;
          }
          set((state) => {
            if (!state.events[event.target]) {
              state.events[event.target] = [];
            }
            state.events[event.target].push(event);
          });
          schedulePersist(get().events);
        },

        getScore: (fingerprint: string): number => {
          const history = get().events[fingerprint] ?? [];
          return history.reduce((sum, e) => sum + e.delta, 0);
        },

        getHistory: (fingerprint: string): ReputationEvent[] => {
          return get().events[fingerprint] ?? [];
        },
      },
    };
  }),
);

export const useReputationStore = createSelectors(useReputationStoreBase);

// ---------------------------------------------------------------------------
// Backward-compatible hook — same shape the old Context-based hook returned
// ---------------------------------------------------------------------------

interface ReputationContextValue {
  events: Record<string, ReputationEvent[]>;
  loading: boolean;
  addEvent: (event: ReputationEvent) => void;
  getScore: (fingerprint: string) => number;
  getHistory: (fingerprint: string) => ReputationEvent[];
}

/** @deprecated Use useReputationStore directly */
export function useReputation(): ReputationContextValue {
  const events = useReputationStore((s) => s.events);
  const loading = useReputationStore((s) => s.loading);
  const actions = useReputationStore((s) => s.actions);

  return {
    events,
    loading,
    addEvent: actions.addEvent,
    getScore: actions.getScore,
    getHistory: actions.getHistory,
  };
}

/**
 * @deprecated Provider is no longer needed — Reputation is now a Zustand store.
 * Kept as a pass-through wrapper for backward compatibility.
 */
export function ReputationProvider({ children }: { children: ReactNode }) {
  return children as ReactElement;
}
