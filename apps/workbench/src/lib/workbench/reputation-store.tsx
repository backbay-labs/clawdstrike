// Reputation Store — React Context + useReducer for reputation event tracking.
//
// Follows the sentinel-store.tsx pattern: State, Action union, reducer,
// Provider with localStorage persistence, and a typed hook.
import React, {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from "react";


export interface ReputationEvent {
  target: string;        // fingerprint of the entity being rated
  eventType: string;     // e.g. "intel_accepted", "false_positive", "vote_up"
  timestamp: number;
  artifactId: string;    // finding/intel ID this event relates to
  delta: number;         // reputation score change
  source: string;        // fingerprint of the voter/system
}


interface ReputationState {
  events: Record<string, ReputationEvent[]>;  // keyed by target fingerprint
  loading: boolean;
}


type ReputationAction =
  | { type: "ADD_EVENT"; event: ReputationEvent }
  | { type: "LOAD"; events: Record<string, ReputationEvent[]> };


function eventKey(e: ReputationEvent): string {
  return `${e.target}:${e.eventType}:${e.timestamp}:${e.artifactId}:${e.source}`;
}


function reputationReducer(
  state: ReputationState,
  action: ReputationAction,
): ReputationState {
  switch (action.type) {
    case "ADD_EVENT": {
      const { event } = action;
      const existing = state.events[event.target] ?? [];
      // Dedup by (target, eventType, timestamp, artifactId)
      const key = eventKey(event);
      if (existing.some((e) => eventKey(e) === key)) {
        return state;
      }
      return {
        ...state,
        events: {
          ...state.events,
          [event.target]: [...existing, event],
        },
      };
    }

    case "LOAD": {
      return {
        ...state,
        events: action.events,
        loading: false,
      };
    }

    default:
      return state;
  }
}


const STORAGE_KEY = "clawdstrike_workbench_reputation";

function persistReputation(events: Record<string, ReputationEvent[]>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(events));
  } catch (e) {
    console.error("[reputation-store] persistReputation failed:", e);
  }
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


function getInitialState(): ReputationState {
  const restored = loadPersistedReputation();
  if (restored) {
    return { events: restored, loading: false };
  }
  return { events: {}, loading: false };
}


interface ReputationContextValue {
  events: Record<string, ReputationEvent[]>;
  loading: boolean;
  addEvent: (event: ReputationEvent) => void;
  getScore: (fingerprint: string) => number;
  getHistory: (fingerprint: string) => ReputationEvent[];
}

const ReputationContext = createContext<ReputationContextValue | null>(null);


export function useReputation(): ReputationContextValue {
  const ctx = useContext(ReputationContext);
  if (!ctx) throw new Error("useReputation must be used within ReputationProvider");
  return ctx;
}


export function ReputationProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reputationReducer, undefined, getInitialState);

    const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => {
      persistReputation(state.events);
    }, 500);
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [state.events]);

  const addEvent = useCallback((event: ReputationEvent) => {
    dispatch({ type: "ADD_EVENT", event });
  }, []);

  const getScore = useCallback(
    (fingerprint: string): number => {
      const history = state.events[fingerprint] ?? [];
      return history.reduce((sum, e) => sum + e.delta, 0);
    },
    [state.events],
  );

  const getHistory = useCallback(
    (fingerprint: string): ReputationEvent[] => {
      return state.events[fingerprint] ?? [];
    },
    [state.events],
  );

  const value: ReputationContextValue = {
    events: state.events,
    loading: state.loading,
    addEvent,
    getScore,
    getHistory,
  };

  return (
    <ReputationContext.Provider value={value}>
      {children}
    </ReputationContext.Provider>
  );
}
