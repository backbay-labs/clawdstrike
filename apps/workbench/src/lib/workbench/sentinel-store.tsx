import React, {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from "react";
import type {
  Sentinel,
  SentinelMemory,
} from "./sentinel-types";
import type { CreateSentinelConfig, StatsEvent, SentinelMutablePatch } from "./sentinel-manager";
import {
  createSentinel as engineCreateSentinel,
  createDefaultRuntimeBinding,
  updateSentinel as engineUpdateSentinel,
  deleteSentinel as engineDeleteSentinel,
  activateSentinel as engineActivateSentinel,
  pauseSentinel as enginePauseSentinel,
  retireSentinel as engineRetireSentinel,
  updateStats as engineUpdateStats,
} from "./sentinel-manager";

export interface SentinelState {
  sentinels: Sentinel[];
  activeSentinelId: string | null;
  loading: boolean;
}

export type SentinelAction =
  | { type: "CREATE"; sentinel: Sentinel }
  | { type: "UPDATE"; sentinelId: string; patch: SentinelMutablePatch }
  | { type: "DELETE"; sentinelId: string }
  | { type: "SET_ACTIVE"; sentinelId: string | null }
  | { type: "ACTIVATE"; sentinelId: string }
  | { type: "PAUSE"; sentinelId: string }
  | { type: "RETIRE"; sentinelId: string }
  | { type: "UPDATE_MEMORY"; sentinelId: string; memory: SentinelMemory }
  | { type: "UPDATE_STATS"; sentinelId: string; event: StatsEvent }
  | { type: "LOAD"; sentinels: Sentinel[] };

function sentinelReducer(state: SentinelState, action: SentinelAction): SentinelState {
  switch (action.type) {
    case "CREATE": {
      return {
        ...state,
        sentinels: [...state.sentinels, action.sentinel],
        activeSentinelId: action.sentinel.id,
      };
    }

    case "UPDATE": {
      return {
        ...state,
        sentinels: state.sentinels.map((s) =>
          s.id === action.sentinelId
            ? engineUpdateSentinel(s, action.patch)
            : s,
        ),
      };
    }

    case "DELETE": {
      const remaining = engineDeleteSentinel(action.sentinelId, state.sentinels);
      const needNewActive = state.activeSentinelId === action.sentinelId;
      return {
        ...state,
        sentinels: remaining,
        activeSentinelId: needNewActive
          ? (remaining.length > 0 ? remaining[0].id : null)
          : state.activeSentinelId,
      };
    }

    case "SET_ACTIVE": {
      if (action.sentinelId !== null && !state.sentinels.some((s) => s.id === action.sentinelId)) {
        return state;
      }
      return { ...state, activeSentinelId: action.sentinelId };
    }

    case "ACTIVATE": {
      return {
        ...state,
        sentinels: state.sentinels.map((s) => {
          if (s.id !== action.sentinelId) return s;
          try {
            return engineActivateSentinel(s);
          } catch {
            return s; // Invalid transition — no-op
          }
        }),
      };
    }

    case "PAUSE": {
      return {
        ...state,
        sentinels: state.sentinels.map((s) => {
          if (s.id !== action.sentinelId) return s;
          try {
            return enginePauseSentinel(s);
          } catch {
            return s;
          }
        }),
      };
    }

    case "RETIRE": {
      return {
        ...state,
        sentinels: state.sentinels.map((s) => {
          if (s.id !== action.sentinelId) return s;
          try {
            return engineRetireSentinel(s);
          } catch {
            return s;
          }
        }),
      };
    }

    case "UPDATE_MEMORY": {
      return {
        ...state,
        sentinels: state.sentinels.map((s) =>
          s.id === action.sentinelId
            ? { ...s, memory: action.memory, updatedAt: Date.now() }
            : s,
        ),
      };
    }

    case "UPDATE_STATS": {
      return {
        ...state,
        sentinels: state.sentinels.map((s) =>
          s.id === action.sentinelId
            ? { ...s, stats: engineUpdateStats(s.stats, action.event), updatedAt: Date.now() }
            : s,
        ),
      };
    }

    case "LOAD": {
      const activeId =
        state.activeSentinelId && action.sentinels.some((s) => s.id === state.activeSentinelId)
          ? state.activeSentinelId
          : action.sentinels.length > 0 ? action.sentinels[0].id : null;
      return {
        ...state,
        sentinels: action.sentinels,
        activeSentinelId: activeId,
        loading: false,
      };
    }

    default:
      return state;
  }
}

const STORAGE_KEY = "clawdstrike_workbench_sentinels";

function persistSentinels(state: SentinelState): void {
  try {
    const persisted = {
      sentinels: state.sentinels,
      activeSentinelId: state.activeSentinelId,
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(persisted));
  } catch (e) {
    console.error("[sentinel-store] persistSentinels failed:", e);
  }
}

function loadPersistedSentinels(): SentinelState | null {
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

function getInitialState(): SentinelState {
  const restored = loadPersistedSentinels();
  if (restored) return restored;

  return {
    sentinels: [],
    activeSentinelId: null,
    loading: false,
  };
}

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

const SentinelContext = createContext<SentinelContextValue | null>(null);

export function useSentinels(): SentinelContextValue {
  const ctx = useContext(SentinelContext);
  if (!ctx) throw new Error("useSentinels must be used within SentinelProvider");
  return ctx;
}

export function SentinelProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(sentinelReducer, undefined, getInitialState);

    const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => {
      persistSentinels(state);
    }, 500);
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [state.sentinels, state.activeSentinelId]);

    const activeSentinel = state.sentinels.find((s) => s.id === state.activeSentinelId);

  
  const createSentinel = useCallback(
    async (config: CreateSentinelConfig): Promise<Sentinel> => {
      const sentinel = await engineCreateSentinel(config);
      dispatch({ type: "CREATE", sentinel });
      return sentinel;
    },
    [],
  );

  const updateSentinelAction = useCallback(
    (sentinelId: string, patch: SentinelMutablePatch) => {
      dispatch({ type: "UPDATE", sentinelId, patch });
    },
    [],
  );

  const deleteSentinelAction = useCallback((sentinelId: string) => {
    dispatch({ type: "DELETE", sentinelId });
  }, []);

  const setActiveSentinel = useCallback((sentinelId: string | null) => {
    dispatch({ type: "SET_ACTIVE", sentinelId });
  }, []);

  const activateSentinelAction = useCallback((sentinelId: string) => {
    dispatch({ type: "ACTIVATE", sentinelId });
  }, []);

  const pauseSentinelAction = useCallback((sentinelId: string) => {
    dispatch({ type: "PAUSE", sentinelId });
  }, []);

  const retireSentinelAction = useCallback((sentinelId: string) => {
    dispatch({ type: "RETIRE", sentinelId });
  }, []);

  const updateMemory = useCallback(
    (sentinelId: string, memory: SentinelMemory) => {
      dispatch({ type: "UPDATE_MEMORY", sentinelId, memory });
    },
    [],
  );

  const updateStatsAction = useCallback(
    (sentinelId: string, event: StatsEvent) => {
      dispatch({ type: "UPDATE_STATS", sentinelId, event });
    },
    [],
  );

  const value: SentinelContextValue = {
    sentinels: state.sentinels,
    activeSentinel,
    loading: state.loading,
    createSentinel,
    updateSentinel: updateSentinelAction,
    deleteSentinel: deleteSentinelAction,
    setActiveSentinel,
    activateSentinel: activateSentinelAction,
    pauseSentinel: pauseSentinelAction,
    retireSentinel: retireSentinelAction,
    updateMemory,
    updateStats: updateStatsAction,
  };

  return (
    <SentinelContext.Provider value={value}>
      {children}
    </SentinelContext.Provider>
  );
}
