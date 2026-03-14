import React, {
  createContext,
  useContext,
  useReducer,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from "react";
import type { AuditEvent } from "./fleet-client";
import type { AgentBaseline, StreamStats } from "./hunt-types";
import type {
  Signal,
  SignalPipelineState,
} from "./signal-pipeline";
import {
  createPipelineState,
  ingestSignal as pipelineIngestSignal,
  ingestAuditEvent as pipelineIngestAuditEvent,
  evictExpiredSignals as pipelineEvictExpired,
} from "./signal-pipeline";

export interface SignalState {
  signals: Signal[];
  pipelineState: SignalPipelineState;
  stats: StreamStats;
  isStreaming: boolean;
}

export type SignalAction =
  | { type: "INGEST"; signal: Signal }
  | { type: "INGEST_BATCH"; signals: Signal[] }
  | { type: "EVICT_EXPIRED" }
  | { type: "SET_STREAMING"; streaming: boolean }
  | { type: "CLEAR" }
  | { type: "UPDATE_STATS"; stats: StreamStats }
  | { type: "LOAD"; signals: Signal[] };

function computeSignalStats(signals: Signal[]): StreamStats {
  const stats: StreamStats = {
    total: signals.length,
    allowed: 0,
    denied: 0,
    warned: 0,
    anomalies: 0,
    byActionType: {},
  };

  for (const signal of signals) {
    if (signal.type === "anomaly") {
      stats.anomalies++;
    } else if (signal.type === "policy_violation") {
      const data = signal.data as Record<string, unknown>;
      if (data.verdict === "deny") {
        stats.denied++;
      } else {
        stats.warned++;
      }
    } else {
      stats.warned++;
    }

    // Track by action type from signal data if available
    const actionType = (signal.data as Record<string, unknown>).actionType;
    if (typeof actionType === "string") {
      stats.byActionType[actionType] = (stats.byActionType[actionType] ?? 0) + 1;
    }
  }

  return stats;
}

function signalReducer(state: SignalState, action: SignalAction): SignalState {
  switch (action.type) {
    case "INGEST": {
      const result = pipelineIngestSignal(state.pipelineState, action.signal);
      if (!result.signal) return state; // Suppressed or deduped

      const signals = [...state.signals, result.signal];
      return {
        ...state,
        signals,
        pipelineState: result.state,
        stats: computeSignalStats(signals),
      };
    }

    case "INGEST_BATCH": {
      let currentPipeline = state.pipelineState;
      const accepted: Signal[] = [];

      for (const signal of action.signals) {
        const result = pipelineIngestSignal(currentPipeline, signal);
        currentPipeline = result.state;
        if (result.signal) {
          accepted.push(result.signal);
        }
      }

      if (accepted.length === 0) return state;

      const signals = [...state.signals, ...accepted];
      return {
        ...state,
        signals,
        pipelineState: currentPipeline,
        stats: computeSignalStats(signals),
      };
    }

    case "EVICT_EXPIRED": {
      const result = pipelineEvictExpired(state.pipelineState);
      if (result.evicted === 0) return state;

      // Sync the store signals array with the pipeline's signal buffer
      const pipelineSignalIds = new Set(result.state.signals.map((s) => s.id));
      const signals = state.signals.filter((s) => pipelineSignalIds.has(s.id));
      return {
        ...state,
        signals,
        pipelineState: result.state,
        stats: computeSignalStats(signals),
      };
    }

    case "SET_STREAMING": {
      return { ...state, isStreaming: action.streaming };
    }

    case "CLEAR": {
      const freshPipeline = createPipelineState();
      return {
        ...state,
        signals: [],
        pipelineState: freshPipeline,
        stats: computeSignalStats([]),
      };
    }

    case "UPDATE_STATS": {
      return { ...state, stats: action.stats };
    }

    case "LOAD": {
      // Rebuild pipeline state from loaded signals
      const pipeline = createPipelineState();
      const loadedPipeline: SignalPipelineState = {
        ...pipeline,
        signals: action.signals,
      };
      return {
        ...state,
        signals: action.signals,
        pipelineState: loadedPipeline,
        stats: computeSignalStats(action.signals),
      };
    }

    default:
      return state;
  }
}

const IDB_NAME = "clawdstrike_workbench_signals";
const IDB_VERSION = 1;
const IDB_STORE = "signals";

function openSignalDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(IDB_NAME, IDB_VERSION);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(IDB_STORE)) {
        db.createObjectStore(IDB_STORE, { keyPath: "id" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function persistSignalsToIdb(signals: Signal[]): Promise<void> {
  try {
    const db = await openSignalDb();
    const tx = db.transaction(IDB_STORE, "readwrite");
    const store = tx.objectStore(IDB_STORE);

    // Clear and replace — signals are ephemeral and high-volume,
    // so a full replace is simpler than diffing.
    store.clear();
    for (const signal of signals) {
      store.put(signal);
    }

    return new Promise((resolve, reject) => {
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    });
  } catch (e) {
    console.error("[signal-store] persistSignalsToIdb failed:", e);
  }
}

async function loadSignalsFromIdb(): Promise<Signal[]> {
  try {
    const db = await openSignalDb();
    const tx = db.transaction(IDB_STORE, "readonly");
    const store = tx.objectStore(IDB_STORE);
    const request = store.getAll();

    return new Promise((resolve, reject) => {
      request.onsuccess = () => {
        db.close();
        const raw = request.result;
        // Validate each entry
        const valid: Signal[] = (raw ?? []).filter(
          (s: unknown): s is Signal =>
            typeof s === "object" &&
            s !== null &&
            typeof (s as Record<string, unknown>).id === "string" &&
            typeof (s as Record<string, unknown>).type === "string" &&
            typeof (s as Record<string, unknown>).timestamp === "number",
        );
        resolve(valid);
      };
      request.onerror = () => {
        db.close();
        reject(request.error);
      };
    });
  } catch (e) {
    console.warn("[signal-store] loadSignalsFromIdb failed:", e);
    return [];
  }
}

async function clearSignalIdb(): Promise<void> {
  try {
    const db = await openSignalDb();
    const tx = db.transaction(IDB_STORE, "readwrite");
    tx.objectStore(IDB_STORE).clear();
    return new Promise((resolve, reject) => {
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    });
  } catch (e) {
    console.warn("[signal-store] clearSignalIdb failed:", e);
  }
}

function getInitialState(): SignalState {
  return {
    signals: [],
    pipelineState: createPipelineState(),
    stats: {
      total: 0,
      allowed: 0,
      denied: 0,
      warned: 0,
      anomalies: 0,
      byActionType: {},
    },
    isStreaming: false,
  };
}

interface SignalContextValue {
  signals: Signal[];
  stats: StreamStats;
  isStreaming: boolean;
  ingestSignal: (signal: Signal) => void;
  ingestAuditEvent: (
    auditEvent: AuditEvent,
    baselines: Map<string, AgentBaseline>,
    sentinelId?: string,
  ) => Signal[];
  evictExpired: () => void;
  setStreaming: (streaming: boolean) => void;
  clear: () => void;
}

const SignalContext = createContext<SignalContextValue | null>(null);

export function useSignals(): SignalContextValue {
  const ctx = useContext(SignalContext);
  if (!ctx) throw new Error("useSignals must be used within SignalProvider");
  return ctx;
}

export function SignalProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(signalReducer, undefined, getInitialState);

  // Hydrate from IndexedDB on mount
  useEffect(() => {
    let cancelled = false;

    loadSignalsFromIdb().then((signals) => {
      if (!cancelled && signals.length > 0) {
        dispatch({ type: "LOAD", signals });
      }
    });

    return () => {
      cancelled = true;
    };
  }, []);

    const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    if (persistRef.current) clearTimeout(persistRef.current);
    persistRef.current = setTimeout(() => {
      persistSignalsToIdb(state.signals);
    }, 1_000); // Slower debounce than localStorage due to IDB overhead
    return () => {
      if (persistRef.current) clearTimeout(persistRef.current);
    };
  }, [state.signals]);

  // We need a mutable ref for the pipeline state to use in the
  // ingestAuditEvent callback, which needs synchronous access to the
  // latest pipeline state for multi-signal production from a single event.
  const pipelineRef = useRef(state.pipelineState);
  useEffect(() => {
    pipelineRef.current = state.pipelineState;
  }, [state.pipelineState]);

  
  const ingestSignal = useCallback((signal: Signal) => {
    dispatch({ type: "INGEST", signal });
  }, []);

  const ingestAuditEvent = useCallback(
    (
      auditEvent: AuditEvent,
      baselines: Map<string, AgentBaseline>,
      sentinelId?: string,
    ): Signal[] => {
      // Use the pipeline function to produce signals from the audit event,
      // then dispatch them as a batch. We read from the ref to get the
      // latest pipeline state.
      const result = pipelineIngestAuditEvent(
        pipelineRef.current,
        auditEvent,
        baselines,
        sentinelId,
      );
      if (result.signals.length > 0) {
        dispatch({ type: "INGEST_BATCH", signals: result.signals });
      }
      return result.signals;
    },
    [],
  );

  const evictExpired = useCallback(() => {
    dispatch({ type: "EVICT_EXPIRED" });
  }, []);

  const setStreaming = useCallback((streaming: boolean) => {
    dispatch({ type: "SET_STREAMING", streaming });
  }, []);

  const clear = useCallback(() => {
    dispatch({ type: "CLEAR" });
    clearSignalIdb();
  }, []);

  const value: SignalContextValue = {
    signals: state.signals,
    stats: state.stats,
    isStreaming: state.isStreaming,
    ingestSignal,
    ingestAuditEvent,
    evictExpired,
    setStreaming,
    clear,
  };

  return (
    <SignalContext.Provider value={value}>
      {children}
    </SignalContext.Provider>
  );
}
