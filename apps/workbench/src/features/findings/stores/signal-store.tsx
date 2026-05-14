import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import type { AuditEvent } from "@/features/fleet/fleet-client";
import type { AgentBaseline, StreamStats } from "@/lib/workbench/hunt-types";
import type {
  Signal,
  SignalPipelineState,
} from "@/lib/workbench/signal-pipeline";
import {
  createPipelineState,
  ingestSignal as pipelineIngestSignal,
  ingestAuditEvent as pipelineIngestAuditEvent,
  evictExpiredSignals as pipelineEvictExpired,
} from "@/lib/workbench/signal-pipeline";

export interface SignalState {
  signals: Signal[];
  pipelineState: SignalPipelineState;
  stats: StreamStats;
  isStreaming: boolean;
}

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

// ---------------------------------------------------------------------------
// IndexedDB persistence (preserved exactly from the Context implementation)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Debounced IDB persistence helper
// ---------------------------------------------------------------------------

let _persistTimer: ReturnType<typeof setTimeout> | null = null;

function schedulePersist(signals: Signal[]): void {
  if (_persistTimer) clearTimeout(_persistTimer);
  _persistTimer = setTimeout(() => {
    persistSignalsToIdb(signals);
    _persistTimer = null;
  }, 1_000); // Slower debounce than localStorage due to IDB overhead
}

// ---------------------------------------------------------------------------
// Zustand store
//
// Note: we do NOT use the immer middleware here because SignalPipelineState
// contains non-plain-object types (Set, class instances) that are
// incompatible with immer's structural sharing / proxy drafts.
// ---------------------------------------------------------------------------

interface SignalStoreState extends SignalState {
  actions: {
    ingestSignal: (signal: Signal) => void;
    ingestBatch: (signals: Signal[]) => void;
    ingestAuditEvent: (
      auditEvent: AuditEvent,
      baselines: Map<string, AgentBaseline>,
      sentinelId?: string,
    ) => Signal[];
    evictExpired: () => void;
    setStreaming: (streaming: boolean) => void;
    clear: () => void;
    load: (signals: Signal[]) => void;
    updateStats: (stats: StreamStats) => void;
  };
}

const useSignalStoreBase = create<SignalStoreState>()((set, get) => ({
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

  actions: {
    ingestSignal: (signal: Signal) => {
      const { pipelineState, signals: prev } = get();
      const result = pipelineIngestSignal(pipelineState, signal);
      if (!result.signal) return; // Suppressed or deduped

      const signals = [...prev, result.signal];
      set({
        signals,
        pipelineState: result.state,
        stats: computeSignalStats(signals),
      });
      schedulePersist(signals);
    },

    ingestBatch: (incoming: Signal[]) => {
      const { pipelineState, signals: prev } = get();
      let currentPipeline = pipelineState;
      const accepted: Signal[] = [];

      for (const signal of incoming) {
        const result = pipelineIngestSignal(currentPipeline, signal);
        currentPipeline = result.state;
        if (result.signal) {
          accepted.push(result.signal);
        }
      }

      if (accepted.length === 0) return;

      const signals = [...prev, ...accepted];
      set({
        signals,
        pipelineState: currentPipeline,
        stats: computeSignalStats(signals),
      });
      schedulePersist(signals);
    },

    ingestAuditEvent: (
      auditEvent: AuditEvent,
      baselines: Map<string, AgentBaseline>,
      sentinelId?: string,
    ): Signal[] => {
      const result = pipelineIngestAuditEvent(
        get().pipelineState,
        auditEvent,
        baselines,
        sentinelId,
      );
      if (result.signals.length > 0) {
        get().actions.ingestBatch(result.signals);
      }
      return result.signals;
    },

    evictExpired: () => {
      const { pipelineState, signals: prev } = get();
      const result = pipelineEvictExpired(pipelineState);
      if (result.evicted === 0) return;

      const pipelineSignalIds = new Set(result.state.signals.map((s) => s.id));
      const signals = prev.filter((s) => pipelineSignalIds.has(s.id));
      set({
        signals,
        pipelineState: result.state,
        stats: computeSignalStats(signals),
      });
      schedulePersist(signals);
    },

    setStreaming: (streaming: boolean) => {
      set({ isStreaming: streaming });
    },

    clear: () => {
      set({
        signals: [],
        pipelineState: createPipelineState(),
        stats: computeSignalStats([]),
      });
      clearSignalIdb();
    },

    load: (signals: Signal[]) => {
      const pipeline = createPipelineState();
      set({
        signals,
        pipelineState: { ...pipeline, signals },
        stats: computeSignalStats(signals),
      });
    },

    updateStats: (stats: StreamStats) => {
      set({ stats });
    },
  },
}));

// Hydrate from IndexedDB on module load
loadSignalsFromIdb().then((signals) => {
  if (signals.length > 0) {
    useSignalStoreBase.getState().actions.load(signals);
  }
});

export const useSignalStore = createSelectors(useSignalStoreBase);

// ---------------------------------------------------------------------------
// Backward-compatible hook
// ---------------------------------------------------------------------------

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

/** @deprecated Use useSignalStore directly */
export function useSignals(): SignalContextValue {
  const signals = useSignalStore((s) => s.signals);
  const stats = useSignalStore((s) => s.stats);
  const isStreaming = useSignalStore((s) => s.isStreaming);
  const actions = useSignalStore((s) => s.actions);

  return {
    signals,
    stats,
    isStreaming,
    ingestSignal: actions.ingestSignal,
    ingestAuditEvent: actions.ingestAuditEvent,
    evictExpired: actions.evictExpired,
    setStreaming: actions.setStreaming,
    clear: actions.clear,
  };
}
