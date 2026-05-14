import { useLayoutEffect } from "react";
import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/lib/create-selectors";
import type { Intel } from "@/lib/workbench/sentinel-types";
import { isIntel } from "@/lib/workbench/sentinel-types";

export const INTEL_STORAGE_KEY = "clawdstrike_workbench_intel";

export type IntelSource = "local" | "swarm";

export interface SwarmIntelRecord {
  swarmId: string;
  intel: Intel;
  receivedAt: number;
  publishedBy?: string;
}

export interface IntelState {
  localIntel: Intel[];
  swarmIntel: SwarmIntelRecord[];
  activeIntelId: string | null;
}

// ---------------------------------------------------------------------------
// Pure helpers (unchanged from Context implementation)
// ---------------------------------------------------------------------------

function swarmIntelKey(record: Pick<SwarmIntelRecord, "swarmId" | "intel">): string {
  return `${record.swarmId}:${record.intel.id}`;
}

function sortLocalIntel(intel: Intel[]): Intel[] {
  return [...intel].sort((left, right) => {
    if (right.createdAt !== left.createdAt) {
      return right.createdAt - left.createdAt;
    }
    return right.version - left.version;
  });
}

function sortSwarmIntel(records: SwarmIntelRecord[]): SwarmIntelRecord[] {
  return [...records].sort((left, right) => {
    if (right.receivedAt !== left.receivedAt) {
      return right.receivedAt - left.receivedAt;
    }
    if (right.intel.createdAt !== left.intel.createdAt) {
      return right.intel.createdAt - left.intel.createdAt;
    }
    return right.intel.version - left.intel.version;
  });
}

function hasIntel(state: Pick<IntelState, "localIntel" | "swarmIntel">, intelId: string): boolean {
  return (
    state.localIntel.some((intel) => intel.id === intelId) ||
    state.swarmIntel.some((record) => record.intel.id === intelId)
  );
}

function nextActiveIntelId(state: Pick<IntelState, "localIntel" | "swarmIntel">): string | null {
  return state.localIntel[0]?.id ?? state.swarmIntel[0]?.intel.id ?? null;
}

function listUniqueSwarmIntel(records: SwarmIntelRecord[]): Intel[] {
  const seen = new Set<string>();
  const unique: Intel[] = [];
  for (const record of records) {
    if (seen.has(record.intel.id)) {
      continue;
    }
    seen.add(record.intel.id);
    unique.push(record.intel);
  }
  return unique;
}

function defaultIntelState(): IntelState {
  return {
    localIntel: [],
    swarmIntel: [],
    activeIntelId: null,
  };
}

// ---------------------------------------------------------------------------
// localStorage persistence (preserved exactly from the Context implementation)
// ---------------------------------------------------------------------------

let lastIntelStorageSnapshot =
  typeof window === "undefined" ? null : readIntelStorageSnapshot();

function readIntelStorageSnapshot(): string | null {
  try {
    return localStorage.getItem(INTEL_STORAGE_KEY);
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeSwarmIntelRecord(value: unknown): SwarmIntelRecord | null {
  if (!isRecord(value) || typeof value.swarmId !== "string" || !isIntel(value.intel)) {
    return null;
  }

  return {
    swarmId: value.swarmId,
    intel: value.intel,
    receivedAt:
      typeof value.receivedAt === "number" && Number.isFinite(value.receivedAt)
        ? value.receivedAt
        : value.intel.createdAt,
    publishedBy: typeof value.publishedBy === "string" ? value.publishedBy : undefined,
  };
}

function loadPersistedIntel(): IntelState | null {
  try {
    const raw = localStorage.getItem(INTEL_STORAGE_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw);
    if (!isRecord(parsed)) {
      return null;
    }

    const localIntel = Array.isArray(parsed.localIntel)
      ? sortLocalIntel(parsed.localIntel.filter((entry: unknown): entry is Intel => isIntel(entry)))
      : [];
    const swarmIntel = Array.isArray(parsed.swarmIntel)
      ? sortSwarmIntel(
          parsed.swarmIntel.flatMap((entry: unknown) => {
            const record = normalizeSwarmIntelRecord(entry);
            return record ? [record] : [];
          }),
        )
      : [];

    const activeIntelId =
      typeof parsed.activeIntelId === "string" &&
      hasIntel({ localIntel, swarmIntel }, parsed.activeIntelId)
        ? parsed.activeIntelId
        : nextActiveIntelId({ localIntel, swarmIntel });

    return {
      localIntel,
      swarmIntel,
      activeIntelId,
    };
  } catch (error) {
    console.warn("[intel-store] loadPersistedIntel failed:", error);
    return null;
  }
}

function persistIntel(state: IntelState): void {
  try {
    const raw = JSON.stringify({
      localIntel: state.localIntel,
      swarmIntel: state.swarmIntel,
      activeIntelId: state.activeIntelId,
    });
    localStorage.setItem(INTEL_STORAGE_KEY, raw);
    lastIntelStorageSnapshot = raw;
  } catch (error) {
    console.error("[intel-store] persistIntel failed:", error);
  }
}

// ---------------------------------------------------------------------------
// Debounced persistence helper
// ---------------------------------------------------------------------------

let _persistTimer: ReturnType<typeof setTimeout> | null = null;

function schedulePersistIntel(state: IntelState): void {
  if (_persistTimer) clearTimeout(_persistTimer);
  _persistTimer = setTimeout(() => {
    persistIntel(state);
    _persistTimer = null;
  }, 500);
}

// Flush on beforeunload (matches old Provider behavior)
if (typeof window !== "undefined") {
  window.addEventListener("beforeunload", () => {
    if (_persistTimer) {
      clearTimeout(_persistTimer);
      _persistTimer = null;
      const state = useIntelStoreBase.getState();
      persistIntel({
        localIntel: state.localIntel,
        swarmIntel: state.swarmIntel,
        activeIntelId: state.activeIntelId,
      });
    }
  });
}

// ---------------------------------------------------------------------------
// Zustand store
// ---------------------------------------------------------------------------

function getInitialIntelState(): IntelState {
  return loadPersistedIntel() ?? defaultIntelState();
}

function syncIntelStoreWithStorage(): void {
  const snapshot = readIntelStorageSnapshot();
  if (snapshot === lastIntelStorageSnapshot) {
    return;
  }

  const restored = loadPersistedIntel() ?? defaultIntelState();
  lastIntelStorageSnapshot = snapshot;
  useIntelStoreBase.setState(restored);
}

interface IntelStoreState extends IntelState {
  actions: {
    upsertLocalIntel: (intel: Intel) => void;
    removeLocalIntel: (intelId: string) => void;
    ingestSwarmIntel: (record: SwarmIntelRecord) => void;
    removeSwarmIntel: (intelId: string, swarmId?: string) => void;
    setActiveIntel: (intelId: string | null) => void;
  };
}

const initial = getInitialIntelState();

const useIntelStoreBase = create<IntelStoreState>()(
  immer((set) => ({
    localIntel: initial.localIntel,
    swarmIntel: initial.swarmIntel,
    activeIntelId: initial.activeIntelId,

    actions: {
      upsertLocalIntel: (intel: Intel) => {
        set((state) => {
          state.localIntel = sortLocalIntel([
            ...state.localIntel.filter((existing) => existing.id !== intel.id),
            intel,
          ]);
          state.activeIntelId = intel.id;
        });
        const s = useIntelStoreBase.getState();
        schedulePersistIntel(s);
      },

      removeLocalIntel: (intelId: string) => {
        set((state) => {
          state.localIntel = state.localIntel.filter((intel) => intel.id !== intelId);
          if (state.activeIntelId === intelId) {
            state.activeIntelId = nextActiveIntelId(state);
          }
        });
        const s = useIntelStoreBase.getState();
        schedulePersistIntel(s);
      },

      ingestSwarmIntel: (record: SwarmIntelRecord) => {
        set((state) => {
          state.swarmIntel = sortSwarmIntel([
            ...state.swarmIntel.filter(
              (existing) => swarmIntelKey(existing) !== swarmIntelKey(record),
            ),
            record,
          ]);
          if (state.activeIntelId === null) {
            state.activeIntelId = record.intel.id;
          }
        });
        const s = useIntelStoreBase.getState();
        schedulePersistIntel(s);
      },

      removeSwarmIntel: (intelId: string, swarmId?: string) => {
        set((state) => {
          state.swarmIntel = state.swarmIntel.filter((record) => {
            if (record.intel.id !== intelId) return true;
            if (!swarmId) return false;
            return record.swarmId !== swarmId;
          });
          if (state.activeIntelId === intelId) {
            state.activeIntelId = nextActiveIntelId(state);
          }
        });
        const s = useIntelStoreBase.getState();
        schedulePersistIntel(s);
      },

      setActiveIntel: (intelId: string | null) => {
        set((state) => {
          if (intelId === null) {
            state.activeIntelId = null;
            return;
          }
          if (hasIntel(state, intelId)) {
            state.activeIntelId = intelId;
          }
        });
        const s = useIntelStoreBase.getState();
        schedulePersistIntel(s);
      },
    },
  })),
);

export const useIntelStore = createSelectors(useIntelStoreBase);

// ---------------------------------------------------------------------------
// Backward-compatible hook
// ---------------------------------------------------------------------------

interface IntelContextValue {
  localIntel: Intel[];
  swarmIntel: Intel[];
  swarmIntelRecords: SwarmIntelRecord[];
  activeIntelId: string | null;
  activeIntel: Intel | undefined;
  upsertLocalIntel: (intel: Intel) => void;
  removeLocalIntel: (intelId: string) => void;
  ingestSwarmIntel: (record: SwarmIntelRecord) => void;
  removeSwarmIntel: (intelId: string, swarmId?: string) => void;
  setActiveIntel: (intelId: string | null) => void;
  getIntelById: (intelId: string) => Intel | undefined;
  getIntelSource: (intelId: string) => IntelSource | undefined;
  getSwarmIntelRecord: (intelId: string) => SwarmIntelRecord | undefined;
  getSwarmIntelRecords: (intelId: string) => SwarmIntelRecord[];
  listIntelBySource: (source: IntelSource) => Intel[];
  listSwarmIntelBySwarm: (swarmId: string) => Intel[];
}

/** @deprecated Use useIntelStore directly */
export function useIntel(): IntelContextValue {
  useLayoutEffect(() => {
    syncIntelStoreWithStorage();
  }, []);

  const localIntel = useIntelStore((s) => s.localIntel);
  const swarmIntelRecords = useIntelStore((s) => s.swarmIntel);
  const activeIntelId = useIntelStore((s) => s.activeIntelId);
  const actions = useIntelStore((s) => s.actions);

  const swarmIntel = listUniqueSwarmIntel(swarmIntelRecords);

  const activeIntel = activeIntelId
    ? (localIntel.find((intel) => intel.id === activeIntelId) ??
      swarmIntelRecords.find((record) => record.intel.id === activeIntelId)?.intel)
    : undefined;

  const getIntelById = (intelId: string) =>
    localIntel.find((intel) => intel.id === intelId) ??
    swarmIntelRecords.find((record) => record.intel.id === intelId)?.intel;

  const getIntelSource = (intelId: string): IntelSource | undefined => {
    if (localIntel.some((intel) => intel.id === intelId)) return "local";
    if (swarmIntelRecords.some((record) => record.intel.id === intelId)) return "swarm";
    return undefined;
  };

  const getSwarmIntelRecord = (intelId: string) =>
    swarmIntelRecords.find((record) => record.intel.id === intelId);

  const getSwarmIntelRecords = (intelId: string) =>
    swarmIntelRecords.filter((record) => record.intel.id === intelId);

  const listIntelBySource = (source: IntelSource) =>
    source === "local" ? localIntel : swarmIntel;

  const listSwarmIntelBySwarm = (swarmId: string) =>
    swarmIntelRecords
      .filter((record) => record.swarmId === swarmId)
      .map((record) => record.intel);

  return {
    localIntel,
    swarmIntel,
    swarmIntelRecords,
    activeIntelId,
    activeIntel,
    upsertLocalIntel: actions.upsertLocalIntel,
    removeLocalIntel: actions.removeLocalIntel,
    ingestSwarmIntel: actions.ingestSwarmIntel,
    removeSwarmIntel: actions.removeSwarmIntel,
    setActiveIntel: actions.setActiveIntel,
    getIntelById,
    getIntelSource,
    getSwarmIntelRecord,
    getSwarmIntelRecords,
    listIntelBySource,
    listSwarmIntelBySwarm,
  };
}
