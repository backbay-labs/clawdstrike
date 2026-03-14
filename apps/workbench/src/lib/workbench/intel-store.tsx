import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useReducer,
  useRef,
  type ReactNode,
} from "react";
import type { Intel } from "./sentinel-types";
import { isIntel } from "./sentinel-types";

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

type IntelAction =
  | { type: "UPSERT_LOCAL"; intel: Intel }
  | { type: "REMOVE_LOCAL"; intelId: string }
  | { type: "INGEST_SWARM"; record: SwarmIntelRecord }
  | { type: "REMOVE_SWARM"; intelId: string; swarmId?: string }
  | { type: "SET_ACTIVE"; intelId: string | null }
  | { type: "LOAD"; state: IntelState };

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

function intelReducer(state: IntelState, action: IntelAction): IntelState {
  switch (action.type) {
    case "UPSERT_LOCAL": {
      const localIntel = sortLocalIntel([
        ...state.localIntel.filter((intel) => intel.id !== action.intel.id),
        action.intel,
      ]);

      return {
        ...state,
        localIntel,
        activeIntelId: action.intel.id,
      };
    }
    case "REMOVE_LOCAL": {
      const nextState = {
        ...state,
        localIntel: state.localIntel.filter((intel) => intel.id !== action.intelId),
      };

      return {
        ...nextState,
        activeIntelId:
          state.activeIntelId === action.intelId ? nextActiveIntelId(nextState) : state.activeIntelId,
      };
    }
    case "INGEST_SWARM": {
      const swarmIntel = sortSwarmIntel([
        ...state.swarmIntel.filter(
          (record) => swarmIntelKey(record) !== swarmIntelKey(action.record),
        ),
        action.record,
      ]);

      return {
        ...state,
        swarmIntel,
        activeIntelId: state.activeIntelId ?? action.record.intel.id,
      };
    }
    case "REMOVE_SWARM": {
      const nextState = {
        ...state,
        swarmIntel: state.swarmIntel.filter((record) => {
          if (record.intel.id !== action.intelId) {
            return true;
          }
          if (!action.swarmId) {
            return false;
          }
          return record.swarmId !== action.swarmId;
        }),
      };

      return {
        ...nextState,
        activeIntelId:
          state.activeIntelId === action.intelId ? nextActiveIntelId(nextState) : state.activeIntelId,
      };
    }
    case "SET_ACTIVE": {
      if (action.intelId === null) {
        return { ...state, activeIntelId: null };
      }
      return hasIntel(state, action.intelId) ? { ...state, activeIntelId: action.intelId } : state;
    }
    case "LOAD":
      return action.state;
    default:
      return state;
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
    localStorage.setItem(
      INTEL_STORAGE_KEY,
      JSON.stringify({
        localIntel: state.localIntel,
        swarmIntel: state.swarmIntel,
        activeIntelId: state.activeIntelId,
      }),
    );
  } catch (error) {
    console.error("[intel-store] persistIntel failed:", error);
  }
}

function getInitialState(): IntelState {
  return (
    loadPersistedIntel() ?? {
      localIntel: [],
      swarmIntel: [],
      activeIntelId: null,
    }
  );
}

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

const IntelContext = createContext<IntelContextValue | null>(null);

export function useIntel(): IntelContextValue {
  const ctx = useContext(IntelContext);
  if (!ctx) {
    throw new Error("useIntel must be used within IntelProvider");
  }
  return ctx;
}

export function IntelProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(intelReducer, undefined, getInitialState);
  const persistRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stateRef = useRef(state);
  stateRef.current = state;

  useEffect(() => {
    if (persistRef.current) {
      clearTimeout(persistRef.current);
    }
    persistRef.current = setTimeout(() => {
      persistIntel(state);
      persistRef.current = null;
    }, 500);

    return () => {
      if (persistRef.current) {
        clearTimeout(persistRef.current);
      }
    };
  }, [state.localIntel, state.swarmIntel, state.activeIntelId]);

  useEffect(() => {
    const handleBeforeUnload = () => {
      if (persistRef.current) {
        clearTimeout(persistRef.current);
        persistRef.current = null;
        persistIntel(stateRef.current);
      }
    };
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => {
      window.removeEventListener("beforeunload", handleBeforeUnload);
    };
  }, []);

  const getIntelById = useCallback(
    (intelId: string) =>
      state.localIntel.find((intel) => intel.id === intelId) ??
      state.swarmIntel.find((record) => record.intel.id === intelId)?.intel,
    [state.localIntel, state.swarmIntel],
  );

  const getIntelSource = useCallback(
    (intelId: string): IntelSource | undefined => {
      if (state.localIntel.some((intel) => intel.id === intelId)) {
        return "local";
      }
      if (state.swarmIntel.some((record) => record.intel.id === intelId)) {
        return "swarm";
      }
      return undefined;
    },
    [state.localIntel, state.swarmIntel],
  );

  const getSwarmIntelRecord = useCallback(
    (intelId: string) => state.swarmIntel.find((record) => record.intel.id === intelId),
    [state.swarmIntel],
  );

  const getSwarmIntelRecords = useCallback(
    (intelId: string) => state.swarmIntel.filter((record) => record.intel.id === intelId),
    [state.swarmIntel],
  );

  const listIntelBySource = useCallback(
    (source: IntelSource) =>
      source === "local"
        ? state.localIntel
        : listUniqueSwarmIntel(state.swarmIntel),
    [state.localIntel, state.swarmIntel],
  );

  const listSwarmIntelBySwarm = useCallback(
    (swarmId: string) =>
      state.swarmIntel
        .filter((record) => record.swarmId === swarmId)
        .map((record) => record.intel),
    [state.swarmIntel],
  );

  const upsertLocalIntel = useCallback((intel: Intel) => {
    dispatch({ type: "UPSERT_LOCAL", intel });
  }, []);

  const removeLocalIntel = useCallback((intelId: string) => {
    dispatch({ type: "REMOVE_LOCAL", intelId });
  }, []);

  const ingestSwarmIntel = useCallback((record: SwarmIntelRecord) => {
    dispatch({ type: "INGEST_SWARM", record });
  }, []);

  const removeSwarmIntel = useCallback((intelId: string, swarmId?: string) => {
    dispatch({ type: "REMOVE_SWARM", intelId, swarmId });
  }, []);

  const setActiveIntel = useCallback((intelId: string | null) => {
    dispatch({ type: "SET_ACTIVE", intelId });
  }, []);

  const value: IntelContextValue = {
    localIntel: state.localIntel,
    swarmIntel: listUniqueSwarmIntel(state.swarmIntel),
    swarmIntelRecords: state.swarmIntel,
    activeIntelId: state.activeIntelId,
    activeIntel: state.activeIntelId ? getIntelById(state.activeIntelId) : undefined,
    upsertLocalIntel,
    removeLocalIntel,
    ingestSwarmIntel,
    removeSwarmIntel,
    setActiveIntel,
    getIntelById,
    getIntelSource,
    getSwarmIntelRecord,
    getSwarmIntelRecords,
    listIntelBySource,
    listSwarmIntelBySwarm,
  };

  return <IntelContext.Provider value={value}>{children}</IntelContext.Provider>;
}
