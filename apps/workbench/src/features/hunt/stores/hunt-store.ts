import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import type {
  AgentBaseline,
  AgentEvent,
  Annotation,
  HuntPattern,
  Investigation,
  StreamStats,
} from "@/lib/workbench/hunt-types";

export interface HuntTelemetrySnapshot {
  baselines: AgentBaseline[];
  events: AgentEvent[];
  lastUpdatedAt: string | null;
  stats: StreamStats;
}

export interface HuntStoreState extends HuntTelemetrySnapshot {
  connected: boolean;
  investigations: Investigation[];
  isLive: boolean;
  isLoading: boolean;
  patterns: HuntPattern[];
  actions: {
    addAnnotation: (investigationId: string, annotation: Omit<Annotation, "id"> & { id?: string }) => void;
    createInvestigation: (investigation: Investigation) => void;
    replaceTelemetry: (snapshot: HuntTelemetrySnapshot) => void;
    setConnected: (connected: boolean) => void;
    setInvestigations: (investigations: Investigation[]) => void;
    setLive: (live: boolean) => void;
    setLoading: (loading: boolean) => void;
    setPatterns: (patterns: HuntPattern[]) => void;
    updateInvestigation: (id: string, updates: Partial<Investigation>) => void;
  };
}

const EMPTY_STATS: StreamStats = {
  total: 0,
  allowed: 0,
  denied: 0,
  warned: 0,
  anomalies: 0,
  byActionType: {},
};

const useHuntStoreBase = create<HuntStoreState>((set) => ({
  baselines: [],
  connected: false,
  events: [],
  investigations: [],
  isLive: true,
  isLoading: false,
  lastUpdatedAt: null,
  patterns: [],
  stats: EMPTY_STATS,
  actions: {
    addAnnotation: (investigationId, annotation) =>
      set((state) => ({
        investigations: state.investigations.map((investigation) =>
          investigation.id === investigationId
            ? {
                ...investigation,
                annotations: [
                  ...investigation.annotations,
                  {
                    createdAt: annotation.createdAt,
                    createdBy: annotation.createdBy,
                    eventId: annotation.eventId,
                    id: annotation.id ?? crypto.randomUUID(),
                    text: annotation.text,
                  },
                ],
                updatedAt: annotation.createdAt,
              }
            : investigation,
        ),
      })),
    createInvestigation: (investigation) =>
      set((state) => ({
        investigations: [investigation, ...state.investigations],
      })),
    replaceTelemetry: (snapshot) =>
      set({
        baselines: snapshot.baselines,
        events: snapshot.events,
        lastUpdatedAt: snapshot.lastUpdatedAt,
        stats: snapshot.stats,
      }),
    setConnected: (connected) => set({ connected }),
    setInvestigations: (investigations) => set({ investigations }),
    setLive: (isLive) => set({ isLive }),
    setLoading: (isLoading) => set({ isLoading }),
    setPatterns: (patterns) => set({ patterns }),
    updateInvestigation: (id, updates) =>
      set((state) => ({
        investigations: state.investigations.map((investigation) =>
          investigation.id === id
            ? {
                ...investigation,
                ...updates,
                updatedAt: updates.updatedAt ?? new Date().toISOString(),
              }
            : investigation,
        ),
      })),
  },
}));

export const useHuntStore = createSelectors(useHuntStoreBase);
