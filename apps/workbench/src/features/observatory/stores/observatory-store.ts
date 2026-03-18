import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import type { ObservatoryStation, ObservatorySeamSummary, ObservatoryState } from "../types";

const DEFAULT_SEAM_SUMMARY: ObservatorySeamSummary = {
  stationCount: 0,
  artifactCount: 0,
  activeProbes: 0,
};

const useObservatoryStoreBase = create<ObservatoryState>((set, get) => ({
  stations: [],
  seamSummary: { ...DEFAULT_SEAM_SUMMARY },
  connected: false,
  actions: {
    setStations: (stations: ObservatoryStation[]) => {
      const artifactCount = stations.reduce((sum, s) => sum + s.artifactCount, 0);
      set({
        stations,
        seamSummary: {
          ...get().seamSummary,
          stationCount: stations.length,
          artifactCount,
        },
      });
    },
    updateSeamSummary: (summary: Partial<ObservatorySeamSummary>) =>
      set((state) => ({ seamSummary: { ...state.seamSummary, ...summary } })),
    setConnected: (connected: boolean) => set({ connected }),
    addArtifacts: (stationId: string, count: number) => {
      set((state) => {
        const stations = state.stations.map((s) =>
          s.id === stationId ? { ...s, artifactCount: s.artifactCount + count } : s,
        );
        const artifactCount = stations.reduce((sum, s) => sum + s.artifactCount, 0);
        return {
          stations,
          seamSummary: { ...state.seamSummary, artifactCount },
        };
      });
    },
  },
}));

export const useObservatoryStore = createSelectors(useObservatoryStoreBase);
