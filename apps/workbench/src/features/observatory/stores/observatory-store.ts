import { create } from "zustand";
import { createSelectors } from "@/lib/create-selectors";
import type {
  ObservatoryReplayAnnotation,
  ObservatoryReplayBookmark,
  ObservatoryReplayMarker,
  ObservatoryStation,
  ObservatorySeamSummary,
  ObservatoryState,
} from "../types";
import {
  createObservatoryMissionLoopState,
  completeObservatoryMissionObjective,
} from "../world/missionLoop";
import { createInitialObservatoryProbeState } from "../world/probeRuntime";
import { HUNT_STATION_LABELS, HUNT_STATION_ORDER } from "../world/stations";
import { getObservatoryNowMs } from "../utils/observatory-time";
import {
  DEFAULT_FLIGHT_STATE,
  type FlightState,
} from "../character/ship/flight-types";
import {
  DEFAULT_DOCKING_STATE,
  type DockingState,
} from "../character/ship/docking-types";

function createDefaultObservatoryStations(): ObservatoryStation[] {
  return HUNT_STATION_ORDER.map((id) => ({
    id,
    kind: "observatory",
    label: HUNT_STATION_LABELS[id],
    route: "/observatory",
    artifactCount: 0,
  }));
}

const DEFAULT_STATIONS = createDefaultObservatoryStations();

const DEFAULT_SEAM_SUMMARY: ObservatorySeamSummary = {
  stationCount: DEFAULT_STATIONS.length,
  artifactCount: 0,
  activeProbes: 0,
};

const useObservatoryStoreBase = create<ObservatoryState>((set, get) => ({
  stations: DEFAULT_STATIONS,
  pressureLanes: [],
  analystPresetId: null,
  seamSummary: { ...DEFAULT_SEAM_SUMMARY },
  connected: false,
  confidence: 0,
  likelyStationId: null,
  mission: null,
  probeState: createInitialObservatoryProbeState(),
  replay: {
    enabled: false,
    frameIndex: 0,
    frameMs: null,
    selectedSpikeTimestampMs: null,
    selectedDistrictId: null,
    bookmarks: [],
    annotations: [],
    markers: [],
  },
  roomReceiveState: "idle",
  selectedStationId: null,
  telemetrySnapshotMs: null,
  flightState: { ...DEFAULT_FLIGHT_STATE },
  dockingState: { ...DEFAULT_DOCKING_STATE },
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
    setActiveProbes: (activeProbes: number) =>
      set((state) => ({
        seamSummary: {
          ...state.seamSummary,
          activeProbes: Math.max(0, Math.floor(activeProbes)),
        },
      })),
    setConnected: (connected: boolean) => set({ connected }),
    setSceneTelemetry: ({
      confidence,
      likelyStationId,
      pressureLanes = [],
      roomReceiveState,
      telemetrySnapshotMs = null,
    }) =>
      set({
        confidence,
        likelyStationId,
        pressureLanes,
        roomReceiveState,
        telemetrySnapshotMs,
      }),
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
    setMission: (mission) => set({ mission }),
    startMission: (huntId: string, nowMs = getObservatoryNowMs(), options = {}) => {
      const mission = createObservatoryMissionLoopState(huntId, nowMs, options);
      set({ mission });
      return mission;
    },
    setProbeState: (next) =>
      set((state) => ({
        probeState:
          typeof next === "function"
            ? (next as (current: typeof state.probeState) => typeof state.probeState)(state.probeState)
            : next,
      })),
    resetProbe: () => set({ probeState: createInitialObservatoryProbeState() }),
    setReplayState: (replay) =>
      set((state) => {
        const nextReplay = { ...state.replay, ...replay };
        if (nextReplay.enabled === false) {
          nextReplay.selectedSpikeTimestampMs = null;
          nextReplay.selectedDistrictId = null;
        }
        return { replay: nextReplay };
      }),
    setSelectedStation: (selectedStationId) => set({ selectedStationId }),
    setAnalystPreset: (analystPresetId) => set({ analystPresetId }),
    setReplayMarkers: (markers: ObservatoryReplayMarker[]) =>
      set((state) => ({
        replay: {
          ...state.replay,
          markers,
        },
      })),
    hydrateReplayArtifacts: ({ bookmarks, annotations }) =>
      set((state) => ({
        replay: {
          ...state.replay,
          bookmarks,
          annotations,
        },
      })),
    addReplayBookmark: (bookmark: ObservatoryReplayBookmark) =>
      set((state) => {
        const bookmarks = state.replay.bookmarks ?? [];
        if (bookmarks.some((entry) => entry.id === bookmark.id)) {
          return state;
        }
        return {
          replay: {
            ...state.replay,
            bookmarks: [...bookmarks, bookmark],
          },
        };
      }),
    removeReplayBookmark: (bookmarkId: string) =>
      set((state) => ({
        replay: {
          ...state.replay,
          bookmarks: (state.replay.bookmarks ?? []).filter((bookmark) => bookmark.id !== bookmarkId),
        },
      })),
    upsertReplayAnnotation: (annotation: ObservatoryReplayAnnotation) =>
      set((state) => {
        const annotations = state.replay.annotations ?? [];
        const index = annotations.findIndex((entry) => entry.id === annotation.id);
        return {
          replay: {
            ...state.replay,
            annotations:
              index >= 0
                ? annotations.map((entry, currentIndex) => (currentIndex === index ? annotation : entry))
                : [...annotations, annotation],
          },
        };
      }),
    removeReplayAnnotation: (annotationId: string) =>
      set((state) => ({
        replay: {
          ...state.replay,
          annotations: (state.replay.annotations ?? []).filter((annotation) => annotation.id !== annotationId),
        },
      })),
    completeObjective: (assetId, nowMs = getObservatoryNowMs(), options = {}) => {
      const currentMission = get().mission;
      if (!currentMission) {
        return null;
      }
      const mission = completeObservatoryMissionObjective(
        currentMission,
        assetId,
        nowMs,
        options,
      );
      set({ mission });
      return mission;
    },
    resetMission: () => set({ mission: null }),
    setFlightState: (updater: FlightState | ((current: FlightState) => FlightState)) =>
      set((state) => ({
        flightState: typeof updater === "function" ? updater(state.flightState) : updater,
      })),
    resetFlightState: () =>
      set({ flightState: { ...DEFAULT_FLIGHT_STATE } }),
    setDockingState: (updater: DockingState | ((current: DockingState) => DockingState)) =>
      set((state) => ({
        dockingState: typeof updater === "function" ? updater(state.dockingState) : updater,
      })),
    resetDockingState: () =>
      set({ dockingState: { ...DEFAULT_DOCKING_STATE } }),
  },
}));

export const useObservatoryStore = createSelectors(useObservatoryStoreBase);
