import type {
  ObservatoryMissionLoopOptions,
  ObservatoryMissionLoopState,
} from "./world/missionLoop";
import type { ObservatoryHeroPropAssetId } from "./world/propAssets";
import type { ObservatoryProbeState } from "./world/probeRuntime";
import type {
  HuntObservatoryReceiveState,
  HuntStationId,
  HuntStationStatus,
} from "./world/types";
import type { FlightState } from "./character/ship/flight-types";
import type { DockingState } from "./character/ship/docking-types";

export type ObservatoryStationKind =
  | "hunt"           // maps to /hunt pane route
  | "observatory"    // maps to /observatory pane route (Phase 3)
  | "nexus"          // maps to /nexus pane route (Phase 4)
  | "spirit-chamber" // maps to /spirit-chamber pane route (Phase 2)
  | "missions"
  | "findings"
  | "receipt-preview";

export interface ObservatoryExplanationCause {
  id: string;
  kind: "traffic" | "anomaly" | "operations" | "receipt" | "investigation" | "pattern" | "policy-gap" | "watch";
  label: string;
  summary: string;
  count: number;
  weight: number;
  route: string;
  routeLabel: string;
}

export interface ObservatoryStationExplanation {
  stationId: HuntStationId;
  summary: string;
  generatedAtMs: number;
  primaryLaneId: HuntStationId | null;
  causes: ObservatoryExplanationCause[];
}

export interface ObservatoryReplayBookmark {
  id: string;
  frameIndex: number;
  timestampMs: number;
  label: string;
  districtId: HuntStationId;
  note?: string;
}

export interface ObservatoryReplayAnnotation {
  id: string;
  frameIndex: number;
  timestampMs: number;
  districtId: HuntStationId;
  authorLabel: string;
  body: string;
  sourceType: "manual" | "bookmark" | "spike";
  sourceId?: string;
}

export interface ObservatoryReplayMarker {
  id: string;
  frameIndex: number;
  timestampMs: number;
  districtId: HuntStationId | null;
  label: string;
  sourceType: "bookmark" | "annotation" | "investigation" | "analyst";
  sourceId?: string | null;
  authorLabel?: string | null;
}

export interface ObservatoryPressureLane {
  stationId: HuntStationId;
  label: string;
  route: string;
  routeLabel: string;
  rawPressure: number;
  score: number;
  affinity: number;
  emphasis: number;
  status: HuntStationStatus;
  rank: number;
  isPrimary: boolean;
}

export type HudPanelId = "explainability" | "replay" | "mission" | "ghost";

export interface ObservatoryAnnotationPin {
  id: string;
  frameIndex: number;
  timestampMs: number;
  worldPosition: [number, number, number];
  note: string;
  districtId: HuntStationId;
}

export interface ConstellationRoute {
  id: string;
  name: string;
  createdAtMs: number;
  stationPath: HuntStationId[];
  missionHuntId: string;
}

export interface ObservatoryInteriorState {
  active: boolean;
  stationId: HuntStationId | null;
  transitionPhase: "entering" | "inside" | "exiting" | null;
}

export type ObservatoryAnalystPresetId = "threat" | "evidence" | "receipts" | "ghost";

export interface ObservatoryStation {
  affinity?: number;
  emphasis?: number;
  hasUnread?: boolean;
  id: HuntStationId;
  kind: ObservatoryStationKind;
  label: string;
  reason?: string | null;
  route: string; // workbench pane route to openApp to
  routeLabel?: string;
  artifactCount: number;
  status?: HuntStationStatus;
  explanation?: ObservatoryStationExplanation | null;
}

export interface ObservatoryReplayState {
  enabled: boolean;
  frameIndex: number;
  frameMs: number | null;
  selectedSpikeTimestampMs?: number | null;
  selectedDistrictId?: HuntStationId | null;
  bookmarks?: ObservatoryReplayBookmark[];
  annotations?: ObservatoryReplayAnnotation[];
  markers?: ObservatoryReplayMarker[];
}

export interface ObservatorySeamSummary {
  stationCount: number;
  artifactCount: number; // total across all stations — drives activity bar badge
  activeProbes: number;  // > 0 means hunt is live; drives badge liveness
}

export interface ObservatoryState {
  stations: ObservatoryStation[];
  pressureLanes: ObservatoryPressureLane[];
  analystPresetId: ObservatoryAnalystPresetId | null;
  seamSummary: ObservatorySeamSummary;
  connected: boolean; // true when linked to live hunt data
  confidence: number;
  likelyStationId: HuntStationId | null;
  mission: ObservatoryMissionLoopState | null;
  probeState: ObservatoryProbeState;
  replay: ObservatoryReplayState;
  roomReceiveState: HuntObservatoryReceiveState;
  selectedStationId: HuntStationId | null;
  telemetrySnapshotMs: number | null;
  /** Phase 21: space flight state slice */
  flightState: FlightState;
  /** Phase 23: docking state slice */
  dockingState: DockingState;
  /** Phase 25: autopilot target — separate from flightState (user intent, not physics) */
  autopilotTargetStationId: HuntStationId | null;
  /** Phase 26: session-only discovery set — stations revealed by proximity fly-through */
  discoveredStations: Set<HuntStationId>;
  /** Phase 29: panel registry — only one HUD panel open at a time */
  activePanel: HudPanelId | null;
  /** Phase 39: annotation pins dropped during replay */
  annotationPins: ObservatoryAnnotationPin[];
  /** Phase 39: constellation routes from completed missions */
  constellations: ConstellationRoute[];
  /** Phase 39: interior zone state machine */
  interiorState: ObservatoryInteriorState;
  actions: {
    setStations: (stations: ObservatoryStation[]) => void;
    updateSeamSummary: (summary: Partial<ObservatorySeamSummary>) => void;
    setActiveProbes: (activeProbes: number) => void;
    setConnected: (connected: boolean) => void;
    setSceneTelemetry: (telemetry: {
      confidence: number;
      likelyStationId: HuntStationId | null;
      pressureLanes?: ObservatoryPressureLane[];
      roomReceiveState: HuntObservatoryReceiveState;
      telemetrySnapshotMs?: number | null;
    }) => void;
    addArtifacts: (stationId: string, count: number) => void;
    setMission: (mission: ObservatoryMissionLoopState | null) => void;
    startMission: (
      huntId: string,
      nowMs?: number,
      options?: ObservatoryMissionLoopOptions,
    ) => ObservatoryMissionLoopState;
    setProbeState: (
      next:
        | ObservatoryProbeState
        | ((current: ObservatoryProbeState) => ObservatoryProbeState),
    ) => void;
    resetProbe: () => void;
    setReplayState: (replay: Partial<ObservatoryReplayState>) => void;
    setSelectedStation: (stationId: HuntStationId | null) => void;
    setAnalystPreset: (presetId: ObservatoryAnalystPresetId | null) => void;
    setReplayMarkers: (markers: ObservatoryReplayMarker[]) => void;
    hydrateReplayArtifacts: (input: {
      bookmarks: ObservatoryReplayBookmark[];
      annotations: ObservatoryReplayAnnotation[];
    }) => void;
    addReplayBookmark: (bookmark: ObservatoryReplayBookmark) => void;
    removeReplayBookmark: (bookmarkId: string) => void;
    upsertReplayAnnotation: (annotation: ObservatoryReplayAnnotation) => void;
    removeReplayAnnotation: (annotationId: string) => void;
    completeObjective: (
      assetId: ObservatoryHeroPropAssetId,
      nowMs?: number,
      options?: ObservatoryMissionLoopOptions,
    ) => ObservatoryMissionLoopState | null;
    resetMission: () => void;
    setFlightState: (updater: FlightState | ((current: FlightState) => FlightState)) => void;
    resetFlightState: () => void;
    setDockingState: (updater: DockingState | ((current: DockingState) => DockingState)) => void;
    resetDockingState: () => void;
    setAutopilotTarget: (stationId: HuntStationId | null) => void;
    clearAutopilot: () => void;
    discoverStation: (stationId: HuntStationId) => void;
    openPanel: (id: HudPanelId) => void;
    closePanel: () => void;
    togglePanel: (id: HudPanelId) => void;
    addAnnotationPin: (pin: ObservatoryAnnotationPin) => void;
    removeAnnotationPin: (pinId: string) => void;
    clearAnnotationPins: () => void;
    addConstellation: (route: ConstellationRoute) => void;
    removeConstellation: (routeId: string) => void;
    clearConstellations: () => void;
    setInteriorState: (state: Partial<ObservatoryInteriorState>) => void;
    clearInterior: () => void;
  };
}
