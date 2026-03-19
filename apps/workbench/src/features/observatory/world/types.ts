// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/types.ts
// These are the canonical world types that ObservatoryWorldCanvas accepts.
// Note: different from apps/workbench/src/features/observatory/types.ts (workbench store types).

export type HuntObservatoryMode = "flow" | "atlas";

export type HuntStationId =
  | "signal"
  | "targets"
  | "run"
  | "receipts"
  | "case-notes"
  | "watch";

export type HuntStationStatus = "idle" | "warming" | "active" | "receiving" | "blocked";

export interface HuntStationPlacement {
  id: HuntStationId;
  label: string;
  angleDeg: number;
  radius: number;
}

export interface HuntStationState {
  id: HuntStationId;
  label: string;
  status: HuntStationStatus;
  affinity: number;
  emphasis: number;
  artifactCount: number;
  hasUnread: boolean;
  reason?: string | null;
}

export type HuntObservatorySelection =
  | { type: "station"; stationId: HuntStationId }
  | { type: "run"; runId: string }
  | { type: "receipt"; receiptId: string }
  | { type: "artifact"; artifactId: string }
  | { type: "entity"; entityId: string }
  | { type: "none" };

export type HuntObservatoryDetailSurface = "none" | "tab" | "rail" | "bottom";
export type HuntObservatoryReceiveState = "idle" | "receiving" | "aftermath";
export type HuntObservatoryCameraPreset = "overview" | "follow-run" | "focus-station";

export interface HuntObservatorySceneState {
  huntId: string;
  mode: HuntObservatoryMode;
  stations: HuntStationState[];
  activeSelection: HuntObservatorySelection;
  likelyStationId: HuntStationId | null;
  roomReceiveState: HuntObservatoryReceiveState;
  spiritFieldBias: number;
  confidence: number;
  cameraPreset: HuntObservatoryCameraPreset;
  openedDetailSurface: HuntObservatoryDetailSurface;
}

export interface HuntCoreActor {
  type: "hunt-core";
  huntId: string;
  title: string;
  posture: "triage" | "investigate" | "report";
  centerStrength: number;
}

export interface HuntStationActor {
  type: "station";
  stationId: HuntStationId;
  label: string;
  affinity: number;
  emphasis: number;
  status: HuntStationStatus;
  reason?: string | null;
}

export interface RunFlowActor {
  type: "run-flow";
  runId: string;
  status: "queued" | "running" | "blocked" | "completed";
  sourceStationId: HuntStationId;
  targetStationId: HuntStationId;
  intensity: number;
  policyPressure: number;
}

export interface ReceiptActor {
  type: "receipt";
  receiptId: string;
  stationId: HuntStationId;
  severity: number;
  freshness: number;
  grouped: boolean;
}

export interface EvidenceLinkActor {
  type: "evidence-link";
  sourceId: string;
  targetId: string;
  semantic: "target" | "evidence" | "cite" | "watch" | "run-input";
  strength: number;
}

export interface WatchBeaconActor {
  type: "watch-beacon";
  stationId: "watch";
  count: number;
  urgency: number;
}

export interface SpiritFieldActor {
  type: "spirit-field";
  kind: "tracker" | "lantern" | "forge" | "loom" | "ledger";
  stance: "watchful" | "focus" | "witness" | "absorb" | "transit";
  likelyStationId: HuntStationId | null;
  emphasis: string[];
  cueKind: "bind" | "focus" | "transit" | "witness" | "absorb" | null;
}

export type HuntObservatoryActor =
  | HuntCoreActor
  | HuntStationActor
  | RunFlowActor
  | ReceiptActor
  | EvidenceLinkActor
  | WatchBeaconActor
  | SpiritFieldActor;
