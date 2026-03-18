import type { HuntSpiritSignalSnapshot } from "@/shell/workbench/spirit/selectors";
import { HUNT_STATION_LABELS, HUNT_STATION_ORDER } from "../stations";
import type {
  HuntObservatoryCameraPreset,
  HuntObservatoryDetailSurface,
  HuntObservatorySceneState,
  HuntObservatorySelection,
  HuntObservatoryMode,
  HuntObservatoryReceiveState,
  HuntStationId,
  HuntStationState,
  HuntStationStatus,
} from "../types";

export interface HuntObservatorySelectorOptions {
  mode?: HuntObservatoryMode;
  activeStationId?: HuntStationId | null;
  roomReceiveState?: HuntObservatoryReceiveState;
  openedDetailSurface?: HuntObservatoryDetailSurface;
  activeSelection?: HuntObservatorySelection | null;
}

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function countOf(
  counts: HuntSpiritSignalSnapshot["artifactCounts"] | HuntSpiritSignalSnapshot["semanticCounts"],
  key: string,
): number {
  const value = counts[key as keyof typeof counts];
  return typeof value === "number" ? value : 0;
}

function addWeight(
  scores: Partial<Record<HuntStationId, number>>,
  stationId: HuntStationId,
  amount: number,
): void {
  scores[stationId] = (scores[stationId] ?? 0) + amount;
}

function reasonForStation(
  stationId: HuntStationId,
  snapshot: HuntSpiritSignalSnapshot,
  activeStationId: HuntStationId | null,
  likelyStationId: HuntStationId | null,
): string | null {
  if (stationId === activeStationId) return "Current station focus.";
  if (stationId === likelyStationId) {
    switch (stationId) {
      case "signal":
        return "Fresh change is arriving at the edge of the hunt world.";
      case "targets":
        return "Subjects and active relationships are pulling hardest here.";
      case "run":
        return "Operator machinery and mounted inputs are driving the field.";
      case "receipts":
        return "Evidence and replayable traces are gathering weight.";
      case "case-notes":
        return "Authored meaning is hardening into judgment.";
      case "watch":
        return "Watchfield pressure is shaping the perimeter.";
    }
  }
  return null;
}

export function deriveHuntObservatoryStationAffinities(
  snapshot: HuntSpiritSignalSnapshot,
): Partial<Record<HuntStationId, number>> {
  const scores: Partial<Record<HuntStationId, number>> = {};

  const receiptCount = countOf(snapshot.artifactCounts, "receipt");
  const evidenceCount = countOf(snapshot.artifactCounts, "evidence");
  const fileCount = countOf(snapshot.artifactCounts, "file");
  const entityCount = countOf(snapshot.artifactCounts, "entity");
  const signalCount = countOf(snapshot.artifactCounts, "signal");
  const noteCount = countOf(snapshot.artifactCounts, "note");

  addWeight(scores, "signal", Math.min(0.55, signalCount * 0.18));
  addWeight(scores, "targets", Math.min(0.65, entityCount * 0.16));
  addWeight(scores, "run", Math.min(0.7, fileCount * 0.16 + snapshot.runningRunCount * 0.2));
  addWeight(scores, "receipts", Math.min(0.8, receiptCount * 0.18 + evidenceCount * 0.16));
  addWeight(scores, "case-notes", Math.min(0.55, noteCount * 0.16));
  addWeight(scores, "watch", Math.min(0.65, countOf(snapshot.semanticCounts, "watch") * 0.22));

  addWeight(scores, "targets", countOf(snapshot.semanticCounts, "target") * 0.18);
  addWeight(scores, "receipts", countOf(snapshot.semanticCounts, "evidence") * 0.16);
  addWeight(scores, "run", countOf(snapshot.semanticCounts, "run-input") * 0.22);
  addWeight(scores, "run", countOf(snapshot.semanticCounts, "mount") * 0.18);
  addWeight(scores, "case-notes", countOf(snapshot.semanticCounts, "cite") * 0.2);
  addWeight(scores, "receipts", countOf(snapshot.semanticCounts, "compare") * 0.14);
  addWeight(scores, "case-notes", countOf(snapshot.semanticCounts, "notes") * 0.16);

  switch (snapshot.likelyIntent) {
    case "attach-target":
      addWeight(scores, "targets", 0.42);
      break;
    case "attach-evidence":
    case "compare":
      addWeight(scores, "receipts", 0.42);
      break;
    case "run-input":
    case "mount":
      addWeight(scores, "run", 0.46);
      break;
    case "cite":
      addWeight(scores, "case-notes", 0.46);
      break;
    case "watch":
      addWeight(scores, "watch", 0.46);
      break;
  }

  switch (snapshot.phase) {
    case "triage":
      addWeight(scores, "signal", 0.14);
      addWeight(scores, "watch", 0.08);
      break;
    case "investigation":
      addWeight(scores, "targets", 0.12);
      addWeight(scores, "run", 0.12);
      addWeight(scores, "receipts", 0.1);
      break;
    case "reporting":
      addWeight(scores, "case-notes", 0.2);
      addWeight(scores, "receipts", 0.08);
      break;
  }

  if (snapshot.currentLens === "notes") addWeight(scores, "case-notes", 0.12);
  if (snapshot.currentLens === "entities") addWeight(scores, "targets", 0.12);
  if (snapshot.currentLens === "files") addWeight(scores, "run", 0.1);
  if (snapshot.currentShell === "wire") addWeight(scores, "signal", 0.08);
  if (snapshot.runningRunCount > 0) addWeight(scores, "run", 0.14);
  if (snapshot.activeCaseId) addWeight(scores, "case-notes", 0.12);
  if (snapshot.draggedObjectKind === "receipt" || snapshot.draggedObjectKind === "evidence") {
    addWeight(scores, "receipts", 0.14);
  }
  if (snapshot.draggedObjectKind === "file") addWeight(scores, "run", 0.12);
  if (snapshot.draggedObjectKind === "entity" || snapshot.draggedObjectKind === "signal") {
    addWeight(scores, "targets", 0.12);
  }

  return scores;
}

export function deriveHuntObservatoryLikelyStationId(
  snapshot: HuntSpiritSignalSnapshot,
): HuntStationId | null {
  const scores = deriveHuntObservatoryStationAffinities(snapshot);
  let bestId: HuntStationId | null = null;
  let bestScore = 0;

  for (const stationId of HUNT_STATION_ORDER) {
    const score = scores[stationId] ?? 0;
    if (score > bestScore) {
      bestScore = score;
      bestId = stationId;
    }
  }

  return bestId;
}

function deriveStationArtifactCount(
  stationId: HuntStationId,
  snapshot: HuntSpiritSignalSnapshot,
): number {
  switch (stationId) {
    case "signal":
      return countOf(snapshot.artifactCounts, "signal");
    case "targets":
      return countOf(snapshot.artifactCounts, "entity");
    case "run":
      return snapshot.runningRunCount + countOf(snapshot.artifactCounts, "file");
    case "receipts":
      return countOf(snapshot.artifactCounts, "receipt") + countOf(snapshot.artifactCounts, "evidence");
    case "case-notes":
      return countOf(snapshot.artifactCounts, "note");
    case "watch":
      return countOf(snapshot.semanticCounts, "watch");
  }
}

function deriveStationStatus(
  stationId: HuntStationId,
  activeStationId: HuntStationId | null,
  likelyStationId: HuntStationId | null,
  roomReceiveState: HuntObservatoryReceiveState,
): HuntStationStatus {
  if (roomReceiveState === "receiving" && stationId === likelyStationId) return "receiving";
  if (stationId === activeStationId) return "active";
  if (stationId === likelyStationId) return "warming";
  return "idle";
}

export function deriveHuntObservatoryStationStates(
  snapshot: HuntSpiritSignalSnapshot,
  options: Pick<
    HuntObservatorySelectorOptions,
    "activeStationId" | "roomReceiveState"
  > = {},
): HuntStationState[] {
  const activeStationId = options.activeStationId ?? null;
  const roomReceiveState = options.roomReceiveState ?? "idle";
  const scores = deriveHuntObservatoryStationAffinities(snapshot);
  const bestScore = Math.max(0.0001, ...HUNT_STATION_ORDER.map((stationId) => scores[stationId] ?? 0));
  const likelyStationId = deriveHuntObservatoryLikelyStationId(snapshot);

  return HUNT_STATION_ORDER.map((stationId) => {
    const affinity = clamp01((scores[stationId] ?? 0) / bestScore);
    const emphasis = clamp01(
      affinity * 0.72 + (stationId === likelyStationId ? 0.18 : 0) + (stationId === activeStationId ? 0.1 : 0),
    );
    const artifactCount = deriveStationArtifactCount(stationId, snapshot);
    return {
      id: stationId,
      label: HUNT_STATION_LABELS[stationId],
      status: deriveStationStatus(stationId, activeStationId, likelyStationId, roomReceiveState),
      affinity,
      emphasis,
      artifactCount,
      hasUnread: artifactCount > 0 && (stationId === "signal" || stationId === "receipts" || stationId === "watch"),
      reason: reasonForStation(stationId, snapshot, activeStationId, likelyStationId),
    };
  });
}

function deriveCameraPreset(
  likelyStationId: HuntStationId | null,
  confidence: number,
): HuntObservatoryCameraPreset {
  if (likelyStationId === "run") return "follow-run";
  if (likelyStationId && confidence >= 0.58) return "focus-station";
  return "overview";
}

export function deriveHuntObservatorySceneState(
  snapshot: HuntSpiritSignalSnapshot,
  options: HuntObservatorySelectorOptions = {},
): HuntObservatorySceneState {
  const mode = options.mode ?? (snapshot.currentShell === "hunt" ? "flow" : "atlas");
  const likelyStationId = deriveHuntObservatoryLikelyStationId(snapshot);
  const activeSelection =
    options.activeSelection ??
    (likelyStationId ? { type: "station", stationId: likelyStationId } : { type: "none" });
  const roomReceiveState = options.roomReceiveState ?? "idle";
  const confidence = clamp01(snapshot.confidenceScore / 100);

  return {
    huntId: snapshot.huntId,
    mode,
    stations: deriveHuntObservatoryStationStates(snapshot, {
      activeStationId: options.activeStationId,
      roomReceiveState,
    }),
    activeSelection,
    likelyStationId,
    roomReceiveState,
    spiritFieldBias: snapshot.boundSpirit ? clamp01(0.28 + confidence * 0.54) : 0,
    confidence,
    cameraPreset: deriveCameraPreset(likelyStationId, confidence),
    openedDetailSurface: options.openedDetailSurface ?? "none",
  };
}
