import type {
  ObservatoryAnalystPresetId,
  ObservatoryStation,
} from "../types";
import { HUNT_STATION_LABELS, HUNT_STATION_ORDER } from "./stations";
import type {
  HuntObservatorySceneState,
  HuntObservatoryMode,
  HuntStationState,
  HuntStationId,
} from "./types";

const PRESET_FOCUS_STATION: Record<ObservatoryAnalystPresetId, HuntStationId> = {
  threat: "watch",
  evidence: "case-notes",
  receipts: "receipts",
  ghost: "watch",
};

export function buildObservatoryStationStates(
  stations: ObservatoryStation[],
  analystPresetId: ObservatoryAnalystPresetId | null = null,
): HuntStationState[] {
  const stationMap = new Map(stations.map((station) => [station.id, station]));
  const presetFocusStationId = analystPresetId ? PRESET_FOCUS_STATION[analystPresetId] : null;
  return HUNT_STATION_ORDER.map((stationId) => {
    const station = stationMap.get(stationId);
    const emphasis = station?.emphasis ?? 0;
    const presetBoost = presetFocusStationId === stationId ? 0.16 : 0;
    return {
      affinity: station?.affinity ?? 0,
      artifactCount: station?.artifactCount ?? 0,
      emphasis: Math.min(1, emphasis + presetBoost),
      hasUnread: station?.hasUnread ?? (station?.artifactCount ?? 0) > 0,
      id: stationId,
      label: station?.label ?? HUNT_STATION_LABELS[stationId],
      reason: station?.reason ?? null,
      status: station?.status ?? "idle",
    };
  });
}

export function buildObservatorySceneState(input: {
  analystPresetId?: ObservatoryAnalystPresetId | null;
  confidence: number;
  likelyStationId: HuntObservatorySceneState["likelyStationId"];
  mode: HuntObservatoryMode;
  roomReceiveState: HuntObservatorySceneState["roomReceiveState"];
  spiritFieldBias: number;
  stations: ObservatoryStation[];
}): HuntObservatorySceneState {
  return {
    activeSelection: { type: "none" },
    cameraPreset:
      input.analystPresetId != null
        ? "focus-station"
        : "overview",
    confidence: input.confidence,
    huntId: "workbench",
    likelyStationId:
      input.analystPresetId != null
        ? PRESET_FOCUS_STATION[input.analystPresetId]
        : input.likelyStationId,
    mode: input.mode,
    openedDetailSurface:
      input.analystPresetId === "receipts"
        ? "bottom"
        : input.analystPresetId != null
          ? "rail"
          : "none",
    roomReceiveState: input.roomReceiveState,
    spiritFieldBias: input.spiritFieldBias,
    stations: buildObservatoryStationStates(
      input.stations,
      input.analystPresetId ?? null,
    ),
  };
}
