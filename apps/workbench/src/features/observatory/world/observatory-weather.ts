import type { ObservatoryStation } from "../types";
import type { HuntObservatoryMode, HuntObservatoryReceiveState, HuntStationId } from "./types";

export type ObservatoryWeatherBudget = "off" | "reduced" | "full";

export interface ObservatoryWeatherState {
  budget: ObservatoryWeatherBudget;
  density: number;
  dominantStationId: HuntStationId | null;
  labelOcclusionOpacity: number;
  missionClearRadius: number;
  phaseOffset: number;
  style: "clear" | "receipt-drizzle" | "perimeter-gusts" | "signal-haze" | "judgment-lattice" | "operations-surge" | "subject-swell";
  tint: string;
}

export interface ObservatoryWeatherInput {
  confidence: number;
  connected?: boolean;
  likelyStationId?: HuntStationId | null;
  mode: HuntObservatoryMode;
  missionTargetStationId?: HuntStationId | null;
  nowMs: number;
  replayEnabled?: boolean;
  roomReceiveState: HuntObservatoryReceiveState;
  saveData?: boolean;
  reducedMotion?: boolean;
  stations: ObservatoryStation[];
}

export interface ResolveObservatoryWeatherBudgetInput {
  connected?: boolean;
  reducedMotion?: boolean;
  replayEnabled?: boolean;
  saveData?: boolean;
  mode?: HuntObservatoryMode;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function hashString(input: string): number {
  let hash = 0;
  for (let index = 0; index < input.length; index += 1) {
    hash = (hash * 33 + input.charCodeAt(index)) >>> 0;
  }
  return hash;
}

function toneForStation(stationId: HuntStationId | null): ObservatoryWeatherState["style"] {
  switch (stationId) {
    case "receipts":
      return "receipt-drizzle";
    case "watch":
      return "perimeter-gusts";
    case "signal":
      return "signal-haze";
    case "case-notes":
      return "judgment-lattice";
    case "run":
      return "operations-surge";
    case "targets":
      return "subject-swell";
    default:
      return "clear";
  }
}

export function resolveObservatoryWeatherBudget(
  input: ResolveObservatoryWeatherBudgetInput,
): ObservatoryWeatherBudget {
  if (input.reducedMotion || input.saveData || input.connected === false) {
    return "off";
  }
  if (input.replayEnabled) {
    return "reduced";
  }
  if (input.mode === "flow") {
    return "full";
  }
  return "reduced";
}

export function deriveObservatoryWeatherState(
  input: ObservatoryWeatherInput,
): ObservatoryWeatherState {
  const budget = resolveObservatoryWeatherBudget({
    connected: input.connected,
    mode: input.mode,
    reducedMotion: input.reducedMotion,
    replayEnabled: input.replayEnabled,
    saveData: input.saveData,
  });
  if (budget === "off") {
    return {
      budget,
      density: 0,
      dominantStationId: null,
      labelOcclusionOpacity: 0,
      missionClearRadius: 4,
      phaseOffset: 0,
      style: "clear",
      tint: "#b7d4ff",
    };
  }

  const sortedStations = [...input.stations].sort((left, right) => {
    const leftScore = (left.emphasis ?? 0) * 2 + (left.affinity ?? 0) + left.artifactCount * 0.22 + (left.status === "receiving" ? 0.6 : left.status === "active" ? 0.45 : 0);
    const rightScore = (right.emphasis ?? 0) * 2 + (right.affinity ?? 0) + right.artifactCount * 0.22 + (right.status === "receiving" ? 0.6 : right.status === "active" ? 0.45 : 0);
    if (rightScore !== leftScore) return rightScore - leftScore;
    return left.label.localeCompare(right.label);
  });
  const dominant = sortedStations.find((station) => station.id === input.likelyStationId) ?? sortedStations[0] ?? null;
  const style = toneForStation(dominant?.id ?? null);
  const confidence = clamp(input.confidence, 0, 1);
  const receiveBias = input.roomReceiveState === "receiving" ? 0.04 : input.roomReceiveState === "aftermath" ? 0.02 : 0;
  const intensityBase =
    (dominant?.emphasis ?? 0) * 0.07 +
    (dominant?.artifactCount ?? 0) * 0.008 +
    (input.mode === "flow" ? 0.012 : 0.005) +
    (1 - confidence) * 0.03 +
    receiveBias;
  const density = clamp(intensityBase, 0, 0.12);
  const labelOcclusionOpacity = clamp(density * 1.4, 0, 0.18);
  const missionClearRadius = clamp(4.2 - density * 12, 3.5, 5.25);
  const phaseOffsetSeed = `${dominant?.id ?? "none"}:${input.missionTargetStationId ?? "none"}:${Math.floor(input.nowMs / 60000)}`;
  const phaseOffset = (hashString(phaseOffsetSeed) % 3600) / 3600;

  return {
    budget,
    density,
    dominantStationId: dominant?.id ?? null,
    labelOcclusionOpacity,
    missionClearRadius,
    phaseOffset,
    style,
    tint:
      style === "receipt-drizzle" ? "#b88f4d" :
      style === "perimeter-gusts" ? "#9cb7ff" :
      style === "signal-haze" ? "#7ad7d0" :
      style === "judgment-lattice" ? "#b49cff" :
      style === "operations-surge" ? "#83d6a3" :
      style === "subject-swell" ? "#e5c07b" :
      "#b7d4ff",
  };
}
