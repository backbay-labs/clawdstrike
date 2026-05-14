import type { ConstellationRoute } from "../types";
import type { ObservatoryMissionLoopState } from "../world/missionLoop";
import type { HuntStationId } from "../world/types";

export function deriveConstellationFromMission(
  mission: ObservatoryMissionLoopState,
  nowMs: number = Date.now(),
): ConstellationRoute | null {
  if (mission.status !== "completed") return null;

  const stationPath: HuntStationId[] = [];
  for (const objId of mission.completedObjectiveIds) {
    const obj = mission.objectives.find((o) => o.id === objId);
    if (obj && !stationPath.includes(obj.stationId)) {
      stationPath.push(obj.stationId);
    }
  }

  return {
    id: `constellation-${mission.huntId}-${mission.completedAtMs ?? nowMs}`,
    name: `Hunt ${mission.huntId}`,
    createdAtMs: mission.completedAtMs ?? nowMs,
    stationPath,
    missionHuntId: mission.huntId,
  };
}

export interface SpiritResonanceConnection {
  from: HuntStationId;
  to: HuntStationId;
}

const RESONANCE_CONNECTIONS: SpiritResonanceConnection[] = [
  { from: "signal", to: "receipts" },
  { from: "targets", to: "case-notes" },
  { from: "run", to: "watch" },
];

export function deriveSpiritResonanceConnections(
  spiritLevel: number,
): SpiritResonanceConnection[] {
  if (spiritLevel < 5) return [];
  return RESONANCE_CONNECTIONS;
}

export interface HeatmapStationPressure {
  stationId: HuntStationId;
  pressure: number;
}

export function deriveHeatmapDataTexture(
  pressures: HeatmapStationPressure[],
  stationOrder: HuntStationId[],
): Float32Array {
  const result = new Float32Array(stationOrder.length);
  const maxPressure = pressures.reduce((max, p) => Math.max(max, p.pressure), 0);
  if (maxPressure === 0) return result;

  for (let i = 0; i < stationOrder.length; i++) {
    const entry = pressures.find((p) => p.stationId === stationOrder[i]);
    result[i] = entry ? entry.pressure / maxPressure : 0;
  }
  return result;
}
