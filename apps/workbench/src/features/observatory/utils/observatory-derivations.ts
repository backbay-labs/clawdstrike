import type { ConstellationRoute } from "../types";
import type { ObservatoryMissionLoopState } from "../world/missionLoop";
import type { HuntStationId } from "../world/types";

/**
 * Derives a ConstellationRoute from a completed mission.
 * Returns null if the mission is not completed.
 */
export function deriveConstellationFromMission(
  mission: ObservatoryMissionLoopState,
  nowMs: number = Date.now(),
): ConstellationRoute | null {
  if (mission.status !== "completed") return null;

  // Build station path from completed objectives in completion order
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

/**
 * Hidden resonance connections revealed at spirit level 5.
 * Returns pairs of station IDs that are not adjacent in the normal transit ring.
 * These are cross-ring connections that only appear when the spirit reaches max level.
 */
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

/**
 * Derives a flat Float32Array of normalized pressure values per station.
 * Index corresponds to the provided stationOrder array position.
 * Used by the ThreatTopologyHeatmap in Phase 40 to drive a color-ramp shader.
 */
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
  if (maxPressure === 0) return result; // all zeros

  for (let i = 0; i < stationOrder.length; i++) {
    const entry = pressures.find((p) => p.stationId === stationOrder[i]);
    result[i] = entry ? entry.pressure / maxPressure : 0;
  }
  return result;
}
