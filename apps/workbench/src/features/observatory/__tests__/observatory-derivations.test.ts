import { describe, expect, it } from "vitest";
import {
  deriveConstellationFromMission,
  deriveHeatmapDataTexture,
  deriveSpiritResonanceConnections,
} from "@/features/observatory/utils/observatory-derivations";
import type { ObservatoryMissionLoopState } from "@/features/observatory/world/missionLoop";
import { HUNT_STATION_ORDER } from "@/features/observatory/world/stations";

function makeCompletedMission(overrides?: Partial<ObservatoryMissionLoopState>): ObservatoryMissionLoopState {
  return {
    huntId: "hunt-alpha",
    startedAtMs: 1000,
    completedAtMs: 5000,
    status: "completed",
    branch: "operations-first",
    briefing: "Test mission",
    completedObjectiveIds: [
      "acknowledge-horizon-ingress",
      "resolve-subject-cluster",
      "arm-operations-scan",
    ],
    objectives: [
      { id: "acknowledge-horizon-ingress", stationId: "signal", assetId: "signal-dish-tower", title: "t", actionLabel: "a", hint: "h", completionRead: "c" },
      { id: "resolve-subject-cluster", stationId: "targets", assetId: "subjects-lattice-anchor", title: "t", actionLabel: "a", hint: "h", completionRead: "c" },
      { id: "arm-operations-scan", stationId: "run", assetId: "operations-scan-rig", title: "t", actionLabel: "a", hint: "h", completionRead: "c" },
    ],
    progress: {
      acknowledgedIngress: true,
      subjectsResolved: true,
      runArmed: true,
      evidenceInspected: false,
      findingSealed: false,
      watchfieldRaised: false,
    },
    ...overrides,
  };
}

describe("deriveConstellationFromMission", () => {
  it("derives a ConstellationRoute from a completed mission", () => {
    const mission = makeCompletedMission();
    const result = deriveConstellationFromMission(mission);
    expect(result).not.toBeNull();
    expect(result!.stationPath).toEqual(["signal", "targets", "run"]);
    expect(result!.missionHuntId).toBe("hunt-alpha");
    expect(result!.name).toBe("Hunt hunt-alpha");
    expect(result!.createdAtMs).toBe(5000);
  });

  it("returns null for an in-progress mission", () => {
    const mission = makeCompletedMission({ status: "in-progress", completedAtMs: null });
    expect(deriveConstellationFromMission(mission)).toBeNull();
  });

  it("generates a deterministic id from huntId and completedAtMs", () => {
    const mission = makeCompletedMission();
    const result = deriveConstellationFromMission(mission);
    expect(result!.id).toBe("constellation-hunt-alpha-5000");
  });
});

describe("deriveSpiritResonanceConnections", () => {
  it("returns empty array when spirit level is below 5", () => {
    expect(deriveSpiritResonanceConnections(1)).toEqual([]);
    expect(deriveSpiritResonanceConnections(4)).toEqual([]);
  });

  it("returns resonance connections at level 5", () => {
    const connections = deriveSpiritResonanceConnections(5);
    expect(connections.length).toBeGreaterThanOrEqual(3);
    for (const conn of connections) {
      expect(typeof conn.from).toBe("string");
      expect(typeof conn.to).toBe("string");
    }
  });

  it("includes cross-ring station pairs", () => {
    const connections = deriveSpiritResonanceConnections(5);
    const pairs = connections.map((c) => `${c.from}-${c.to}`);
    expect(pairs).toContain("signal-receipts");
    expect(pairs).toContain("targets-case-notes");
    expect(pairs).toContain("run-watch");
  });
});

describe("deriveHeatmapDataTexture", () => {
  it("returns a Float32Array of length matching station order", () => {
    const result = deriveHeatmapDataTexture([], HUNT_STATION_ORDER);
    expect(result).toBeInstanceOf(Float32Array);
    expect(result.length).toBe(6);
  });

  it("normalizes pressure values to 0-1 range", () => {
    const pressures = [
      { stationId: "signal" as const, pressure: 50 },
      { stationId: "targets" as const, pressure: 100 },
      { stationId: "run" as const, pressure: 25 },
    ];
    const result = deriveHeatmapDataTexture(pressures, HUNT_STATION_ORDER);
    expect(result[0]).toBeCloseTo(0.5); // signal: 50/100
    expect(result[1]).toBeCloseTo(1.0); // targets: 100/100
    expect(result[2]).toBeCloseTo(0.25); // run: 25/100
    expect(result[3]).toBeCloseTo(0); // receipts: not in input
  });

  it("returns all zeros when all pressures are zero", () => {
    const pressures = [
      { stationId: "signal" as const, pressure: 0 },
      { stationId: "targets" as const, pressure: 0 },
    ];
    const result = deriveHeatmapDataTexture(pressures, HUNT_STATION_ORDER);
    for (let i = 0; i < result.length; i++) {
      expect(result[i]).toBe(0);
    }
  });
});
