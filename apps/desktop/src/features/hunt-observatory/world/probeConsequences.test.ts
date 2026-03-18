import { describe, expect, it } from "vitest";
import { deriveObservatoryWorld } from "./deriveObservatoryWorld";
import {
  applyObservatoryProbeConsequences,
} from "./probeConsequences";
import {
  completeObservatoryMissionObjective,
  createObservatoryMissionLoopState,
} from "./missionLoop";
import {
  advanceObservatoryProbeState,
  createInitialObservatoryProbeState,
  dispatchObservatoryProbe,
  OBSERVATORY_PROBE_ACTIVE_MS,
} from "./probeRuntime";

function createBaseWorld() {
  return deriveObservatoryWorld({
    mode: "atlas",
    activeStationId: "run",
    spirit: {
      kind: "tracker",
      accentColor: "#88d4ff",
      likelyStationId: "run",
      cueKind: "focus",
    },
    sceneState: {
      huntId: "hunt-1",
      mode: "atlas",
      stations: [
        {
          id: "signal",
          label: "Horizon",
          status: "idle",
          affinity: 0.42,
          emphasis: 0.38,
          artifactCount: 1,
          hasUnread: true,
        },
        {
          id: "targets",
          label: "Subjects",
          status: "active",
          affinity: 0.74,
          emphasis: 0.66,
          artifactCount: 3,
          hasUnread: true,
        },
        {
          id: "run",
          label: "Operations",
          status: "active",
          affinity: 0.91,
          emphasis: 1,
          artifactCount: 4,
          hasUnread: false,
        },
        {
          id: "receipts",
          label: "Evidence",
          status: "warming",
          affinity: 0.62,
          emphasis: 0.52,
          artifactCount: 2,
          hasUnread: true,
        },
        {
          id: "case-notes",
          label: "Judgment",
          status: "idle",
          affinity: 0.26,
          emphasis: 0.24,
          artifactCount: 0,
          hasUnread: false,
        },
      ],
      activeSelection: { type: "station", stationId: "run" },
      likelyStationId: "run",
      roomReceiveState: "receiving",
      spiritFieldBias: 0.7,
      confidence: 0.82,
      cameraPreset: "follow-run",
      openedDetailSurface: "none",
    },
  });
}

function createRunObjectiveMission() {
  const mission = createObservatoryMissionLoopState("hunt-42", 100);
  const afterHorizon = completeObservatoryMissionObjective(mission, "signal-dish-tower", 200);
  return completeObservatoryMissionObjective(
    afterHorizon,
    "subjects-lattice-anchor",
    300,
    { branchHint: "operations-first" },
  );
}

describe("observatory probe consequences", () => {
  it("retasks the current objective district and crew while the probe is active", () => {
    const baseWorld = createBaseWorld();
    const mission = createRunObjectiveMission();
    const activeProbe = dispatchObservatoryProbe(
      createInitialObservatoryProbeState(),
      "run",
      0,
    );

    const result = applyObservatoryProbeConsequences(baseWorld, activeProbe, mission);
    const runDistrict = result.world.districts.find((district) => district.id === "run");
    const baseRunRoute = baseWorld.transitLinks.find((route) => route.stationId === "run");
    const runRoute = result.world.transitLinks.find((route) => route.stationId === "run");

    expect(result.directive?.stationId).toBe("run");
    expect(result.directive?.state).toBe("surveying");
    expect(result.directive?.missionRead).toContain("Mission assist at Operations");
    expect(runDistrict?.probeReaction?.state).toBe("surveying");
    expect(runDistrict?.probeReaction?.crewDirective).toContain("Technicians");
    expect(runDistrict?.localRead).toContain("Mission assist at Operations");
    expect(runDistrict?.crew[0]?.response?.utilityVisible).toBe(true);
    expect(runDistrict?.crew[0]?.response?.paceMultiplier).toBeGreaterThan(1.5);
    expect(runRoute?.showPulse).toBe(true);
    expect(runRoute?.convoyCount).toBeGreaterThan(baseRunRoute?.convoyCount ?? 0);
    expect(runRoute?.intensity).toBeGreaterThan(baseRunRoute?.intensity ?? 0);
  });

  it("keeps the district stabilized during cooldown", () => {
    const baseWorld = createBaseWorld();
    const mission = createRunObjectiveMission();
    const activeProbe = dispatchObservatoryProbe(
      createInitialObservatoryProbeState(),
      "run",
      0,
    );
    const coolingProbe = advanceObservatoryProbeState(
      activeProbe,
      OBSERVATORY_PROBE_ACTIVE_MS + 20,
    );

    const result = applyObservatoryProbeConsequences(baseWorld, coolingProbe, mission);
    const runDistrict = result.world.districts.find((district) => district.id === "run");

    expect(result.directive?.state).toBe("stabilizing");
    expect(result.directive?.missionRead).toContain("recharges");
    expect(runDistrict?.probeReaction?.state).toBe("stabilizing");
    expect(runDistrict?.crew[0]?.response?.paceMultiplier).toBeLessThan(1.4);
  });

  it("leaves the world untouched when the probe is ready", () => {
    const baseWorld = createBaseWorld();
    const result = applyObservatoryProbeConsequences(
      baseWorld,
      createInitialObservatoryProbeState(),
      createRunObjectiveMission(),
    );

    expect(result.directive).toBeNull();
    expect(result.world).toBe(baseWorld);
  });
});
