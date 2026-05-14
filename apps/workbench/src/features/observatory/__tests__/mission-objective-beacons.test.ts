import { describe, expect, it } from "vitest";
import type { ObservatoryMissionLoopState } from "../world/missionLoop";
import { shouldShowBeacons, getBeaconStations } from "../components/MissionObjectiveBeacons";

function makeMission(
  completedIds: string[],
  objectiveStations: string[],
): ObservatoryMissionLoopState {
  return {
    huntId: "test",
    startedAtMs: 0,
    completedAtMs: null,
    status: "in-progress",
    branch: null,
    briefing: "",
    completedObjectiveIds: completedIds as any,
    objectives: objectiveStations.map((stationId, i) => ({
      id: `obj-${i}` as any,
      stationId: stationId as any,
      assetId: "loot-cache" as any,
      title: "",
      actionLabel: "",
      hint: "",
      completionRead: "",
    })),
    progress: {
      acknowledgedIngress: false,
      subjectsResolved: false,
      runArmed: false,
      evidenceInspected: false,
      findingSealed: false,
      watchfieldRaised: false,
    },
  };
}

describe("MissionObjectiveBeacons helpers", () => {
  it("shouldShowBeacons returns false for null mission", () => {
    expect(shouldShowBeacons(null)).toBe(false);
  });

  it("shouldShowBeacons returns true when mission has objectives", () => {
    expect(shouldShowBeacons(makeMission([], ["signal"]))).toBe(true);
  });

  it("shouldShowBeacons returns true for completed mission (static desaturated glow)", () => {
    const completed = { ...makeMission([], ["signal"]), status: "completed" as const };
    expect(shouldShowBeacons(completed)).toBe(true);
  });

  it("getBeaconStations: first objective is active, second is inactive when no completions", () => {
    const stations = getBeaconStations(makeMission([], ["signal", "targets"]));
    expect(stations).toEqual([
      { stationId: "signal", isActive: true, isCompleted: false },
      { stationId: "targets", isActive: false, isCompleted: false },
    ]);
  });

  it("getBeaconStations: completed objective is marked isCompleted, next is active", () => {
    // obj-0 maps to "signal", obj-1 maps to "targets"
    const stations = getBeaconStations(makeMission(["obj-0"], ["signal", "targets"]));
    const signalEntry = stations.find((s) => s.stationId === "signal");
    const targetsEntry = stations.find((s) => s.stationId === "targets");
    expect(signalEntry).toEqual({ stationId: "signal", isActive: false, isCompleted: true });
    expect(targetsEntry).toEqual({ stationId: "targets", isActive: true, isCompleted: false });
  });

  it("getBeaconStations: all completed means all isCompleted=true, none isActive", () => {
    const stations = getBeaconStations(makeMission(["obj-0", "obj-1"], ["signal", "targets"]));
    expect(stations.every((s) => s.isCompleted)).toBe(true);
    expect(stations.every((s) => !s.isActive)).toBe(true);
  });
});
