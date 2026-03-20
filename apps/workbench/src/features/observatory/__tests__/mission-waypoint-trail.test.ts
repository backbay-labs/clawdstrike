// apps/workbench/src/features/observatory/__tests__/mission-waypoint-trail.test.ts
// Tests for shouldShowWaypointTrail gate logic and narrative lookup helpers.
import { describe, it, expect } from "vitest";
import { shouldShowWaypointTrail } from "../components/MissionWaypointTrail";
import { createObservatoryMissionLoopState } from "../world/missionLoop";
import type { ObservatoryMissionLoopState } from "../world/missionLoop";

describe("shouldShowWaypointTrail", () => {
  it("returns false when mission is null", () => {
    expect(shouldShowWaypointTrail(null, true)).toBe(false);
  });

  it("returns false when characterControllerEnabled is false", () => {
    const mission = createObservatoryMissionLoopState("test-hunt", 0);
    expect(shouldShowWaypointTrail(mission, false)).toBe(false);
  });

  it("returns false when mission.status is 'completed'", () => {
    const mission: ObservatoryMissionLoopState = {
      ...createObservatoryMissionLoopState("test-hunt", 0),
      status: "completed",
      completedAtMs: 100,
    };
    expect(shouldShowWaypointTrail(mission, true)).toBe(false);
  });

  it("returns false when mission is null and characterControllerEnabled is false", () => {
    expect(shouldShowWaypointTrail(null, false)).toBe(false);
  });

  it("returns true when mission is in-progress and characterControllerEnabled is true", () => {
    const mission = createObservatoryMissionLoopState("test-hunt", 0);
    expect(shouldShowWaypointTrail(mission, true)).toBe(true);
  });

  it("returns false when all objectives are completed (no current objective)", () => {
    const mission: ObservatoryMissionLoopState = {
      ...createObservatoryMissionLoopState("test-hunt", 0),
      status: "completed",
      completedAtMs: 200,
      completedObjectiveIds: [
        "acknowledge-horizon-ingress",
        "resolve-subject-cluster",
        "arm-operations-scan",
        "inspect-evidence-arrival",
        "seal-judgment-finding",
        "raise-watchfield-perimeter",
      ],
    };
    expect(shouldShowWaypointTrail(mission, true)).toBe(false);
  });
});
