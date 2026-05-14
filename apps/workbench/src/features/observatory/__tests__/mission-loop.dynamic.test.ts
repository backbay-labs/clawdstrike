import { describe, expect, it } from "vitest";
import {
  createObservatoryMissionLoopState,
  createObservatoryMissionPlan,
  deriveObservatoryMissionBranch,
} from "@/features/observatory/world/missionLoop";
import type { HuntObservatorySceneState } from "@/features/observatory/world/types";
import type { Investigation, HuntPattern } from "@/lib/workbench/hunt-types";

function makeSceneState(): HuntObservatorySceneState {
  return {
    huntId: "hunt-live",
    mode: "atlas",
    activeSelection: { type: "none" },
    cameraPreset: "overview",
    confidence: 0.82,
    likelyStationId: "receipts",
    openedDetailSurface: "none",
    roomReceiveState: "receiving",
    spiritFieldBias: 0.5,
    stations: [
      {
        id: "signal",
        label: "Horizon",
        status: "warming",
        affinity: 0.28,
        emphasis: 0.31,
        artifactCount: 1,
        hasUnread: true,
      },
      {
        id: "targets",
        label: "Subjects",
        status: "warming",
        affinity: 0.32,
        emphasis: 0.34,
        artifactCount: 1,
        hasUnread: true,
      },
      {
        id: "run",
        label: "Operations",
        status: "active",
        affinity: 0.48,
        emphasis: 0.55,
        artifactCount: 2,
        hasUnread: true,
        reason: "Operations is carrying the current load.",
      },
      {
        id: "receipts",
        label: "Evidence",
        status: "receiving",
        affinity: 0.78,
        emphasis: 0.88,
        artifactCount: 4,
        hasUnread: true,
        reason: "Evidence arrivals are stacking faster than operators can process them.",
      },
      {
        id: "case-notes",
        label: "Judgment",
        status: "warming",
        affinity: 0.46,
        emphasis: 0.52,
        artifactCount: 2,
        hasUnread: true,
      },
      {
        id: "watch",
        label: "Watchfield",
        status: "active",
        affinity: 0.4,
        emphasis: 0.62,
        artifactCount: 1,
        hasUnread: true,
        reason: "Outer patrol anomalies are keeping the watchfield awake.",
      },
    ],
  };
}

describe("dynamic mission loop planning", () => {
  it("switches to evidence-first when receipts outrun operations", () => {
    const sceneState = makeSceneState();
    const investigations: Investigation[] = [
      {
        id: "inv-1",
        title: "Judgment drift",
        status: "open",
        severity: "high",
        createdAt: "2026-03-19T13:00:00.000Z",
        updatedAt: "2026-03-19T15:30:00.000Z",
        createdBy: "operator",
        agentIds: ["agent-1"],
        sessionIds: ["session-1"],
        timeRange: {
          start: "2026-03-19T13:00:00.000Z",
          end: "2026-03-19T16:00:00.000Z",
        },
        eventIds: ["event-1"],
        annotations: [],
        verdict: "policy-gap",
      },
      {
        id: "inv-2",
        title: "Watchfield drift",
        status: "in-progress",
        severity: "medium",
        createdAt: "2026-03-19T12:00:00.000Z",
        updatedAt: "2026-03-19T15:45:00.000Z",
        createdBy: "operator",
        agentIds: ["agent-2"],
        sessionIds: ["session-2"],
        timeRange: {
          start: "2026-03-19T12:00:00.000Z",
          end: "2026-03-19T16:00:00.000Z",
        },
        eventIds: ["event-2"],
        annotations: [],
      },
    ];
    const patterns: HuntPattern[] = [
      {
        id: "pattern-1",
        name: "Receipt surge",
        description: "Evidence pressure is elevated",
        discoveredAt: "2026-03-19T14:30:00.000Z",
        status: "confirmed",
        sequence: [],
        matchCount: 2,
        exampleSessionIds: ["session-1"],
        agentIds: ["agent-1"],
      },
    ];

    expect(deriveObservatoryMissionBranch(sceneState)).toBe("evidence-first");

    const plan = createObservatoryMissionPlan({
      investigations,
      patterns,
      sceneState,
    });

    expect(plan.objectives.map((objective) => objective.id)).toEqual([
      "acknowledge-horizon-ingress",
      "resolve-subject-cluster",
      "inspect-evidence-arrival",
      "arm-operations-scan",
      "raise-watchfield-perimeter",
      "seal-judgment-finding",
    ]);
    expect(plan.briefing).toContain("Evidence is outrunning Operations");
    expect(plan.briefing).toContain("Watchfield pressure is high enough");
  });

  it("stores the dynamic objective sequence in the mission loop state", () => {
    const plan = createObservatoryMissionPlan({
      sceneState: makeSceneState(),
      investigations: [],
      patterns: [],
    });

    const mission = createObservatoryMissionLoopState("hunt-live", 1234, {
      branchHint: "evidence-first",
      plan,
    });

    expect(mission.branch).toBe("evidence-first");
    expect(mission.briefing).toBe(plan.briefing);
    expect(mission.objectives).toEqual(plan.objectives);
    expect(mission.completedObjectiveIds).toEqual([]);
  });
});
