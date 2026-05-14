import { describe, expect, it } from "vitest";
import {
  createObservatoryMissionPlan,
  deriveObservatoryMissionBranch,
} from "@/features/observatory/world/missionLoop";
import type { HuntObservatorySceneState } from "@/features/observatory/world/types";
import type { Investigation, HuntPattern } from "@/lib/workbench/hunt-types";

function makeSceneState(overrides: Partial<HuntObservatorySceneState["stations"][number]>[] = []): HuntObservatorySceneState {
  const stations: HuntObservatorySceneState["stations"] = [
    {
      id: "signal",
      label: "Horizon",
      status: "active",
      affinity: 0.62,
      emphasis: 0.68,
      artifactCount: 2,
      hasUnread: true,
      reason: "Ingress traffic is widening across Horizon.",
    },
    {
      id: "targets",
      label: "Subjects",
      status: "warming",
      affinity: 0.58,
      emphasis: 0.6,
      artifactCount: 2,
      hasUnread: true,
      reason: "Subjects are clustering around the ingress path.",
    },
    {
      id: "run",
      label: "Operations",
      status: "active",
      affinity: 0.7,
      emphasis: 0.78,
      artifactCount: 4,
      hasUnread: true,
      reason: "Operations is carrying a heavy execution load.",
    },
    {
      id: "receipts",
      label: "Evidence",
      status: "receiving",
      affinity: 0.84,
      emphasis: 0.9,
      artifactCount: 5,
      hasUnread: true,
      reason: "Evidence receipts are stacking faster than the archive can settle them.",
    },
    {
      id: "case-notes",
      label: "Judgment",
      status: "warming",
      affinity: 0.47,
      emphasis: 0.52,
      artifactCount: 1,
      hasUnread: true,
      reason: "Judgment is holding an authored finding open.",
    },
    {
      id: "watch",
      label: "Watchfield",
      status: "active",
      affinity: 0.62,
      emphasis: 0.66,
      artifactCount: 3,
      hasUnread: true,
      reason: "Watchfield pressure is keeping the perimeter awake.",
    },
  ];

  if (overrides.length > 0) {
    overrides.forEach((override) => {
      const idx = stations.findIndex((station) => station.id === override.id);
      if (idx >= 0) {
        stations[idx] = { ...stations[idx], ...override };
      }
    });
  }

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
    stations,
  };
}

describe("compound mission planning", () => {
  it("builds run+receipts compound context when evidence pressure is outrunning execution", () => {
    const plan = createObservatoryMissionPlan({
      investigations: [
        {
          id: "inv-1",
          title: "Receipt drift",
          status: "open",
          severity: "high",
          createdAt: "2026-03-19T15:00:00.000Z",
          updatedAt: "2026-03-19T15:30:00.000Z",
          createdBy: "operator",
          agentIds: ["agent-receipts"],
          sessionIds: ["session-receipts"],
          timeRange: {
            start: "2026-03-19T14:30:00.000Z",
            end: "2026-03-19T16:00:00.000Z",
          },
          eventIds: ["receipt-1"],
          annotations: [],
          verdict: "policy-gap",
        },
      ] satisfies Investigation[],
      patterns: [
        {
          id: "pattern-1",
          name: "Receipt surge",
          description: "Evidence pressure is elevated",
          discoveredAt: "2026-03-19T15:20:00.000Z",
          status: "confirmed",
          sequence: [],
          matchCount: 2,
          exampleSessionIds: ["session-receipts"],
          agentIds: ["agent-receipts"],
        },
      ] satisfies HuntPattern[],
      sceneState: makeSceneState(),
    });

    const objective = plan.objectives.find((entry) => entry.id === "inspect-evidence-arrival");

    expect(deriveObservatoryMissionBranch(makeSceneState())).toBe("evidence-first");
    expect(objective?.supportingStationIds).toEqual(["run", "signal"]);
    expect(objective?.rationale).toContain("Evidence");
    expect(objective?.rationale).toContain("Operations");
    expect(objective?.confidence).toBeGreaterThan(0.5);
    expect(plan.briefing).toContain("Compound recommendation");
  });

  it("builds signal+targets compound context when ingress pressure and subject clustering rise together", () => {
    const plan = createObservatoryMissionPlan({
      sceneState: makeSceneState([
        {
          id: "signal",
          status: "receiving",
          emphasis: 0.84,
          artifactCount: 4,
          reason: "Horizon ingress is widening across the live fleet.",
        },
        {
          id: "targets",
          status: "active",
          emphasis: 0.76,
          artifactCount: 3,
          reason: "Subjects are triangulating around the live ingress.",
        },
      ]),
    });

    const objective = plan.objectives.find((entry) => entry.id === "resolve-subject-cluster");

    expect(objective?.supportingStationIds).toEqual(["signal", "receipts"]);
    expect(objective?.rationale).toContain("Subjects");
    expect(objective?.rationale).toContain("Horizon");
    expect(objective?.rationale).toContain("Evidence");
    expect(objective?.confidence).toBeGreaterThan(0.5);
  });

  it("preserves the legacy sequence and avoids compound metadata when the scene is quiet", () => {
    const plan = createObservatoryMissionPlan({ sceneState: null });

    expect(plan.objectives.map((objective) => objective.id)).toEqual([
      "acknowledge-horizon-ingress",
      "resolve-subject-cluster",
      "arm-operations-scan",
      "inspect-evidence-arrival",
      "seal-judgment-finding",
    ]);
    expect(plan.objectives.every((objective) => !objective.supportingStationIds?.length)).toBe(true);
    expect(plan.objectives.every((objective) => objective.rationale == null)).toBe(true);
  });
});
