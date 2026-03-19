import { describe, expect, it } from "vitest";
import {
  completeObservatoryMissionObjective,
  createObservatoryMissionLoopState,
  deriveObservatoryMissionBranch,
  getCurrentObservatoryMissionObjective,
  isObservatoryMissionObjectiveProp,
  resolveObservatoryMissionProbeTargetStationId,
} from "@/features/observatory/world/missionLoop";

describe("observatory mission loop", () => {
  it("starts at Horizon, adds Subjects, and follows the operations-first branch", () => {
    const mission = createObservatoryMissionLoopState("hunt-42", 100);

    expect(getCurrentObservatoryMissionObjective(mission)?.stationId).toBe("signal");
    expect(isObservatoryMissionObjectiveProp(mission, "signal-dish-tower")).toBe(true);
    expect(isObservatoryMissionObjectiveProp(mission, "subjects-lattice-anchor")).toBe(false);

    const afterHorizon = completeObservatoryMissionObjective(mission, "signal-dish-tower", 200);
    expect(afterHorizon.progress.acknowledgedIngress).toBe(true);
    expect(getCurrentObservatoryMissionObjective(afterHorizon)?.stationId).toBe("targets");

    const afterSubjects = completeObservatoryMissionObjective(
      afterHorizon,
      "subjects-lattice-anchor",
      300,
      { branchHint: "operations-first" },
    );
    expect(afterSubjects.progress.subjectsResolved).toBe(true);
    expect(afterSubjects.branch).toBe("operations-first");
    expect(getCurrentObservatoryMissionObjective(afterSubjects)?.stationId).toBe("run");

    const afterRun = completeObservatoryMissionObjective(afterSubjects, "operations-scan-rig", 400);
    expect(afterRun.progress.runArmed).toBe(true);
    expect(getCurrentObservatoryMissionObjective(afterRun)?.stationId).toBe("receipts");

    const afterEvidence = completeObservatoryMissionObjective(afterRun, "evidence-vault-rack", 500);
    expect(afterEvidence.progress.evidenceInspected).toBe(true);
    expect(getCurrentObservatoryMissionObjective(afterEvidence)?.stationId).toBe("case-notes");

    const complete = completeObservatoryMissionObjective(afterEvidence, "judgment-dais", 600);
    expect(complete.progress.findingSealed).toBe(true);
    expect(complete.status).toBe("completed");
    expect(complete.completedAtMs).toBe(600);
    expect(getCurrentObservatoryMissionObjective(complete)).toBeNull();
  });

  it("can branch to evidence before operations after Subjects", () => {
    const mission = createObservatoryMissionLoopState("hunt-42", 100);
    const afterHorizon = completeObservatoryMissionObjective(mission, "signal-dish-tower", 200);
    const afterSubjects = completeObservatoryMissionObjective(
      afterHorizon,
      "subjects-lattice-anchor",
      300,
      { branchHint: "evidence-first" },
    );

    expect(afterSubjects.branch).toBe("evidence-first");
    expect(getCurrentObservatoryMissionObjective(afterSubjects)?.stationId).toBe("receipts");

    const afterEvidence = completeObservatoryMissionObjective(afterSubjects, "evidence-vault-rack", 400);
    expect(getCurrentObservatoryMissionObjective(afterEvidence)?.stationId).toBe("run");
  });

  it("derives the evidence-first branch from live scene pressure", () => {
    expect(
      deriveObservatoryMissionBranch({
        huntId: "hunt-7",
        mode: "atlas",
        stations: [
          { id: "signal", label: "Horizon", status: "idle", affinity: 0.4, emphasis: 0.3, artifactCount: 1, hasUnread: true },
          { id: "targets", label: "Subjects", status: "idle", affinity: 0.5, emphasis: 0.5, artifactCount: 2, hasUnread: false },
          { id: "run", label: "Operations", status: "idle", affinity: 0.52, emphasis: 0.48, artifactCount: 1, hasUnread: false },
          { id: "receipts", label: "Evidence", status: "receiving", affinity: 0.78, emphasis: 0.74, artifactCount: 4, hasUnread: true },
          { id: "case-notes", label: "Judgment", status: "idle", affinity: 0.22, emphasis: 0.2, artifactCount: 0, hasUnread: false },
          { id: "watch", label: "Watchfield", status: "idle", affinity: 0.18, emphasis: 0.16, artifactCount: 0, hasUnread: false },
        ],
        activeSelection: { type: "station", stationId: "receipts" },
        likelyStationId: "receipts",
        roomReceiveState: "receiving",
        spiritFieldBias: 0.6,
        confidence: 0.82,
        cameraPreset: "focus-station",
        openedDetailSurface: "none",
      }),
    ).toBe("evidence-first");
  });

  it("ignores out-of-order prop activations", () => {
    const mission = createObservatoryMissionLoopState("hunt-42", 100);
    const unchanged = completeObservatoryMissionObjective(mission, "judgment-dais", 200);
    expect(unchanged).toEqual(mission);
  });

  it("targets the current mission objective for operator probes before fallback stations", () => {
    const mission = createObservatoryMissionLoopState("hunt-42", 100);

    expect(
      resolveObservatoryMissionProbeTargetStationId(mission, {
        activeStationId: "watch",
        likelyStationId: "run",
      }),
    ).toBe("signal");

    const afterHorizon = completeObservatoryMissionObjective(mission, "signal-dish-tower", 200);
    expect(
      resolveObservatoryMissionProbeTargetStationId(afterHorizon, {
        activeStationId: "watch",
        likelyStationId: "run",
      }),
    ).toBe("targets");
  });

  it("falls back to active or likely stations when there is no current objective", () => {
    expect(
      resolveObservatoryMissionProbeTargetStationId(null, {
        activeStationId: "watch",
        likelyStationId: "run",
      }),
    ).toBe("watch");

    expect(
      resolveObservatoryMissionProbeTargetStationId(null, {
        activeStationId: null,
        likelyStationId: "run",
      }),
    ).toBe("run");
  });
});
