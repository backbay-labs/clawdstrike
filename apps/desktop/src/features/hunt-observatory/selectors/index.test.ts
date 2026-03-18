import { describe, expect, it } from "vitest";
import type { HuntSpiritSignalSnapshot } from "@/shell/workbench/spirit/selectors";
import {
  deriveHuntObservatoryLikelyStationId,
  deriveHuntObservatorySceneState,
  deriveHuntObservatoryStationStates,
} from "./index";

function makeSnapshot(
  overrides: Partial<HuntSpiritSignalSnapshot> = {},
): HuntSpiritSignalSnapshot {
  return {
    huntId: "hunt-1",
    huntTitle: "Ghostline",
    currentShell: "hunt",
    currentLens: "entities",
    activeRunId: null,
    activeCaseId: null,
    draggedObjectKind: null,
    likelyIntent: "attach-target",
    phase: "investigation",
    phaseScore: 0.72,
    confidenceScore: 74,
    totalArtifacts: 4,
    totalRuns: 1,
    runningRunCount: 0,
    artifactCounts: {
      entity: 2,
      signal: 1,
      file: 1,
    },
    semanticCounts: {
      target: 2,
      watch: 1,
    },
    dominantArtifactKinds: ["entity", "signal", "file"],
    dominantSemantics: ["target", "watch"],
    suggestedAnchorArtifactIds: ["artifact-1"],
    boundSpirit: null,
    ...overrides,
  };
}

describe("deriveHuntObservatoryLikelyStationId", () => {
  it("prioritizes receipts for evidence-led hunts", () => {
    const snapshot = makeSnapshot({
      likelyIntent: "attach-evidence",
      artifactCounts: { receipt: 2, evidence: 1 },
      semanticCounts: { evidence: 2 },
      currentLens: "notes",
    });

    expect(deriveHuntObservatoryLikelyStationId(snapshot)).toBe("receipts");
  });

  it("prioritizes case-notes during reporting posture", () => {
    const snapshot = makeSnapshot({
      likelyIntent: "cite",
      phase: "reporting",
      currentLens: "notes",
      activeCaseId: "case-1",
      artifactCounts: { note: 2, receipt: 1 },
      semanticCounts: { cite: 1, notes: 2 },
    });

    expect(deriveHuntObservatoryLikelyStationId(snapshot)).toBe("case-notes");
  });
});

describe("deriveHuntObservatoryStationStates", () => {
  it("marks the likely station as warming and active station as active", () => {
    const stations = deriveHuntObservatoryStationStates(makeSnapshot(), {
      activeStationId: "signal",
      roomReceiveState: "idle",
    });

    const signal = stations.find((station) => station.id === "signal");
    const targets = stations.find((station) => station.id === "targets");
    expect(signal?.status).toBe("active");
    expect(targets?.status).toBe("warming");
    expect(targets?.affinity).toBeGreaterThan(0.8);
  });
});

describe("deriveHuntObservatorySceneState", () => {
  it("derives a coherent flow scene state from the spirit snapshot", () => {
    const sceneState = deriveHuntObservatorySceneState(
      makeSnapshot({
        likelyIntent: "run-input",
        boundSpirit: {
          kind: "tracker",
          thesis: null,
          anchorArtifactIds: [],
          bindSource: "default-create",
          bindReason: "Signal-first pressure.",
          isPinned: false,
          liveMood: "attuned",
          version: 1,
          confidenceScore: 74,
          boundAt: 1_000,
          reboundAt: null,
        },
        runningRunCount: 1,
        artifactCounts: { entity: 2, signal: 1, file: 2 },
        semanticCounts: { target: 2, "run-input": 1 },
      }),
      {
        activeStationId: "run",
        roomReceiveState: "receiving",
      },
    );

    expect(sceneState.mode).toBe("flow");
    expect(sceneState.likelyStationId).toBe("run");
    expect(sceneState.cameraPreset).toBe("follow-run");
    expect(sceneState.roomReceiveState).toBe("receiving");
    expect(sceneState.spiritFieldBias).toBeGreaterThan(0.6);
  });
});
