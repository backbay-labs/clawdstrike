import { describe, expect, it } from "vitest";
import {
  createHuntSpiritState,
  deriveHuntSpiritRuntimeState,
  type HuntSpiritSignalSnapshot,
} from "@/shell/workbench/spirit";
import { deriveHuntSpiritSceneActor, detectHuntSpiritSceneCue } from "./runtime";

function makeSnapshot(overrides: Partial<HuntSpiritSignalSnapshot> = {}): HuntSpiritSignalSnapshot {
  return {
    huntId: "hunt-1",
    huntTitle: "Ghostline",
    currentShell: "hunt",
    currentLens: "entities",
    activeRunId: null,
    activeCaseId: null,
    draggedObjectKind: null,
    likelyIntent: "watch",
    phase: "investigation",
    phaseScore: 72,
    confidenceScore: 78,
    totalArtifacts: 3,
    totalRuns: 1,
    runningRunCount: 0,
    artifactCounts: {
      receipt: 1,
      evidence: 0,
      file: 1,
    },
    semanticCounts: {
      watch: 1,
    },
    dominantArtifactKinds: ["receipt", "file"],
    dominantSemantics: ["watch"],
    suggestedAnchorArtifactIds: ["artifact-1"],
    boundSpirit: createHuntSpiritState({
      kind: "lantern",
      bindSource: "quick-bind",
      bindReason: "Receipt-led inquiry.",
      confidenceScore: 78,
      boundAt: 1_000,
    }),
    ...overrides,
  };
}

describe("detectHuntSpiritSceneCue", () => {
  it("emits a bind cue for a newly bound spirit", () => {
    const snapshot = makeSnapshot();
    const runtime = deriveHuntSpiritRuntimeState(snapshot.boundSpirit, {
      currentShell: snapshot.currentShell,
      currentLens: snapshot.currentLens,
      likelyIntent: snapshot.likelyIntent,
      confidenceScore: snapshot.confidenceScore,
      activeStationId: "security-overview",
    });

    const cue = detectHuntSpiritSceneCue({
      runtime,
      snapshot,
      previousSnapshot: null,
      activeStationId: "security-overview",
      previousActiveStationId: null,
      nowMs: 2_000,
    });

    expect(cue?.kind).toBe("bind");
  });

  it("witnesses newly attached receipts before falling back to focus", () => {
    const previousSnapshot = makeSnapshot({
      boundSpirit: createHuntSpiritState({
        kind: "lantern",
        bindSource: "quick-bind",
        bindReason: "Receipt-led inquiry.",
        confidenceScore: 78,
        boundAt: 1_000,
      }),
    });
    const snapshot = makeSnapshot({
      artifactCounts: {
        receipt: 2,
        evidence: 1,
        file: 1,
      },
      totalArtifacts: 4,
    });
    const runtime = deriveHuntSpiritRuntimeState(snapshot.boundSpirit, {
      currentShell: snapshot.currentShell,
      currentLens: snapshot.currentLens,
      likelyIntent: "cite",
      confidenceScore: snapshot.confidenceScore,
      activeStationId: "security-overview",
    });

    const cue = detectHuntSpiritSceneCue({
      runtime,
      snapshot,
      previousSnapshot,
      activeStationId: "security-overview",
      previousActiveStationId: "security-overview",
      nowMs: 8_000,
    });

    expect(cue?.kind).toBe("witness");
  });
});

describe("deriveHuntSpiritSceneActor", () => {
  it("builds a distinct forensics actor from the existing spirit runtime", () => {
    const snapshot = makeSnapshot();
    const runtime = deriveHuntSpiritRuntimeState(snapshot.boundSpirit, {
      currentShell: snapshot.currentShell,
      currentLens: snapshot.currentLens,
      likelyIntent: snapshot.likelyIntent,
      confidenceScore: snapshot.confidenceScore,
      activeStationId: "threat-radar",
    });

    const actor = deriveHuntSpiritSceneActor({
      runtime,
      snapshot,
      activeStationId: "threat-radar",
      cue: null,
    });

    expect(actor).not.toBeNull();
    expect(actor?.huntId).toBe("hunt-1");
    expect(actor?.label).toBe("Lantern");
    expect(actor?.laneBias).toBeGreaterThan(0);
    expect(actor?.presenceStrength).toBeGreaterThan(0.3);
  });
});
