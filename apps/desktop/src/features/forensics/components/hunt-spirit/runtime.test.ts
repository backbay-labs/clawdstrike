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
      bindSource: "quick-configure",
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
        bindSource: "quick-configure",
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

  it("does not keep re-emitting focus while the stance is already focused", () => {
    const snapshot = makeSnapshot();
    const runtime = deriveHuntSpiritRuntimeState(snapshot.boundSpirit, {
      currentShell: snapshot.currentShell,
      currentLens: snapshot.currentLens,
      likelyIntent: "watch",
      confidenceScore: snapshot.confidenceScore,
      activeStationId: "security-overview",
    });

    const cue = detectHuntSpiritSceneCue({
      runtime,
      previousRuntime: runtime,
      snapshot,
      previousSnapshot: snapshot,
      activeStationId: "security-overview",
      previousActiveStationId: "security-overview",
      nowMs: 10_000,
    });

    expect(cue).toBeNull();
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
    if (!actor) throw new Error("expected scene actor");
    expect(actor.huntId).toBe("hunt-1");
    expect(actor.label).toBe("Lantern");
    expect(actor.laneBias).toBeGreaterThan(0);
    expect(actor.presenceStrength).toBeGreaterThan(0.3);
    expect(actor.observatoryActiveStationId).toBe("watch");
    expect(actor.observatoryLikelyStationId).toBe("watch");
    expect(actor.observatoryActor).toBeDefined();
    if (!actor.observatoryActor) throw new Error("expected observatory actor");
    expect(actor.observatoryActor.type).toBe("spirit-field");
    expect(actor.observatoryActor.stance).toBe("focus");
    expect(actor.observatoryActor.cueKind).toBeNull();
  });

  it("derives observatory receipt posture from evidence-led intent", () => {
    const snapshot = makeSnapshot({
      likelyIntent: "attach-evidence",
      artifactCounts: {
        receipt: 2,
        evidence: 1,
        file: 0,
      },
      semanticCounts: {
        evidence: 1,
      },
    });
    const runtime = deriveHuntSpiritRuntimeState(snapshot.boundSpirit, {
      currentShell: snapshot.currentShell,
      currentLens: "notes",
      likelyIntent: snapshot.likelyIntent,
      confidenceScore: snapshot.confidenceScore,
      activeStationId: "security-overview",
    });

    const actor = deriveHuntSpiritSceneActor({
      runtime,
      snapshot,
      activeStationId: "security-overview",
      cue: {
        kind: "witness",
        reason: "Witnessing new proof.",
        durationMs: 2_800,
        startedAt: 5_000,
        expiresAt: 7_800,
      },
    });

    expect(actor).not.toBeNull();
    if (!actor) throw new Error("expected scene actor");
    expect(actor.observatoryActiveStationId).toBe("signal");
    expect(actor.observatoryLikelyStationId).toBe("receipts");
    expect(actor.observatoryActor).toBeDefined();
    if (!actor.observatoryActor) throw new Error("expected observatory actor");
    expect(actor.observatoryActor.cueKind).toBe("witness");
    expect(actor.observatoryActor.likelyStationId).toBe("receipts");
  });
});
