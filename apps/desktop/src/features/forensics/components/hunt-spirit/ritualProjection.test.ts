import { describe, expect, it } from "vitest";
import {
  projectForensicsSpiritRitualModel,
  resolveForensicsSpiritReleasePhase,
} from "./ritualProjection";
import type { HuntSpiritSceneActor } from "./runtime";

function makeActor(overrides: Partial<HuntSpiritSceneActor> = {}): HuntSpiritSceneActor {
  return {
    huntId: "hunt-1",
    huntTitle: "Ghostline",
    kind: "lantern",
    label: "Lantern",
    accentColor: "#d8c37d",
    contour: "aperture-reveal",
    stance: "witness",
    cue: {
      kind: "bind",
      reason: "Spirit bind pulse entering the river field.",
      durationMs: 3600,
      startedAt: 1_000,
      expiresAt: 4_600,
    },
    emphasis: ["evidence", "receipts", "notes"],
    reason: "Receipt-led inquiry.",
    activeStationId: "attack-graph",
    observatoryActiveStationId: "targets",
    observatoryLikelyStationId: "receipts",
    observatoryActor: {
      type: "spirit-field",
      kind: "lantern",
      stance: "witness",
      likelyStationId: "receipts",
      emphasis: ["evidence", "receipts", "notes"],
      cueKind: "bind",
    },
    presenceStrength: 0.72,
    orbitRadius: 1.5,
    altitude: 1.8,
    laneBias: 0.12,
    focusBeam: 0.48,
    ...overrides,
  };
}

describe("projectForensicsSpiritRitualModel", () => {
  it("projects the active river actor into the SR3 ritual model", () => {
    const model = projectForensicsSpiritRitualModel(makeActor());

    expect(model.release.title).toContain("Receive Lantern");
    expect(model.stationLabel).toBe("Attack Graph");
    expect(model.focusLine).toContain("evidence");
    expect(model.runtime.currentShell).toBe("forensics");
  });

  it("maps bind receive into a releasing phase", () => {
    expect(resolveForensicsSpiritReleasePhase(makeActor())).toBe("releasing");
    expect(
      resolveForensicsSpiritReleasePhase(makeActor({ cue: { kind: "focus", reason: "Tightening", durationMs: 1200, startedAt: 1, expiresAt: 2 } })),
    ).toBe("released");
  });
});
