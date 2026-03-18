import { describe, expect, it } from "vitest";
import {
  projectNexusSpiritRitualModel,
  resolveNexusSpiritReleasePhase,
} from "./ritualProjection";
import type { NexusSpiritSceneActor } from "./runtime";

function makeActor(overrides: Partial<NexusSpiritSceneActor> = {}): NexusSpiritSceneActor {
  return {
    huntId: "hunt-1",
    huntTitle: "Ghostline",
    kind: "tracker",
    label: "Tracker",
    accentColor: "#d4a84b",
    contour: "reticle-vector",
    stance: "focus",
    cue: {
      kind: "transit",
      reason: "Spirit posture transfers with the active strikecell focus.",
      durationMs: 2600,
      startedAt: 1_000,
      expiresAt: 3_600,
      fromStrikecellId: "security-overview",
      toStrikecellId: "threat-radar",
    },
    emphasis: ["entities", "watch", "target"],
    reason: "Target-heavy hunt with live threat pressure.",
    anchorStrikecellId: "security-overview",
    likelyStationId: "threat-radar",
    observatoryAnchorStationId: "signal",
    observatoryLikelyStationId: "watch",
    observatoryStationAffinities: {
      signal: 0.82,
      watch: 0.64,
    },
    observatoryActor: {
      type: "spirit-field",
      kind: "tracker",
      stance: "focus",
      likelyStationId: "watch",
      emphasis: ["entities", "watch", "target"],
      cueKind: "transit",
    },
    presenceStrength: 0.74,
    orbitRadius: 1.36,
    altitude: 1.7,
    focusBeam: 0.54,
    stationAffinities: {
      "security-overview": 0.82,
      "threat-radar": 0.64,
    },
    ...overrides,
  };
}

describe("projectNexusSpiritRitualModel", () => {
  it("projects the active nexus companion into the SR3 ritual model", () => {
    const model = projectNexusSpiritRitualModel(makeActor());

    expect(model.release.title).toContain("Transit Tracker");
    expect(model.stationLabel).toBe("Threat Radar");
    expect(model.focusLine).toContain("entities");
    expect(model.runtime.currentShell).toBe("nexus");
  });

  it("maps transit and focus cues into release phases", () => {
    expect(resolveNexusSpiritReleasePhase(makeActor())).toBe("releasing");
    expect(
      resolveNexusSpiritReleasePhase(
        makeActor({
          cue: {
            kind: "focus",
            reason: "Tightening station emphasis around the current hunt posture.",
            durationMs: 2000,
            startedAt: 1_000,
            expiresAt: 3_000,
            fromStrikecellId: "security-overview",
            toStrikecellId: "security-overview",
          },
        }),
      ),
    ).toBe("released");
  });
});
