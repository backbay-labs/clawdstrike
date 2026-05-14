import { describe, expect, it } from "vitest";
import type { ObservatoryStation } from "@/features/observatory/types";
import { createInitialObservatoryProbeState, dispatchObservatoryProbe } from "@/features/observatory/world/probeRuntime";
import { deriveObservatorySpikeCue, buildObservatorySpikeCueKey } from "@/features/observatory/world/observatory-presence";

function makeStation(
  id: ObservatoryStation["id"],
  overrides: Partial<ObservatoryStation> = {},
): ObservatoryStation {
  return {
    artifactCount: 0,
    affinity: 0.4,
    emphasis: 0.3,
    id,
    kind: "observatory",
    label: id.toUpperCase(),
    route: `/${id}`,
    routeLabel: id.toUpperCase(),
    status: "warming",
    ...overrides,
  };
}

describe("deriveObservatorySpikeCue", () => {
  it("produces a cue from rising emphasis and active status with a route recommendation", () => {
    const cue = deriveObservatorySpikeCue({
      flyByActive: false,
      ghostMode: "auto",
      nowMs: 1000,
      previousStationEmphasis: { receipts: 0.1 },
      stations: [
        makeStation("signal", { emphasis: 0.12, status: "idle" }),
        makeStation("receipts", {
          artifactCount: 3,
          emphasis: 0.34,
          reason: "Investigations are pinning new evidence arrivals to active analyst work.",
          status: "active",
        }),
      ],
    });

    expect(cue).not.toBeNull();
    expect(cue?.stationId).toBe("receipts");
    expect(cue?.title).toContain("drawing attention");
    expect(cue?.causes.length).toBeGreaterThanOrEqual(2);
    expect(cue?.recommendation.route).toBe("/receipt-preview");
    expect(cue?.recommendation.actionLabel).toContain("Open");
  });

  it("produces a cue for a deliberate probe discovery even if the station was not the prior winner", () => {
    const activeProbe = dispatchObservatoryProbe(createInitialObservatoryProbeState(), "watch", 1000);

    const cue = deriveObservatorySpikeCue({
      likelyStationId: "signal",
      missionTargetStationId: "watch",
      nowMs: 1300,
      previousLikelyStationId: "signal",
      previousProbeStatus: "ready",
      probeState: activeProbe,
      selectedStationId: "watch",
      stations: [
        makeStation("signal", { emphasis: 0.52, status: "warming" }),
        makeStation("watch", {
          artifactCount: 2,
          emphasis: 0.41,
          reason: "The perimeter is reacting to the active probe.",
          status: "receiving",
        }),
      ],
    });

    expect(cue?.stationId).toBe("watch");
    expect(cue?.causes.some((cause) => cause.detail.includes("probe"))).toBe(true);
  });

  it("returns null for replay, fly-by, or unchanged-pressure inputs and keeps the cue key stable", () => {
    const stations = [makeStation("signal", { emphasis: 0.2, status: "idle" })];
    const cue = deriveObservatorySpikeCue({
      flyByActive: false,
      nowMs: 1000,
      previousStationEmphasis: { signal: 0.2 },
      stations,
    });
    expect(cue).toBeNull();

    const replayCue = deriveObservatorySpikeCue({
      flyByActive: false,
      nowMs: 1000,
      replayEnabled: true,
      stations,
    });
    expect(replayCue).toBeNull();

    const flyByCue = deriveObservatorySpikeCue({
      flyByActive: true,
      nowMs: 1000,
      stations,
    });
    expect(flyByCue).toBeNull();

    const hotCue = deriveObservatorySpikeCue({
      flyByActive: false,
      nowMs: 1000,
      previousStationEmphasis: { signal: 0.05 },
      previousCueKey: null,
      stations: [makeStation("signal", { emphasis: 0.3, status: "active" })],
    });
    const stableKey = hotCue ? buildObservatorySpikeCueKey(hotCue) : "";
    expect(buildObservatorySpikeCueKey({ ...hotCue!, cueKey: "ignored" })).toBe(stableKey);

    const repeated = deriveObservatorySpikeCue({
      flyByActive: false,
      nowMs: 1000,
      previousCueKey: stableKey,
      previousStationEmphasis: { signal: 0.05 },
      stations: [makeStation("signal", { emphasis: 0.3, status: "active" })],
    });
    expect(repeated).toBeNull();
  });

  it("requires a meaningful transition before repeating a hot-station cue", () => {
    const cue = deriveObservatorySpikeCue({
      likelyStationId: "signal",
      nowMs: 1000,
      previousLikelyStationId: "signal",
      previousProbeStatus: "ready",
      previousStationEmphasis: { signal: 0.3 },
      stations: [makeStation("signal", { artifactCount: 2, emphasis: 0.3, status: "active" })],
    });

    expect(cue).toBeNull();
  });

  it("prefers the more explainable station when a slightly higher-pressure station has no reason", () => {
    const cue = deriveObservatorySpikeCue({
      flyByActive: false,
      nowMs: 1000,
      stations: [
        makeStation("receipts", {
          artifactCount: 5,
          emphasis: 0.55,
          reason: "Evidence receipts are accumulating faster than the archive can settle them.",
          status: "active",
        }),
        makeStation("watch", {
          artifactCount: 8,
          emphasis: 0.57,
          status: "active",
        }),
      ],
    });

    expect(cue?.stationId).toBe("receipts");
    expect(cue?.title).toContain("attention");
  });
});
