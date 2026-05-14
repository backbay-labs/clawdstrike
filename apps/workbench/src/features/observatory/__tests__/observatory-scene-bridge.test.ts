import { describe, expect, it } from "vitest";
import type { ObservatoryStation } from "@/features/observatory/types";
import {
  buildObservatorySceneState,
  buildObservatoryStationStates,
} from "@/features/observatory/world/observatory-scene-bridge";

const baseStations: ObservatoryStation[] = [
  {
    affinity: 0.42,
    artifactCount: 0,
    emphasis: 0.28,
    id: "signal",
    kind: "hunt",
    label: "Signal",
    route: "/hunt",
    status: "warming",
  },
  {
    affinity: 0.77,
    artifactCount: 4,
    emphasis: 0.91,
    id: "receipts",
    kind: "receipt-preview",
    label: "Receipts",
    route: "/receipt-preview",
    status: "receiving",
  },
  {
    affinity: 0.63,
    artifactCount: 1,
    emphasis: 0.48,
    id: "watch",
    kind: "nexus",
    label: "Watch",
    route: "/nexus",
    status: "active",
  },
] satisfies ObservatoryStation[];

describe("observatory scene bridge", () => {
  it("applies preset emphasis boosts without breaking station ordering", () => {
    const states = buildObservatoryStationStates(baseStations, "receipts");

    expect(states.map((station) => station.id)).toEqual([
      "signal",
      "targets",
      "run",
      "receipts",
      "case-notes",
      "watch",
    ]);
    expect(states.find((station) => station.id === "receipts")?.emphasis).toBeCloseTo(1, 5);
    expect(states.find((station) => station.id === "watch")?.emphasis).toBeCloseTo(0.48, 5);
  });

  it("switches scene focus and detail surface for analyst presets", () => {
    const receiptsScene = buildObservatorySceneState({
      analystPresetId: "receipts",
      confidence: 0.82,
      likelyStationId: "watch",
      mode: "atlas",
      roomReceiveState: "receiving",
      spiritFieldBias: 0.5,
      stations: baseStations,
    });
    const evidenceScene = buildObservatorySceneState({
      analystPresetId: "evidence",
      confidence: 0.64,
      likelyStationId: "signal",
      mode: "flow",
      roomReceiveState: "idle",
      spiritFieldBias: 0,
      stations: baseStations,
    });

    expect(receiptsScene.cameraPreset).toBe("focus-station");
    expect(receiptsScene.likelyStationId).toBe("receipts");
    expect(receiptsScene.openedDetailSurface).toBe("bottom");
    expect(evidenceScene.cameraPreset).toBe("focus-station");
    expect(evidenceScene.likelyStationId).toBe("case-notes");
    expect(evidenceScene.openedDetailSurface).toBe("rail");
  });

  it("preserves the incoming live focus when no analyst preset is active", () => {
    const scene = buildObservatorySceneState({
      confidence: 0.58,
      likelyStationId: "watch",
      mode: "atlas",
      roomReceiveState: "aftermath",
      spiritFieldBias: 0.3,
      stations: baseStations,
    });

    expect(scene.cameraPreset).toBe("overview");
    expect(scene.likelyStationId).toBe("watch");
    expect(scene.openedDetailSurface).toBe("none");
  });
});
