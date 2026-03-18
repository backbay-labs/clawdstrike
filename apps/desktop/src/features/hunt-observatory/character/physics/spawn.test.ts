import { describe, expect, it } from "vitest";
import type { HuntStationPlacement } from "../../types";
import { resolveObservatorySpawnPoint } from "./spawn";

const placements: HuntStationPlacement[] = [
  { id: "signal", label: "Signal", angleDeg: 0, radius: 18 },
  { id: "watch", label: "Watch", angleDeg: 90, radius: 20 },
];

describe("resolveObservatorySpawnPoint", () => {
  it("falls back to the thesis core when no preferred station is provided", () => {
    const spawn = resolveObservatorySpawnPoint(placements);
    expect(spawn.id).toBe("thesis-core");
    expect(spawn.stationId).toBeNull();
    expect(spawn.position[2]).toBeGreaterThan(0);
  });

  it("resolves a preferred station spawn from the station placement", () => {
    const spawn = resolveObservatorySpawnPoint(placements, "watch", {
      baseHeight: 1.4,
      radialOffset: 2,
    });

    expect(spawn.id).toBe("station:watch");
    expect(spawn.stationId).toBe("watch");
    expect(spawn.position[1]).toBe(1.4);
    expect(Math.abs(spawn.position[0])).toBeLessThan(0.1);
    expect(spawn.position[2]).toBeGreaterThan(10);
  });
});
