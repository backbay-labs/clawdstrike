import { describe, expect, it } from "vitest";
import {
  createObservatoryGroundQuery,
  createObservatoryGroundScratch,
  createStationPlateSpecs,
  resolveGroundHeightFromQuery,
  resolveObservatoryWorldSpawn,
  resolveJumpPadBoostFromQuery,
  resolveNearestDistrictIdFromQuery,
} from "@/features/observatory/components/flow-runtime/grounding";
import type { DerivedObservatoryWorld } from "@/features/observatory/world/deriveObservatoryWorld";

const world = {
  districts: [
    {
      id: "watch",
      baseDiscRadius: 8,
      position: [0, 0, 0],
      traversalSurfaces: [
        {
          key: "deck",
          kind: "platform",
          colliderKind: "box",
          position: [0, 1, 0],
          rotation: [0, 0, 0],
          scale: [2, 1, 2],
        },
        {
          key: "pad",
          kind: "jump-pad",
          colliderKind: "cylinder",
          position: [3, 0.5, 0],
          rotation: [0, 0, 0],
          scale: [2, 1, 2],
          jumpBoost: 11,
        },
      ],
    },
    {
      id: "scan",
      baseDiscRadius: 6,
      position: [20, 0, 0],
      traversalSurfaces: [],
    },
  ],
  watchfield: {
    position: [10, 0, 10],
  },
} as unknown as DerivedObservatoryWorld;

describe("observatory flow grounding", () => {
  it("resolves ground height from station plates, surfaces, and watchfield fallback", () => {
    const query = createObservatoryGroundQuery(world);
    const scratch = createObservatoryGroundScratch();

    expect(resolveGroundHeightFromQuery(query, [0.5, 0, 0.5], scratch)).toBeCloseTo(1.5, 5);
    expect(resolveGroundHeightFromQuery(query, [10, 0, 10], scratch)).toBe(0.24);
    expect(resolveGroundHeightFromQuery(query, [50, 0, 50], scratch)).toBe(0);
  });

  it("resolves nearest district ids only within the observatory radius", () => {
    const query = createObservatoryGroundQuery(world);

    expect(resolveNearestDistrictIdFromQuery(query, [1, 0, 1])).toBe("watch");
    expect(resolveNearestDistrictIdFromQuery(query, [18, 0, 0])).toBe("scan");
    expect(resolveNearestDistrictIdFromQuery(query, [48, 0, 48])).toBeNull();
  });

  it("resolves jump-pad boosts from precomputed surfaces", () => {
    const query = createObservatoryGroundQuery(world);

    expect(resolveJumpPadBoostFromQuery(query, [3, 0.5, 0])).toBe(11);
    expect(resolveJumpPadBoostFromQuery(query, [0, 0, 0])).toBeNull();
  });

  it("creates station plate specs and spawn points from the live grounding module", () => {
    const specs = createStationPlateSpecs(world);

    expect(specs).toHaveLength(4);
    expect(specs[0]?.id).toBe("station-plate:watch");
    expect(resolveObservatoryWorldSpawn(world, "watch").stationId).toBe("watch");
  });
});
