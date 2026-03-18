import { describe, expect, it } from "vitest";
import type { ObservatoryTraversalSurfaceRecipe } from "./deriveObservatoryWorld";
import {
  resolveObservatoryTraversalHalfExtents,
  shouldAdhereObservatoryPlayerToGround,
} from "./grounding";

function createSurface(
  overrides: Partial<ObservatoryTraversalSurfaceRecipe> = {},
): ObservatoryTraversalSurfaceRecipe {
  return {
    colliderKind: "box",
    emissiveIntensity: 0.2,
    key: "test-surface",
    kind: "platform",
    opacity: 0.3,
    position: [0, 0, 0],
    rotation: [0, 0, 0],
    scale: [2, 0.2, 1],
    ...overrides,
  };
}

describe("resolveObservatoryTraversalHalfExtents", () => {
  it("shrinks ramp support edges to reduce capsule snagging", () => {
    const halfExtents = resolveObservatoryTraversalHalfExtents(
      createSurface({ kind: "ramp", scale: [2.1, 0.18, 0.88] }),
    );

    expect(halfExtents[0]).toBeCloseTo(0.87);
    expect(halfExtents[1]).toBeCloseTo(0.09);
    expect(halfExtents[2]).toBeCloseTo(0.38);
  });

  it("keeps non-ramp surfaces unchanged", () => {
    const halfExtents = resolveObservatoryTraversalHalfExtents(
      createSurface({ kind: "observation-platform", scale: [2.4, 0.18, 1.4] }),
    );

    expect(halfExtents).toEqual([1.2, 0.09, 0.7]);
  });
});

describe("shouldAdhereObservatoryPlayerToGround", () => {
  it("keeps the player grounded across a tiny hover gap", () => {
    expect(
      shouldAdhereObservatoryPlayerToGround({
        activeFlip: false,
        hoverGap: 0.04,
        jumpQueued: false,
        verticalVelocityY: 0.18,
      }),
    ).toBe(true);
  });

  it("does not clamp active jumps or flips", () => {
    expect(
      shouldAdhereObservatoryPlayerToGround({
        activeFlip: false,
        hoverGap: 0.04,
        jumpQueued: true,
        verticalVelocityY: 0.18,
      }),
    ).toBe(false);

    expect(
      shouldAdhereObservatoryPlayerToGround({
        activeFlip: true,
        hoverGap: 0.04,
        jumpQueued: false,
        verticalVelocityY: 0.18,
      }),
    ).toBe(false);
  });

  it("does not clamp when the player is meaningfully airborne", () => {
    expect(
      shouldAdhereObservatoryPlayerToGround({
        activeFlip: false,
        hoverGap: 0.18,
        jumpQueued: false,
        verticalVelocityY: 0.18,
      }),
    ).toBe(false);

    expect(
      shouldAdhereObservatoryPlayerToGround({
        activeFlip: false,
        hoverGap: 0.04,
        jumpQueued: false,
        verticalVelocityY: 1.8,
      }),
    ).toBe(false);
  });
});
