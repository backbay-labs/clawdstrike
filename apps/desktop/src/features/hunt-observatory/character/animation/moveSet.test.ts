import { describe, expect, it } from "vitest";
import {
  getObservatoryPlayerMoveSpec,
  mapControllerActionToVisualAction,
  resolveObservatoryActionClipName,
  resolveObservatoryPlayerAction,
  sampleObservatoryPlayerPose,
  type ObservatoryPlayerControllerStateLike,
} from "./moveSet";

function makeControllerState(
  overrides: Partial<ObservatoryPlayerControllerStateLike> = {},
): ObservatoryPlayerControllerStateLike {
  return {
    position: [0, 0, 0],
    velocity: [0, 0, 0],
    grounded: true,
    facingRadians: 0,
    ...overrides,
  };
}

describe("mapControllerActionToVisualAction", () => {
  it("normalizes controller jump and flip tokens into visual actions", () => {
    expect(mapControllerActionToVisualAction("jump-start")).toBe("jump");
    expect(mapControllerActionToVisualAction("jump_air")).toBe("jump");
    expect(mapControllerActionToVisualAction("flip-front")).toBe("front-flip");
    expect(mapControllerActionToVisualAction("flip back")).toBe("back-flip");
  });
});

describe("resolveObservatoryPlayerAction", () => {
  it("uses explicit controller actions when present", () => {
    const resolved = resolveObservatoryPlayerAction(
      makeControllerState({
        activeAction: "flip-front",
        grounded: false,
        velocity: [0, 4, 0],
      }),
    );

    expect(resolved.action).toBe("front-flip");
    expect(resolved.usedFallbackAction).toBe(false);
  });

  it("falls back to locomotion and landing from raw controller state", () => {
    const running = resolveObservatoryPlayerAction(
      makeControllerState({
        activeAction: null,
        velocity: [0, 0, 2.8],
        sprinting: true,
      }),
    );
    const airborne = resolveObservatoryPlayerAction(
      makeControllerState({
        activeAction: null,
        grounded: false,
        velocity: [0, 3.2, 0.1],
      }),
      { previousGrounded: true },
    );
    const landed = resolveObservatoryPlayerAction(
      makeControllerState({
        activeAction: null,
        grounded: true,
        velocity: [0, -0.1, 0],
      }),
      { previousGrounded: false },
    );

    expect(running.action).toBe("run");
    expect(airborne.action).toBe("jump");
    expect(landed.action).toBe("land");
    expect(landed.landTimerSeconds).toBeGreaterThan(0);
  });
});

describe("resolveObservatoryActionClipName", () => {
  it("matches specific flip clips before generic flip clips", () => {
    const clipName = resolveObservatoryActionClipName("front-flip", [
      "Idle",
      "Flip",
      "FrontFlip",
    ]);

    expect(clipName).toBe("FrontFlip");
  });
});

describe("getObservatoryPlayerMoveSpec", () => {
  it("exposes shared move metadata for authored flips", () => {
    const move = getObservatoryPlayerMoveSpec("front-flip");

    expect(move.oneShot).toBe(true);
    expect(move.presentation?.spinTurns).toBeLessThan(0);
    expect(move.physics?.forwardBoostScale).toBeGreaterThan(0);
  });
});

describe("sampleObservatoryPlayerPose", () => {
  it("spins front and back flips in opposite directions", () => {
    const frontFlip = sampleObservatoryPlayerPose({
      action: "front-flip",
      elapsedSeconds: 0.36,
      horizontalSpeed: 0,
    });
    const backFlip = sampleObservatoryPlayerPose({
      action: "back-flip",
      elapsedSeconds: 0.36,
      horizontalSpeed: 0,
    });

    expect(frontFlip.bodySpinX).toBeLessThan(0);
    expect(backFlip.bodySpinX).toBeGreaterThan(0);
  });

  it("compresses the body during landing", () => {
    const pose = sampleObservatoryPlayerPose({
      action: "land",
      elapsedSeconds: 0.04,
      horizontalSpeed: 0,
    });

    expect(pose.rootScale[1]).toBeLessThan(1);
    expect(pose.rootOffsetY).toBeLessThan(0);
  });
});
