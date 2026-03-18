import { describe, expect, it } from "vitest";
import {
  createEmptyObservatoryPlayerKeyState,
  DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
} from "../types";
import {
  deriveObservatoryPlayerIntent,
  reduceObservatoryPlayerKeyState,
} from "./useObservatoryPlayerInput";

describe("deriveObservatoryPlayerIntent", () => {
  it("maps the standard vertical bindings, sprint, and jump into intent", () => {
    let keyState = createEmptyObservatoryPlayerKeyState();
    keyState = reduceObservatoryPlayerKeyState(
      keyState,
      { type: "keydown", code: "KeyW", repeat: false, nowMs: 10 },
      DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    );
    keyState = reduceObservatoryPlayerKeyState(
      keyState,
      { type: "keydown", code: "ShiftLeft", repeat: false, nowMs: 20 },
      DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    );
    keyState = reduceObservatoryPlayerKeyState(
      keyState,
      { type: "keydown", code: "Space", repeat: false, nowMs: 30 },
      DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    );

    expect(deriveObservatoryPlayerIntent(keyState)).toEqual({
      moveX: 0,
      moveY: 1,
      sprint: true,
      jump: true,
      flipFront: false,
      flipBack: false,
      interact: false,
    });
  });

  it("queues a front flip on a fast second space press", () => {
    let keyState = createEmptyObservatoryPlayerKeyState();
    keyState = reduceObservatoryPlayerKeyState(
      keyState,
      { type: "keydown", code: "Space", repeat: false, nowMs: 100 },
      DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    );
    keyState = reduceObservatoryPlayerKeyState(
      keyState,
      { type: "keydown", code: "Space", repeat: false, nowMs: 320 },
      DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    );

    const intent = deriveObservatoryPlayerIntent(keyState);
    expect(intent.jump).toBe(true);
    expect(intent.flipFront).toBe(true);
    expect(intent.interact).toBe(false);
  });

  it("treats flip inputs as transient pulses that can be consumed", () => {
    let keyState = createEmptyObservatoryPlayerKeyState();
    keyState = reduceObservatoryPlayerKeyState(
      keyState,
      { type: "keydown", code: "KeyQ", repeat: false, nowMs: 10 },
      DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    );
    keyState = reduceObservatoryPlayerKeyState(
      keyState,
      { type: "keydown", code: "KeyE", repeat: false, nowMs: 20 },
      DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    );

    expect(deriveObservatoryPlayerIntent(keyState).flipFront).toBe(true);
    expect(deriveObservatoryPlayerIntent(keyState).flipBack).toBe(true);

    const consumed = reduceObservatoryPlayerKeyState(
      keyState,
      { type: "consume", code: "", repeat: false, nowMs: 30 },
      DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    );
    expect(deriveObservatoryPlayerIntent(consumed).flipFront).toBe(false);
    expect(deriveObservatoryPlayerIntent(consumed).flipBack).toBe(false);
  });

  it("queues an interact pulse on F and clears it on consume", () => {
    let keyState = createEmptyObservatoryPlayerKeyState();
    keyState = reduceObservatoryPlayerKeyState(
      keyState,
      { type: "keydown", code: "KeyF", repeat: false, nowMs: 10 },
      DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    );

    expect(deriveObservatoryPlayerIntent(keyState).interact).toBe(true);

    const consumed = reduceObservatoryPlayerKeyState(
      keyState,
      { type: "consume", code: "", repeat: false, nowMs: 30 },
      DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    );
    expect(deriveObservatoryPlayerIntent(consumed).interact).toBe(false);
  });
});
