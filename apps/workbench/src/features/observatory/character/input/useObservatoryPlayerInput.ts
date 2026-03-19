// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/character/input/useObservatoryPlayerInput.ts
// Import remapped: ../types → ../types (character types)

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  createEmptyObservatoryPlayerIntent,
  createEmptyObservatoryPlayerKeyState,
  DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
  type ObservatoryPlayerBindings,
  type ObservatoryPlayerIntent,
  type ObservatoryPlayerKeyState,
} from "../types";

const DOUBLE_SPACE_FLIP_WINDOW_MS = 300;

function isBound(code: string, bindings: string[]): boolean {
  return bindings.includes(code);
}

function clampAxis(value: number): number {
  if (value > 0) return 1;
  if (value < 0) return -1;
  return 0;
}

export function deriveObservatoryPlayerIntent(
  keyState: ObservatoryPlayerKeyState,
  bindings: ObservatoryPlayerBindings = DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
): ObservatoryPlayerIntent {
  const moveX = clampAxis(
    (Array.from(keyState.pressed).some((code) => isBound(code, bindings.moveRight)) ? 1 : 0)
      - (Array.from(keyState.pressed).some((code) => isBound(code, bindings.moveLeft)) ? 1 : 0),
  );
  const moveY = clampAxis(
    (Array.from(keyState.pressed).some((code) => isBound(code, bindings.moveForward)) ? 1 : 0)
      - (Array.from(keyState.pressed).some((code) => isBound(code, bindings.moveBackward)) ? 1 : 0),
  );

  return {
    moveX,
    moveY,
    sprint: Array.from(keyState.pressed).some((code) => isBound(code, bindings.sprint)),
    jump: keyState.jumpQueued,
    flipFront: keyState.flipFrontQueued,
    flipBack: keyState.flipBackQueued,
    interact: keyState.interactQueued,
  };
}

export function reduceObservatoryPlayerKeyState(
  previous: ObservatoryPlayerKeyState,
  event: Pick<KeyboardEvent, "code" | "repeat"> & {
    nowMs?: number;
    type: "keydown" | "keyup" | "consume";
  },
  bindings: ObservatoryPlayerBindings = DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
): ObservatoryPlayerKeyState {
  const nextPressed = new Set(previous.pressed);

  if (event.type === "keydown") {
    nextPressed.add(event.code);
  } else if (event.type === "keyup") {
    nextPressed.delete(event.code);
  }

  const jumpPressed =
    event.type === "keydown" && !event.repeat && isBound(event.code, bindings.jump);
  const nextJumpPressedAtMs = jumpPressed ? event.nowMs ?? null : previous.lastJumpPressedAtMs;
  const shouldQueueDoubleSpaceFlip =
    jumpPressed &&
    previous.lastJumpPressedAtMs != null &&
    event.nowMs != null &&
    event.nowMs - previous.lastJumpPressedAtMs <= DOUBLE_SPACE_FLIP_WINDOW_MS;

  return {
    pressed: nextPressed,
    jumpQueued:
      event.type === "consume"
        ? false
        : previous.jumpQueued
            || (jumpPressed && !shouldQueueDoubleSpaceFlip),
    flipFrontQueued:
      event.type === "consume"
        ? false
        : previous.flipFrontQueued
            || shouldQueueDoubleSpaceFlip
            || (
              event.type === "keydown"
              && !event.repeat
              && isBound(event.code, bindings.flipFront)
            ),
    flipBackQueued:
      event.type === "consume"
        ? false
        : previous.flipBackQueued
            || (event.type === "keydown" && !event.repeat && isBound(event.code, bindings.flipBack)),
    interactQueued:
      event.type === "consume"
        ? false
        : previous.interactQueued
            || (event.type === "keydown" && !event.repeat && isBound(event.code, bindings.interact)),
    lastJumpPressedAtMs: event.type === "consume" ? previous.lastJumpPressedAtMs : nextJumpPressedAtMs,
  };
}

export interface UseObservatoryPlayerInputOptions {
  enabled?: boolean;
  bindings?: ObservatoryPlayerBindings;
  target?: Window | null;
}

export interface UseObservatoryPlayerInputResult {
  intent: ObservatoryPlayerIntent;
  keyState: ObservatoryPlayerKeyState;
  consumeTransientActions: () => void;
  reset: () => void;
}

export function useObservatoryPlayerInput(
  options: UseObservatoryPlayerInputOptions = {},
): UseObservatoryPlayerInputResult {
  const {
    enabled = true,
    bindings = DEFAULT_OBSERVATORY_PLAYER_BINDINGS,
    target = typeof window !== "undefined" ? window : null,
  } = options;
  const [keyState, setKeyState] = useState<ObservatoryPlayerKeyState>(() =>
    createEmptyObservatoryPlayerKeyState(),
  );

  useEffect(() => {
    if (!enabled || !target) return;

    const onKeyDown = (event: KeyboardEvent) => {
      setKeyState((previous) =>
        reduceObservatoryPlayerKeyState(
          previous,
          {
            type: "keydown",
            code: event.code,
            repeat: event.repeat,
            nowMs: performance.now(),
          },
          bindings,
        ));
    };
    const onKeyUp = (event: KeyboardEvent) => {
      setKeyState((previous) =>
        reduceObservatoryPlayerKeyState(
          previous,
          {
            type: "keyup",
            code: event.code,
            repeat: event.repeat,
            nowMs: performance.now(),
          },
          bindings,
        ));
    };

    target.addEventListener("keydown", onKeyDown);
    target.addEventListener("keyup", onKeyUp);
    return () => {
      target.removeEventListener("keydown", onKeyDown);
      target.removeEventListener("keyup", onKeyUp);
    };
  }, [bindings, enabled, target]);

  const consumeTransientActions = useCallback(() => {
    setKeyState((previous) => reduceObservatoryPlayerKeyState(previous, { code: "", repeat: false, type: "consume" }, bindings));
  }, [bindings]);

  const reset = useCallback(() => {
    setKeyState(createEmptyObservatoryPlayerKeyState());
  }, []);

  const intent = useMemo(
    () => (enabled ? deriveObservatoryPlayerIntent(keyState, bindings) : createEmptyObservatoryPlayerIntent()),
    [bindings, enabled, keyState],
  );

  return {
    intent,
    keyState,
    consumeTransientActions,
    reset,
  };
}
