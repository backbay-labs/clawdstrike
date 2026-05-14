/**
 * useFlightInput.ts — Phase 21 FLT-02
 *
 * Input hook that reads keyboard + mouse input and produces a FlightIntent
 * on each frame. Uses refs (not state) so mutations never trigger re-renders
 * in the hot path.
 *
 * Keyboard mapping (per CONTEXT.md):
 *   W / ArrowUp    = thrust +1
 *   S / ArrowDown  = thrust -1
 *   A / ArrowLeft  = strafe -1
 *   D / ArrowRight = strafe +1
 *   Space          = vertical +1
 *   ShiftLeft/ShiftRight = vertical -1
 *   KeyE           = interactTriggered (one-shot)
 *
 * Mouse: accumulated movementX/Y while pointer lock is active, zeroed after
 * each frame read.
 *
 * Boost: double-tap W within boostDoubleTapWindowMs sets boostTriggered for
 * one frame.
 */

import { useCallback, useEffect, useRef } from "react";
import {
  createEmptyFlightIntent,
  DEFAULT_FLIGHT_CONFIG,
  type FlightConfig,
  type FlightIntent,
} from "./flight-types";
import { getObservatoryNowMs } from "../../utils/observatory-time";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface UseFlightInputOptions {
  enabled: boolean;
  config?: FlightConfig;
}

export interface UseFlightInputResult {
  intentRef: React.RefObject<FlightIntent>;
  requestPointerLock: () => void;
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useFlightInput({
  enabled,
  config = DEFAULT_FLIGHT_CONFIG,
}: UseFlightInputOptions): UseFlightInputResult {
  // intentRef is read every frame by useFlightLoop — never triggers re-renders
  const intentRef = useRef<FlightIntent>(createEmptyFlightIntent());

  // Pressed keys tracked as a Set to support multiple simultaneous keys
  const pressedRef = useRef(new Set<string>());

  // Boost double-tap detection
  const lastForwardPressRef = useRef<number | null>(null);

  // Pointer lock tracking
  const pointerLockedRef = useRef(false);

  const requestPointerLock = useCallback(() => {
    document.body.requestPointerLock();
  }, []);

  useEffect(() => {
    if (!enabled) {
      // Clear all input state when disabled
      pressedRef.current.clear();
      lastForwardPressRef.current = null;
      const intent = intentRef.current;
      intent.thrust = 0;
      intent.strafe = 0;
      intent.vertical = 0;
      intent.mouseDeltaX = 0;
      intent.mouseDeltaY = 0;
      intent.boostTriggered = false;
      intent.interactTriggered = false;
      // Release pointer lock if we hold it
      if (pointerLockedRef.current && document.pointerLockElement) {
        document.exitPointerLock();
      }
      return;
    }

    // -----------------------------------------------------------------------
    // Keyboard listeners
    // -----------------------------------------------------------------------

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.repeat) return;

      pressedRef.current.add(event.code);

      const intent = intentRef.current;

      // Boost: double-tap W detection
      if (event.code === "KeyW" || event.code === "ArrowUp") {
        const nowMs = getObservatoryNowMs();
        const lastMs = lastForwardPressRef.current;
        if (lastMs !== null && nowMs - lastMs <= config.boostDoubleTapWindowMs) {
          intent.boostTriggered = true;
        }
        lastForwardPressRef.current = nowMs;
      }

      // Interact: one-shot trigger
      if (event.code === "KeyE") {
        intent.interactTriggered = true;
      }

      // Rebuild axis values from full key set
      rebuildAxes(intent, pressedRef.current);
    };

    const onKeyUp = (event: KeyboardEvent) => {
      pressedRef.current.delete(event.code);
      rebuildAxes(intentRef.current, pressedRef.current);
    };

    window.addEventListener("keydown", onKeyDown);
    window.addEventListener("keyup", onKeyUp);

    // -----------------------------------------------------------------------
    // Mouse listener (only accumulates when pointer locked)
    // -----------------------------------------------------------------------

    const onMouseMove = (event: MouseEvent) => {
      if (!pointerLockedRef.current) return;
      intentRef.current.mouseDeltaX += event.movementX;
      intentRef.current.mouseDeltaY += event.movementY;
    };

    document.addEventListener("mousemove", onMouseMove);

    // -----------------------------------------------------------------------
    // Pointer lock change listener
    // -----------------------------------------------------------------------

    const onPointerLockChange = () => {
      pointerLockedRef.current = document.pointerLockElement != null;
    };

    document.addEventListener("pointerlockchange", onPointerLockChange);

    return () => {
      window.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("keyup", onKeyUp);
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("pointerlockchange", onPointerLockChange);
    };
  }, [enabled, config.boostDoubleTapWindowMs]);

  return { intentRef, requestPointerLock };
}

// ---------------------------------------------------------------------------
// Axis derivation (pure function — no allocations)
// ---------------------------------------------------------------------------

function rebuildAxes(intent: FlightIntent, pressed: Set<string>): void {
  let thrust = 0;
  let strafe = 0;
  let vertical = 0;

  if (pressed.has("KeyW") || pressed.has("ArrowUp")) thrust += 1;
  if (pressed.has("KeyS") || pressed.has("ArrowDown")) thrust -= 1;
  if (pressed.has("KeyA") || pressed.has("ArrowLeft")) strafe -= 1;
  if (pressed.has("KeyD") || pressed.has("ArrowRight")) strafe += 1;
  if (pressed.has("Space")) vertical += 1;
  if (pressed.has("ShiftLeft") || pressed.has("ShiftRight")) vertical -= 1;

  intent.thrust = Math.max(-1, Math.min(1, thrust));
  intent.strafe = Math.max(-1, Math.min(1, strafe));
  intent.vertical = Math.max(-1, Math.min(1, vertical));
}
