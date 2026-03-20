/**
 * SpaceFlightController.tsx — Phase 21 FLT-02
 *
 * Replaces the Rapier-based FlowModeController for the v6.0 space flight
 * experience. Renders the ShipMesh and runs the flight input + physics hooks.
 * No gravity, no rigid bodies — pure velocity-based flight.
 *
 * Usage in ObservatoryFlowRuntimeScene:
 *   lazy(() => import("./SpaceFlightController").then(...))
 */

import { useEffect, useRef, useCallback, type RefObject } from "react";
import * as THREE from "three";
import { useThree } from "@react-three/fiber";
import { ShipMesh } from "./ShipMesh";
import { useFlightInput } from "./useFlightInput";
import { useFlightLoop } from "./useFlightLoop";
import { DEFAULT_FLIGHT_STATE } from "./flight-types";
import type { FlightState } from "./flight-types";
import type { ObservatoryPlayerFocusState } from "../../components/flow-runtime/grounding";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface SpaceFlightControllerProps {
  /** Whether keyboard + mouse input is active (gates per-pane focus) */
  inputEnabled: boolean;
  /** Spirit accent color — forwarded to ShipMesh hull panels */
  accentColor?: string;
  /** Ref written each frame so FovController + WorldCameraRig read ship state */
  playerFocusRef: RefObject<ObservatoryPlayerFocusState | null>;
  /** Optional callback to push FlightState to store (throttled ~100ms) */
  onStateChange?: (state: FlightState) => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SpaceFlightController({
  inputEnabled,
  accentColor,
  playerFocusRef,
  onStateChange,
}: SpaceFlightControllerProps) {
  const shipRef = useRef<THREE.Group>(null);

  // Flight input — keyboard + mouse → FlightIntent ref
  const { intentRef, requestPointerLock } = useFlightInput({ enabled: inputEnabled });

  // State change bridge: updates both onStateChange callback AND playerFocusRef
  const handleStateChange = useCallback(
    (state: FlightState) => {
      // Write to playerFocusRef so FovController and WorldCameraRig can read it
      playerFocusRef.current = {
        action: state.currentSpeed > 30 ? "sprint" : state.currentSpeed > 1 ? "walk" : null,
        airborne: false,
        facingRadians: 0, // Not used for flight — quaternion is the truth
        moving: state.currentSpeed > 0.5,
        moveVector: [0, 0],
        position: [...state.position] as [number, number, number],
        sprinting: state.speedTier === "boost",
        stationId: state.nearestStationId,
      };

      onStateChange?.(state);
    },
    [playerFocusRef, onStateChange],
  );

  // Flight physics loop — mutates shipRef each frame
  useFlightLoop({ intentRef, shipRef, onStateChange: handleStateChange });

  // Pointer lock on canvas click
  const { gl } = useThree();
  useEffect(() => {
    if (!inputEnabled) return;
    const handler = () => requestPointerLock();
    gl.domElement.addEventListener("click", handler);
    return () => gl.domElement.removeEventListener("click", handler);
  }, [gl.domElement, inputEnabled, requestPointerLock]);

  // Initialize ship at DEFAULT_FLIGHT_STATE spawn position on mount
  useEffect(() => {
    const ship = shipRef.current;
    if (!ship) return;
    const [x, y, z] = DEFAULT_FLIGHT_STATE.position;
    ship.position.set(x, y, z);
    const [qx, qy, qz, qw] = DEFAULT_FLIGHT_STATE.quaternion;
    ship.quaternion.set(qx, qy, qz, qw);
  }, []);

  return (
    <group ref={shipRef}>
      <ShipMesh accentColor={accentColor} />
    </group>
  );
}
