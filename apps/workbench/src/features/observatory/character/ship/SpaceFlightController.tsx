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
import { useDockingSystem } from "./useDockingSystem";
import { DEFAULT_FLIGHT_STATE, DEFAULT_FLIGHT_CONFIG } from "./flight-types";
import type { FlightState } from "./flight-types";
import type { DockingState } from "./docking-types";
import type { ObservatoryPlayerFocusState } from "../../components/flow-runtime/grounding";
import { ChaseCamera } from "./ChaseCamera";
import { ShipThrusterVFX } from "./ShipThrusterVFX";
import { useObservatoryStore } from "../../stores/observatory-store";

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

  // FLT-06: Track thrust intensity and boost state for ShipThrusterVFX
  // Use refs (not state) to avoid re-renders in the 60Hz frame loop
  const thrustIntensityRef = useRef(0);
  const boostingRef = useRef(false);

  // DCK: Flight input enabled ref — set to false during dock lock sequence
  const flightInputEnabledRef = useRef(true);
  const setFlightInputEnabled = useCallback((enabled: boolean) => {
    flightInputEnabledRef.current = enabled;
  }, []);

  // Flight input — keyboard + mouse → FlightIntent ref
  const { intentRef, requestPointerLock } = useFlightInput({ enabled: inputEnabled });

  // DCK: dockingState store action — stable reference via getState()
  const handleDockingStateChange = useCallback((state: DockingState) => {
    useObservatoryStore.getState().actions.setDockingState(state);
  }, []);

  // State change bridge: updates both onStateChange callback AND playerFocusRef
  // Does NOT overwrite playerFocusRef.position when docked (docking system owns position)
  const handleStateChange = useCallback(
    (state: FlightState) => {
      // Only update playerFocusRef when not docked (docking system manages position during lock)
      if (flightInputEnabledRef.current) {
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
      }

      // FLT-06: Update thruster VFX refs — thrustIntensity = speed / cruiseSpeed (0-1+)
      thrustIntensityRef.current = Math.min(1, state.currentSpeed / DEFAULT_FLIGHT_CONFIG.cruiseSpeed);
      boostingRef.current = state.speedTier === "boost";

      onStateChange?.(state);
    },
    [playerFocusRef, onStateChange],
  );

  // Flight physics loop — mutates shipRef each frame; returns velRef for docking system
  const { velRef } = useFlightLoop({
    intentRef,
    shipRef,
    onStateChange: handleStateChange,
    flightInputEnabled: flightInputEnabledRef,
  });

  // DCK: Three-zone docking system — approach / magnet-pull / dock lock / undock
  useDockingSystem({
    shipRef,
    intentRef,
    velocityRef: velRef,
    setFlightInputEnabled,
    onDockingStateChange: handleDockingStateChange,
  });

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
    <>
      <group ref={shipRef}>
        <ShipMesh accentColor={accentColor} />
      </group>
      {/* FLT-05: Chase camera — follows ship with lerp-lagged tracking */}
      <ChaseCamera shipRef={shipRef} />
      {/* FLT-06: Thruster exhaust particles — 4 nozzles, scales with thrust intensity */}
      <ShipThrusterVFX
        shipRef={shipRef}
        thrustIntensity={thrustIntensityRef.current}
        boosting={boostingRef.current}
        accentColor={accentColor}
      />
    </>
  );
}
