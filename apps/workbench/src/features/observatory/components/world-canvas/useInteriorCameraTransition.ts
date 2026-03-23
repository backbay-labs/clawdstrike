// useInteriorCameraTransition — Phase 43 INTR-01/INTR-04/INTR-05/INTR-06
//
// Manages smooth camera transition between exterior observatory and station interior views.
// Runs inside the R3F Canvas (uses useFrame and useThree).
//
// INTR-04: 1.2s camera push with quadratic ease-out
// INTR-05: FOV narrows from 60 to 50 during entry
// INTR-06: Near plane adjusts to 0.02 on interior entry to prevent z-fighting

import { useFrame, useThree } from "@react-three/fiber";
import { useEffect, useRef } from "react";
import * as THREE from "three";
import type { ObservatoryInteriorState } from "../../types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface InteriorCameraTransitionOptions {
  interiorState: ObservatoryInteriorState;
  targetPosition: [number, number, number] | null; // station world position
  controlsRef: React.RefObject<THREE.EventDispatcher | null>;
  onTransitionComplete: (phase: "inside" | null) => void;
}

// Captured exterior state restored on exit
interface ExteriorCameraSnapshot {
  position: THREE.Vector3;
  target: THREE.Vector3;
  fov: number;
  near: number;
}

// OrbitControls shape we need for constraint manipulation
interface OrbitControlsLike {
  target: THREE.Vector3;
  enableRotate: boolean;
  enablePan: boolean;
  minDistance: number;
  maxDistance: number;
  minPolarAngle: number;
  maxPolarAngle: number;
}

// ---------------------------------------------------------------------------
// Constants (INTR-04, INTR-05, INTR-06)
// ---------------------------------------------------------------------------

const TRANSITION_DURATION = 1.2; // seconds per CONTEXT.md
const INTERIOR_FOV = 50;
const EXTERIOR_FOV = 60;
const INTERIOR_NEAR = 0.02; // INTR-06: z-fighting prevention per CONTEXT.md
const EXTERIOR_NEAR = 0.1;
// Interior camera offset from room center — slightly back + up for orbit perspective
const INTERIOR_CAMERA_OFFSET = new THREE.Vector3(0, 4, 8);
// Constrained orbit limits inside room
const INTERIOR_MIN_DISTANCE = 3;
const INTERIOR_MAX_DISTANCE = 12;
const INTERIOR_MIN_POLAR = Math.PI * 0.15; // can't look straight up
const INTERIOR_MAX_POLAR = Math.PI * 0.75; // can't look straight down
// Exterior orbit constraint restoration defaults
const EXTERIOR_MIN_DISTANCE = 0;
const EXTERIOR_MAX_DISTANCE = Infinity;
const EXTERIOR_MIN_POLAR = 0;
const EXTERIOR_MAX_POLAR = Math.PI;

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useInteriorCameraTransition({
  interiorState,
  targetPosition,
  controlsRef,
  onTransitionComplete,
}: InteriorCameraTransitionOptions) {
  const { camera } = useThree();

  // Track transition progress [0, 1]
  const progressRef = useRef(0);
  // Detect phase changes to react on entering/exiting
  const previousPhaseRef = useRef<string | null>(null);

  // Captured exterior camera state for restoration on exit
  const exteriorCameraRef = useRef<ExteriorCameraSnapshot | null>(null);

  // Computed interior target/camera positions for current transition
  const interiorTargetRef = useRef<THREE.Vector3>(new THREE.Vector3());
  const interiorCameraPositionRef = useRef<THREE.Vector3>(new THREE.Vector3());

  // React to transitionPhase changes
  useEffect(() => {
    const { transitionPhase } = interiorState;
    const prev = previousPhaseRef.current;
    previousPhaseRef.current = transitionPhase;

    if (transitionPhase === "entering" && prev !== "entering") {
      // Capture current exterior state for restoration later
      const controls = controlsRef.current as unknown as OrbitControlsLike | null;
      exteriorCameraRef.current = {
        position: camera.position.clone(),
        target: controls?.target?.clone() ?? new THREE.Vector3(),
        fov: (camera as THREE.PerspectiveCamera).fov ?? EXTERIOR_FOV,
        near: camera.near,
      };
      progressRef.current = 0;

      if (targetPosition) {
        // Room center is at station y + 4 (half of 8-unit room height)
        const roomCenter = new THREE.Vector3(
          targetPosition[0],
          targetPosition[1] + 4,
          targetPosition[2],
        );
        interiorTargetRef.current.copy(roomCenter);
        interiorCameraPositionRef.current
          .copy(roomCenter)
          .add(INTERIOR_CAMERA_OFFSET);
      }
    }

    if (transitionPhase === "exiting" && prev !== "exiting") {
      // Begin exit: progress was 1.0 (fully inside) and we lerp back
      progressRef.current = 0;
    }

    // Restore exterior orbit constraints when interior fully deactivated
    if (!interiorState.active) {
      const controls = controlsRef.current as unknown as OrbitControlsLike | null;
      if (controls) {
        controls.enableRotate = false;
        controls.enablePan = false;
        controls.minDistance = EXTERIOR_MIN_DISTANCE;
        controls.maxDistance = EXTERIOR_MAX_DISTANCE;
        controls.minPolarAngle = EXTERIOR_MIN_POLAR;
        controls.maxPolarAngle = EXTERIOR_MAX_POLAR;
      }
    }
  }, [camera, controlsRef, interiorState, targetPosition]);

  useFrame((_, delta) => {
    const { transitionPhase } = interiorState;
    const perspCamera = camera as THREE.PerspectiveCamera;
    const controls = controlsRef.current as unknown as OrbitControlsLike | null;

    if (transitionPhase === "entering") {
      progressRef.current = Math.min(
        progressRef.current + delta / TRANSITION_DURATION,
        1.0,
      );
      // Quadratic ease-out per CONTEXT.md decision
      const t = 1 - (1 - progressRef.current) * (1 - progressRef.current);

      const ext = exteriorCameraRef.current;
      if (ext) {
        // Lerp camera position
        camera.position.lerpVectors(ext.position, interiorCameraPositionRef.current, t);

        // Lerp controls target
        if (controls?.target) {
          controls.target.lerpVectors(ext.target, interiorTargetRef.current, t);
        }

        // Lerp FOV
        perspCamera.fov = THREE.MathUtils.lerp(ext.fov, INTERIOR_FOV, t);

        // Lerp near plane (INTR-06: reduces to 0.02 inside)
        camera.near = THREE.MathUtils.lerp(ext.near, INTERIOR_NEAR, t);
        perspCamera.updateProjectionMatrix();
      }

      if (progressRef.current >= 1.0) {
        // Transition complete — apply interior orbit constraints
        if (controls) {
          controls.enableRotate = true;
          controls.enablePan = false;
          controls.minDistance = INTERIOR_MIN_DISTANCE;
          controls.maxDistance = INTERIOR_MAX_DISTANCE;
          controls.minPolarAngle = INTERIOR_MIN_POLAR;
          controls.maxPolarAngle = INTERIOR_MAX_POLAR;
        }
        onTransitionComplete("inside");
      }
    } else if (transitionPhase === "exiting") {
      progressRef.current = Math.min(
        progressRef.current + delta / TRANSITION_DURATION,
        1.0,
      );
      // Quadratic ease-out
      const t = 1 - (1 - progressRef.current) * (1 - progressRef.current);

      const ext = exteriorCameraRef.current;
      if (ext) {
        // Lerp camera position back to exterior
        camera.position.lerpVectors(interiorCameraPositionRef.current, ext.position, t);

        // Lerp controls target back to exterior
        if (controls?.target) {
          controls.target.lerpVectors(interiorTargetRef.current, ext.target, t);
        }

        // Lerp FOV back
        perspCamera.fov = THREE.MathUtils.lerp(INTERIOR_FOV, ext.fov, t);

        // Lerp near plane back to exterior
        camera.near = THREE.MathUtils.lerp(INTERIOR_NEAR, ext.near, t);
        perspCamera.updateProjectionMatrix();
      }

      if (progressRef.current >= 1.0) {
        // Exit complete — restore exterior orbit constraints
        if (controls) {
          controls.enableRotate = false;
          controls.enablePan = false;
          controls.minDistance = EXTERIOR_MIN_DISTANCE;
          controls.maxDistance = EXTERIOR_MAX_DISTANCE;
          controls.minPolarAngle = EXTERIOR_MIN_POLAR;
          controls.maxPolarAngle = EXTERIOR_MAX_POLAR;
        }
        exteriorCameraRef.current = null;
        onTransitionComplete(null);
      }
    }
    // "inside": no lerp needed — user controls camera via OrbitControls
  });
}
