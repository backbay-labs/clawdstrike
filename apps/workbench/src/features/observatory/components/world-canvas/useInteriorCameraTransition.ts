import { useFrame, useThree } from "@react-three/fiber";
import { useEffect, useRef } from "react";
import * as THREE from "three";
import type { ObservatoryInteriorState } from "../../types";

interface InteriorCameraTransitionOptions {
  interiorState: ObservatoryInteriorState;
  targetPosition: [number, number, number] | null;
  controlsRef: React.RefObject<THREE.EventDispatcher | null>;
  onTransitionComplete: (phase: "inside" | null) => void;
}

interface ExteriorCameraSnapshot {
  position: THREE.Vector3;
  target: THREE.Vector3;
  fov: number;
  near: number;
}

interface OrbitControlsLike {
  target: THREE.Vector3;
  enableRotate: boolean;
  enablePan: boolean;
  minDistance: number;
  maxDistance: number;
  minPolarAngle: number;
  maxPolarAngle: number;
}

const TRANSITION_DURATION = 1.2;
const INTERIOR_FOV = 50;
const EXTERIOR_FOV = 60;
const INTERIOR_NEAR = 0.02;
const EXTERIOR_NEAR = 0.1;
const INTERIOR_CAMERA_OFFSET = new THREE.Vector3(0, 4, 8);

export function useInteriorCameraTransition({
  interiorState,
  targetPosition,
  controlsRef,
  onTransitionComplete,
}: InteriorCameraTransitionOptions) {
  const { camera } = useThree();

  const progressRef = useRef(0);
  const previousPhaseRef = useRef<string | null>(null);
  const exteriorCameraRef = useRef<ExteriorCameraSnapshot | null>(null);
  const interiorTargetRef = useRef<THREE.Vector3>(new THREE.Vector3());
  const interiorCameraPositionRef = useRef<THREE.Vector3>(new THREE.Vector3());

  useEffect(() => {
    const { transitionPhase } = interiorState;
    const prev = previousPhaseRef.current;
    previousPhaseRef.current = transitionPhase;

    if (transitionPhase === "entering" && prev !== "entering") {
      const controls = controlsRef.current as unknown as OrbitControlsLike | null;
      exteriorCameraRef.current = {
        position: camera.position.clone(),
        target: controls?.target?.clone() ?? new THREE.Vector3(),
        fov: (camera as THREE.PerspectiveCamera).fov ?? EXTERIOR_FOV,
        near: camera.near,
      };
      progressRef.current = 0;

      if (targetPosition) {
        const roomCenter = new THREE.Vector3(
          targetPosition[0],
          targetPosition[1] + 4,
          targetPosition[2],
        );
        interiorTargetRef.current.copy(roomCenter);
        interiorCameraPositionRef.current.copy(roomCenter).add(INTERIOR_CAMERA_OFFSET);
      }
    }

    if (transitionPhase === "exiting" && prev !== "exiting") {
      progressRef.current = 0;
    }

    if (!interiorState.active) {
      const controls = controlsRef.current as unknown as OrbitControlsLike | null;
      if (controls) {
        controls.enableRotate = false;
        controls.enablePan = false;
        controls.minDistance = 0;
        controls.maxDistance = Infinity;
        controls.minPolarAngle = 0;
        controls.maxPolarAngle = Math.PI;
      }
    }
  }, [camera, controlsRef, interiorState, targetPosition]);

  useFrame((_, delta) => {
    const { transitionPhase } = interiorState;
    const perspCamera = camera as THREE.PerspectiveCamera;
    const controls = controlsRef.current as unknown as OrbitControlsLike | null;

    if (transitionPhase === "entering") {
      progressRef.current = Math.min(progressRef.current + delta / TRANSITION_DURATION, 1.0);
      const t = 1 - (1 - progressRef.current) ** 2;

      const ext = exteriorCameraRef.current;
      if (ext) {
        camera.position.lerpVectors(ext.position, interiorCameraPositionRef.current, t);
        if (controls?.target) {
          controls.target.lerpVectors(ext.target, interiorTargetRef.current, t);
        }
        perspCamera.fov = THREE.MathUtils.lerp(ext.fov, INTERIOR_FOV, t);
        camera.near = THREE.MathUtils.lerp(ext.near, INTERIOR_NEAR, t);
        perspCamera.updateProjectionMatrix();
      }

      if (progressRef.current >= 1.0) {
        if (controls) {
          controls.enableRotate = true;
          controls.enablePan = false;
          controls.minDistance = 3;
          controls.maxDistance = 12;
          controls.minPolarAngle = Math.PI * 0.15;
          controls.maxPolarAngle = Math.PI * 0.75;
        }
        onTransitionComplete("inside");
      }
    } else if (transitionPhase === "exiting") {
      progressRef.current = Math.min(progressRef.current + delta / TRANSITION_DURATION, 1.0);
      const t = 1 - (1 - progressRef.current) ** 2;

      const ext = exteriorCameraRef.current;
      if (ext) {
        camera.position.lerpVectors(interiorCameraPositionRef.current, ext.position, t);
        if (controls?.target) {
          controls.target.lerpVectors(interiorTargetRef.current, ext.target, t);
        }
        perspCamera.fov = THREE.MathUtils.lerp(INTERIOR_FOV, ext.fov, t);
        camera.near = THREE.MathUtils.lerp(INTERIOR_NEAR, ext.near, t);
        perspCamera.updateProjectionMatrix();
      }

      if (progressRef.current >= 1.0) {
        if (controls) {
          controls.enableRotate = false;
          controls.enablePan = false;
          controls.minDistance = 0;
          controls.maxDistance = Infinity;
          controls.minPolarAngle = 0;
          controls.maxPolarAngle = Math.PI;
        }
        exteriorCameraRef.current = null;
        onTransitionComplete(null);
      }
    }
  });
}
