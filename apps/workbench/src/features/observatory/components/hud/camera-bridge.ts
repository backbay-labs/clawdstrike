/**
 * camera-bridge.ts — Phase 24 HUD-06
 *
 * Bridges camera state from the R3F Canvas fiber context to DOM-side HUD code.
 *
 * Problem: R3F hooks (useThree, useFrame) only work inside the Canvas context.
 * DOM overlay components (SpeedIndicator, HeadingCompass, target bracket overlays)
 * run outside the Canvas and cannot call useThree(). This bridge solves that by
 * writing camera matrices into a module-level ref object each frame via useFrame.
 *
 * Usage:
 *   1. Mount <HudCameraBridge /> inside the R3F Canvas (e.g. as a child of ObservatoryWorldCanvas).
 *   2. DOM-side HUD components read from hudCameraRef.current — always fresh, zero subscriptions.
 *
 * Performance contract:
 *   - No `new` allocations inside the useFrame callback — only .copy() calls.
 *   - Runs at priority -100 (before render) so HUD reads see the current frame's matrices.
 */

import { useFrame } from "@react-three/fiber";
import * as THREE from "three";
import type { PerspectiveCamera } from "three";

// ---------------------------------------------------------------------------
// Module-level camera ref — accessible anywhere, no React subscriptions
// ---------------------------------------------------------------------------

/**
 * Module-level ref that holds a snapshot of the camera's world matrices.
 * Written every frame by HudCameraBridge inside the Canvas context.
 * Read by DOM-side HUD components in their requestAnimationFrame loops.
 *
 * The matrices are pre-allocated once and mutated in-place via .copy() — no GC pressure.
 */
export const hudCameraRef: {
  current: {
    projectionMatrix: THREE.Matrix4;
    matrixWorldInverse: THREE.Matrix4;
    fov: number;
    aspect: number;
    position: THREE.Vector3;
  };
} = {
  current: {
    projectionMatrix: new THREE.Matrix4(),
    matrixWorldInverse: new THREE.Matrix4(),
    fov: 60,
    aspect: 1,
    position: new THREE.Vector3(),
  },
};

// ---------------------------------------------------------------------------
// R3F component — mounts inside Canvas, copies camera state each frame
// ---------------------------------------------------------------------------

/**
 * HudCameraBridge — renders null but runs a high-priority useFrame hook that
 * copies camera matrices into hudCameraRef each frame.
 *
 * Mount this as a child of any R3F Canvas that also renders the SpaceFlightHud overlay.
 * Placement inside ObservatoryWorldCanvas is ideal since it already owns the camera.
 */
export function HudCameraBridge(): null {
  useFrame(({ camera }) => {
    // .copy() mutates in-place — no allocations. Priority -100 runs before render.
    hudCameraRef.current.projectionMatrix.copy(camera.projectionMatrix);
    hudCameraRef.current.matrixWorldInverse.copy(camera.matrixWorldInverse);
    hudCameraRef.current.position.copy(camera.position);

    const perspCamera = camera as PerspectiveCamera;
    hudCameraRef.current.fov = perspCamera.fov ?? 60;
    hudCameraRef.current.aspect = perspCamera.aspect ?? 1;
  }, -100);

  return null;
}
