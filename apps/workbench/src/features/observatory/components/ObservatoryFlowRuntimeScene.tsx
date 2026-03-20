/**
 * ObservatoryFlowRuntimeScene.tsx — Phase 21 FLT-02
 *
 * Bridge module: replaces the Rapier-based ObservatoryFlowPhysicsBootstrap
 * with the SpaceFlightController for the v6.0 space flight experience.
 *
 * The call site in ObservatoryWorldCanvas.tsx passes the full
 * ObservatoryFlowRuntimeSceneProps interface — this component accepts those
 * props and forwards only what SpaceFlightController needs, discarding the
 * Rapier-specific fields (world, heroProps, etc.) without error.
 *
 * Re-exports the types that ObservatoryWorldCanvas imports from this module
 * so the import site in ObservatoryWorldCanvas.tsx does not need to change.
 */

import { lazy, Suspense } from "react";
import type { ObservatoryFlowRuntimeSceneProps } from "./flow-runtime/observatory-player-types";

export type {
  MissionInteractionSource,
  ObservatoryFlowRuntimeSceneProps,
  ObservatoryPlayerFocusState,
  ObservatoryPlayerWorldState,
} from "./flow-runtime/observatory-player-types";

const LazySpaceFlightController = lazy(() =>
  import("../character/ship/SpaceFlightController").then((module) => ({
    default: module.SpaceFlightController,
  })),
);

export function ObservatoryFlowRuntimeScene({
  inputEnabled = false,
  playerFocusRef,
}: ObservatoryFlowRuntimeSceneProps) {
  return (
    <Suspense fallback={null}>
      <LazySpaceFlightController
        inputEnabled={inputEnabled}
        playerFocusRef={playerFocusRef}
      />
    </Suspense>
  );
}
