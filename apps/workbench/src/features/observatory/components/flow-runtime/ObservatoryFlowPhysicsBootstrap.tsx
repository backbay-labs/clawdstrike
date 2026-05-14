import { lazy, Suspense } from "react";
import { Physics } from "@react-three/rapier";
import type { ObservatoryFlowRuntimeSceneProps } from "./observatory-player-types";

const LazyObservatoryFlowColliders = lazy(() =>
  import("./ObservatoryFlowColliders").then((module) => ({
    default: module.ObservatoryFlowColliders,
  })),
);

const LazyObservatoryPlayerRuntime = lazy(() =>
  import("./ObservatoryPlayerRuntime").then((module) => ({
    default: module.ObservatoryPlayerRuntime,
  })),
);

export function ObservatoryFlowPhysicsBootstrap({
  enableCharacterVfx = false,
  heroProps,
  inputEnabled = false,
  onInteractProp,
  onWorldStateChange,
  playerFocusRef,
  preferredStationId,
  world,
}: ObservatoryFlowRuntimeSceneProps) {
  return (
    <Physics colliders={false} gravity={[0, 0, 0]} timeStep="vary">
      <Suspense fallback={null}>
        <LazyObservatoryFlowColliders world={world} />
      </Suspense>
      <Suspense fallback={null}>
        <LazyObservatoryPlayerRuntime
          enableCharacterVfx={enableCharacterVfx}
          heroProps={heroProps}
          inputEnabled={inputEnabled}
          onInteractProp={onInteractProp}
          onWorldStateChange={onWorldStateChange}
          playerFocusRef={playerFocusRef}
          preferredStationId={preferredStationId}
          world={world}
        />
      </Suspense>
    </Physics>
  );
}
