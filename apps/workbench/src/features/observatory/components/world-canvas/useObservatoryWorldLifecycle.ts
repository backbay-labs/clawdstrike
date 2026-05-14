import { useMemo } from "react";
import type { HuntStationId } from "../../world/types";
import type { ObservatoryProbeState } from "../../world/probeRuntime";
import {
  shouldKeepObservatoryRealtimeActive,
  type ObservatoryRuntimeActivitySources,
} from "../../utils/observatory-performance";

export interface UseObservatoryWorldLifecycleInput {
  activeHeroInteraction: boolean;
  cameraResetToken: number;
  flyByActive: boolean;
  missionTargetStationId: HuntStationId | null;
  playerInputEnabled: boolean;
  probeStatus: ObservatoryProbeState["status"];
  replayFrameIndex?: number | null;
  replayScrubbing?: boolean;
  selectedStationId: HuntStationId | null;
  shouldInvalidateOnRouteChange: boolean;
  eruptionCount: number;
  routeSignature: string;
}

export function useObservatoryWorldLifecycle(input: UseObservatoryWorldLifecycleInput): {
  effectiveFrameloop: "always" | "demand";
  realtimeActivitySources: ObservatoryRuntimeActivitySources & {
    replayFrameIndex: number;
    routeSignature: string;
  };
} {
  const realtimeActivitySources = useMemo(
    () => ({
      activeHeroInteraction: input.activeHeroInteraction,
      eruptionCount: input.eruptionCount,
      flyByActive: input.flyByActive,
      missionTargetStationId: input.missionTargetStationId,
      playerInputEnabled: input.playerInputEnabled,
      probeStatus: input.probeStatus,
      replayScrubbing: input.replayScrubbing ?? false,
      replayFrameIndex: input.replayFrameIndex ?? -1,
      routeSignature: input.routeSignature,
      selectedStationId: input.selectedStationId,
      shouldInvalidateOnRouteChange: input.shouldInvalidateOnRouteChange,
    }),
    [
      input.activeHeroInteraction,
      input.cameraResetToken,
      input.eruptionCount,
      input.flyByActive,
      input.missionTargetStationId,
      input.playerInputEnabled,
      input.probeStatus,
      input.replayFrameIndex,
      input.replayScrubbing,
      input.routeSignature,
      input.selectedStationId,
      input.shouldInvalidateOnRouteChange,
    ],
  );
  const effectiveFrameloop = shouldKeepObservatoryRealtimeActive(realtimeActivitySources)
    ? "always"
    : "demand";

  return {
    effectiveFrameloop,
    realtimeActivitySources,
  };
}
