import { useEffect, useMemo } from "react";
import { useThree } from "@react-three/fiber";
import type { ObservatoryRuntimeActivitySources } from "../../utils/observatory-performance";

export interface ObservatoryInvalidationControllerProps {
  sources: ObservatoryRuntimeActivitySources & {
    replayFrameIndex: number;
    routeSignature: string;
  };
}

export function ObservatoryInvalidationController({ sources }: ObservatoryInvalidationControllerProps) {
  const invalidate = useThree((state) => state.invalidate);
  const sourceKey = useMemo(
    () =>
      [
        sources.activeHeroInteraction ? "hero" : "idle",
        sources.eruptionCount,
        sources.flyByActive ? "fly" : "steady",
        sources.missionTargetStationId ?? "none",
        sources.playerInputEnabled ? "input" : "noinput",
        sources.probeStatus,
        sources.replayFrameIndex,
        sources.replayScrubbing ? "scrub" : "nonscrub",
        sources.routeSignature,
        sources.selectedStationId ?? "none",
        sources.annotationDropCount ?? 0,
        sources.heatmapPulseVersion ?? 0,
        sources.spiritTrailSegmentCount ?? 0,
        sources.constellationCount ?? 0,
        sources.interiorTransitionPhase ?? "none",
      ].join("|"),
    [
      sources.activeHeroInteraction,
      sources.eruptionCount,
      sources.flyByActive,
      sources.missionTargetStationId,
      sources.playerInputEnabled,
      sources.probeStatus,
      sources.replayFrameIndex,
      sources.replayScrubbing,
      sources.routeSignature,
      sources.selectedStationId,
      sources.annotationDropCount,
      sources.heatmapPulseVersion,
      sources.spiritTrailSegmentCount,
      sources.constellationCount,
      sources.interiorTransitionPhase,
    ],
  );

  useEffect(() => {
    invalidate();
  }, [invalidate, sourceKey]);

  return null;
}
