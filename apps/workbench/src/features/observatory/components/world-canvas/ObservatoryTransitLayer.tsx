import { Line } from "@react-three/drei";
import type { ObservatoryTransitLayerProps } from "./observatory-world-scene-types";
import { HypothesisScaffold, TransitRoute } from "../../components/ObservatoryWorldCanvas";
import { ObservatorySpaceLanes } from "./ObservatorySpaceLanes";

export function ObservatoryTransitLayer({
  eruptionStrengthByRouteStation,
  missionTargetStationId,
  world,
}: ObservatoryTransitLayerProps) {
  return (
    <>
      {world.coreLinks.map((entry) => (
        <Line
          key={entry.key}
          points={entry.points}
          color={entry.colorHex}
          transparent
          opacity={entry.opacity}
          lineWidth={1}
        />
      ))}
      {world.hypothesisScaffolds.map((scaffold) => (
        <HypothesisScaffold key={scaffold.key} scaffold={scaffold} />
      ))}
      {world.transitLinks.map((route) => (
        <TransitRoute
          key={route.key}
          modeOpacityScale={world.modeProfile.routeOpacityScale}
          missionTarget={missionTargetStationId === route.stationId}
          route={route}
          eruptionStrength={eruptionStrengthByRouteStation[route.stationId] ?? 0}
        />
      ))}
      <ObservatorySpaceLanes />
    </>
  );
}
